#!/usr/bin/env node
// scripts/verify-dkim-statement.mjs: Offline RFC 6376 DKIM (rsa-sha256) broker statement attachment verifier.
import { createHash, createPublicKey, createSign, createVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';

const REQUIRED_HEADERS_LIST = [
  'from',
  'subject',
  'date',
  'mime-version',
  'content-type',
];
export const REQUIRED_SIGNED_HEADERS = REQUIRED_HEADERS_LIST;

export class DkimError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

export function canonicalizeHeaderSimple(rawHeader) {
  return rawHeader.replace(/\r?\n$/, '');
}

export function canonicalizeHeaderRelaxed(rawHeader) {
  const noTrailing = rawHeader.replace(/\r?\n$/, '');
  const colonIdx = noTrailing.indexOf(':');
  if (colonIdx < 0) throw new DkimError('DKIM_MALFORMED_HEADER', 'Header missing colon separator');
  const name = noTrailing.slice(0, colonIdx).toLowerCase().trim();
  const unfoldedVal = noTrailing
    .slice(colonIdx + 1)
    .replace(/\r?\n[ \t]+/g, ' ')
    .replace(/[ \t]+/g, ' ')
    .trim();
  return `${name}:${unfoldedVal}`;
}

export function canonicalizeBodySimple(rawBody) {
  const crlf = String(rawBody ?? '').replace(/\r?\n/g, '\r\n');
  const stripped = crlf.replace(/(\r\n)+$/, '');
  return `${stripped}\r\n`;
}

export function canonicalizeBodyRelaxed(rawBody) {
  const crlf = String(rawBody ?? '').replace(/\r?\n/g, '\r\n');
  if (crlf.length === 0) return '';
  const lines = crlf.split('\r\n');
  if (lines[lines.length - 1] === '') lines.pop();
  const normLines = lines.map((line) => line.replace(/[ \t]+$/g, '').replace(/[ \t]+/g, ' '));
  while (normLines.length > 0 && normLines[normLines.length - 1] === '') {
    normLines.pop();
  }
  if (normLines.length === 0) return '';
  return `${normLines.join('\r\n')}\r\n`;
}

export function parseEmlStructure(rawEml) {
  const text = Buffer.isBuffer(rawEml) || rawEml instanceof Uint8Array
    ? Buffer.from(rawEml).toString('utf8')
    : String(rawEml ?? '');
  const normalized = text.replace(/\r?\n/g, '\r\n');
  const splitIdx = normalized.indexOf('\r\n\r\n');
  if (splitIdx < 0) {
    throw new DkimError('DKIM_MALFORMED_EML', 'EML missing header/body CRLFCRLF separator');
  }
  const headerBlock = normalized.slice(0, splitIdx);
  const bodyBlock = normalized.slice(splitIdx + 4);

  const rawHeaders = [];
  for (const line of headerBlock.split('\r\n')) {
    if (/^[ \t]/.test(line) && rawHeaders.length > 0) {
      rawHeaders[rawHeaders.length - 1].raw += `\r\n${line}`;
    } else {
      const idx = line.indexOf(':');
      if (idx < 0) {
        throw new DkimError('DKIM_MALFORMED_HEADER', `Malformed header line: ${line}`);
      }
      rawHeaders.push({
        name: line.slice(0, idx).trim(),
        lowerName: line.slice(0, idx).trim().toLowerCase(),
        raw: line,
      });
    }
  }
  return { rawHeaders, bodyBlock };
}

export function parseDkimTags(rawDkimHeader) {
  const colonIdx = rawDkimHeader.indexOf(':');
  const val = colonIdx >= 0 ? rawDkimHeader.slice(colonIdx + 1) : rawDkimHeader;
  const unfolded = val.replace(/\r?\n[ \t]+/g, ' ').trim();
  const tags = {};
  for (const part of unfolded.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx < 0) {
      throw new DkimError('DKIM_MALFORMED_TAG', `Malformed DKIM tag: ${trimmed}`);
    }
    const k = trimmed.slice(0, eqIdx).trim();
    const v = trimmed.slice(eqIdx + 1).trim();
    if (Object.hasOwn(tags, k)) {
      throw new DkimError('DKIM_DUPLICATE_TAG', `Duplicate DKIM tag "${k}="`);
    }
    tags[k] = v;
  }
  return tags;
}

export function stripDkimSignatureValue(rawDkimHeader) {
  return rawDkimHeader.replace(/(\bb\s*=\s*)([^;]*)/, '$1');
}

export function extractMimeAttachments(rawHeaders, bodyBlock) {
  const ctHeader = rawHeaders.find((h) => h.lowerName === 'content-type');
  if (!ctHeader) return [];
  const ctVal = ctHeader.raw.slice(ctHeader.raw.indexOf(':') + 1).replace(/\r?\n[ \t]+/g, ' ');
  const boundaryMatch = /boundary\s*=\s*(?:"([^"]+)"|([^\s;]+))/i.exec(ctVal);
  const attachments = [];

  if (!boundaryMatch) {
    const cteHeader = rawHeaders.find((h) => h.lowerName === 'content-transfer-encoding');
    const cteVal = cteHeader ? cteHeader.raw.slice(cteHeader.raw.indexOf(':') + 1).trim().toLowerCase() : '';
    if (cteVal === 'base64') {
      const cleanB64 = bodyBlock.replace(/\s+/g, '');
      const content = Buffer.from(cleanB64, 'base64');
      attachments.push({
        filename: 'statement',
        contentType: ctVal.split(';')[0].trim(),
        bytes: content,
        sha256: createHash('sha256').update(content).digest('hex'),
      });
    }
    return attachments;
  }

  const boundary = boundaryMatch[1] || boundaryMatch[2];
  const delimiter = `--${boundary}`;
  const parts = bodyBlock.split(delimiter);
  for (let i = 1; i < parts.length; i++) {
    let part = parts[i];
    if (part.startsWith('--')) break;
    part = part.replace(/^\r\n/, '').replace(/\r\n$/, '');
    const sep = part.indexOf('\r\n\r\n');
    if (sep < 0) continue;
    const partHeadersRaw = part.slice(0, sep).replace(/\r\n[ \t]+/g, ' ');
    const partBody = part.slice(sep + 4);
    const isBase64 = /Content-Transfer-Encoding\s*:\s*base64/i.test(partHeadersRaw);
    const dispMatch = /Content-Disposition\s*:\s*attachment/i.test(partHeadersRaw);
    const nameMatch = /filename\s*=\s*(?:"([^"]+)"|([^\s;]+))/i.exec(partHeadersRaw) ||
                      /name\s*=\s*(?:"([^"]+)"|([^\s;]+))/i.exec(partHeadersRaw);
    const partCtMatch = /Content-Type\s*:\s*([^;\r\n]+)/i.exec(partHeadersRaw);
    if (isBase64 || dispMatch) {
      const cleanB64 = partBody.replace(/\s+/g, '');
      const decoded = Buffer.from(cleanB64, 'base64');
      attachments.push({
        filename: nameMatch ? (nameMatch[1] || nameMatch[2]) : 'attachment',
        contentType: partCtMatch ? partCtMatch[1].trim() : 'application/octet-stream',
        bytes: decoded,
        sha256: createHash('sha256').update(decoded).digest('hex'),
      });
    }
  }
  return attachments;
}

/**
 * Verifies an RFC 6376 DKIM-signed (.eml) broker statement message offline.
 */
export function verifyDkimStatementEml(rawEml, options = {}) {
  const { rawHeaders, bodyBlock } = parseEmlStructure(rawEml);
  const dkimHeaders = rawHeaders.filter((h) => h.lowerName === 'dkim-signature');
  if (dkimHeaders.length === 0) {
    throw new DkimError('DKIM_SIGNATURE_MISSING', 'No DKIM-Signature header found in .eml');
  }

  const dkimHeader = dkimHeaders[0];
  const tags = parseDkimTags(dkimHeader.raw);

  if (Object.hasOwn(tags, 'l')) {
    throw new DkimError(
      'DKIM_BODY_LENGTH_TAG_FORBIDDEN',
      'DKIM-Signature contains forbidden l= body-length tag (RFC 6376 body truncation hazard)'
    );
  }

  if (tags.v !== '1') {
    throw new DkimError('DKIM_VERSION_UNSUPPORTED', `Unsupported DKIM version v=${tags.v}`);
  }
  if (tags.a !== 'rsa-sha256') {
    throw new DkimError('DKIM_ALGORITHM_UNSUPPORTED', `Unsupported DKIM algorithm a=${tags.a}`);
  }

  const domain = (tags.d || '').toLowerCase();
  const selector = tags.s || '';
  if (!domain || !selector) {
    throw new DkimError('DKIM_MISSING_DOMAIN_OR_SELECTOR', 'DKIM-Signature missing d= or s=');
  }

  if (options.expectedDomain && domain !== options.expectedDomain.toLowerCase()) {
    throw new DkimError(
      'DKIM_DOMAIN_MISMATCH',
      `DKIM signing domain "${domain}" does not match expected broker domain "${options.expectedDomain}"`
    );
  }

  const signedHeaderList = (tags.h || '')
    .split(':')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);

  for (const req of REQUIRED_SIGNED_HEADERS) {
    if (!signedHeaderList.includes(req)) {
      throw new DkimError(
        'DKIM_REQUIRED_HEADERS_UNSIGNED',
        `Required header "${req}" is not covered by DKIM h= tag`
      );
    }
  }

  // Enforce From: header domain alignment with d=
  const fromHeaders = rawHeaders.filter((h) => h.lowerName === 'from');
  if (fromHeaders.length === 0) {
    throw new DkimError('DKIM_MISSING_FROM', 'Message lacks From: header');
  }

  // Reject messages with duplicate unsigned header instances for any signed or required header
  const headerCountsInMessage = new Map();
  for (const h of rawHeaders) {
    if (h.lowerName === 'dkim-signature') continue;
    headerCountsInMessage.set(h.lowerName, (headerCountsInMessage.get(h.lowerName) || 0) + 1);
  }
  const headerCountsInH = new Map();
  for (const hName of signedHeaderList) {
    headerCountsInH.set(hName, (headerCountsInH.get(hName) || 0) + 1);
  }
  for (const [hName, msgCount] of headerCountsInMessage.entries()) {
    if (REQUIRED_SIGNED_HEADERS.includes(hName) || headerCountsInH.has(hName)) {
      const signedCount = headerCountsInH.get(hName) || 0;
      if (msgCount > signedCount) {
        throw new DkimError(
          'DKIM_UNSIGNED_DUPLICATE_HEADER',
          `Header "${hName}" appears ${msgCount} times in message but only ${signedCount} times in DKIM h=`
        );
      }
    }
  }

  const canonSpec = (tags.c || 'simple/simple').toLowerCase().split('/');
  const headerCanonAlg = canonSpec[0] || 'simple';
  const bodyCanonAlg = canonSpec[1] || 'simple';
  if (!['simple', 'relaxed'].includes(headerCanonAlg) || !['simple', 'relaxed'].includes(bodyCanonAlg)) {
    throw new DkimError('DKIM_CANON_UNSUPPORTED', `Unsupported canonicalization c=${tags.c}`);
  }

  const canonHeaderFn = headerCanonAlg === 'relaxed' ? canonicalizeHeaderRelaxed : canonicalizeHeaderSimple;
  const canonBodyFn = bodyCanonAlg === 'relaxed' ? canonicalizeBodyRelaxed : canonicalizeBodySimple;

  const canonBody = canonBodyFn(bodyBlock);
  const computedBh = createHash('sha256').update(canonBody, 'utf8').digest('base64');
  const expectedBh = (tags.bh || '').replace(/\s+/g, '');
  if (computedBh !== expectedBh) {
    throw new DkimError('DKIM_BODY_HASH_MISMATCH', 'Canonicalized body SHA-256 does not match DKIM bh=');
  }

  // Resolve public key offline from options.publicKeyPem or options.trustedKeys
  const dnsRecordName = `${selector}._domainkey.${domain}`;
  const pubPem = options.publicKeyPem || options.trustedKeys?.[dnsRecordName];
  if (!pubPem) {
    throw new DkimError('DKIM_KEY_NOT_FOUND', `No trusted offline public key for ${dnsRecordName}`);
  }

  const pubKeyObj = createPublicKey(pubPem);
  const modLen = pubKeyObj.asymmetricKeyDetails?.modulusLength ?? 0;
  if (pubKeyObj.asymmetricKeyType !== 'rsa' || modLen < 2048) {
    throw new DkimError('DKIM_WEAK_KEY', `RSA key modulus length ${modLen} < 2048 bits`);
  }

  // Reconstruct signed header hash input bottom-up per RFC 6376 §5.4.2
  const consumedIndices = new Set();
  const signedLines = [];
  for (const hName of signedHeaderList) {
    let matchedIdx = -1;
    for (let i = rawHeaders.length - 1; i >= 0; i--) {
      if (!consumedIndices.has(i) && rawHeaders[i].lowerName === hName) {
        matchedIdx = i;
        break;
      }
    }
    if (matchedIdx >= 0) {
      consumedIndices.add(matchedIdx);
      signedLines.push(`${canonHeaderFn(rawHeaders[matchedIdx].raw)}\r\n`);
    }
  }

  const dkimWithoutB = stripDkimSignatureValue(dkimHeader.raw);
  signedLines.push(canonHeaderFn(dkimWithoutB));
  const signingInput = signedLines.join('');

  const sigBytes = Buffer.from((tags.b || '').replace(/\s+/g, ''), 'base64');
  const verifier = createVerify('RSA-SHA256');
  verifier.update(signingInput, 'utf8');
  verifier.end();
  if (!verifier.verify(pubKeyObj, sigBytes)) {
    throw new DkimError('DKIM_SIGNATURE_INVALID', 'RSASSA-PKCS1-v1_5 signature verification failed');
  }

  const attachments = extractMimeAttachments(rawHeaders, bodyBlock);

  return {
    ok: true,
    status: 'DKIM_VERIFIED',
    domain,
    selector,
    dnsRecordName,
    canonicalization: `${headerCanonAlg}/${bodyCanonAlg}`,
    signedHeaders: signedHeaderList,
    bodyHash: computedBh,
    attachments,
  };
}

/**
 * Helper to construct a deterministically signed RFC 6376 DKIM .eml for testing.
 */
export function signDkimEml({
  headers,
  body,
  domain,
  selector,
  privateKeyPem,
  canonicalization = 'relaxed/relaxed',
  signedHeaders = ['From', 'To', 'Subject', 'Date', 'MIME-Version', 'Content-Type'],
  extraTags = '',
}) {
  const [hAlg, bAlg] = canonicalization.split('/');
  const canonHeaderFn = hAlg === 'relaxed' ? canonicalizeHeaderRelaxed : canonicalizeHeaderSimple;
  const canonBodyFn = bAlg === 'relaxed' ? canonicalizeBodyRelaxed : canonicalizeBodySimple;

  const canonBody = canonBodyFn(body);
  const bh = createHash('sha256').update(canonBody, 'utf8').digest('base64');
  const hTag = signedHeaders.join(':');
  const dkimTemplate =
    `DKIM-Signature: v=1; a=rsa-sha256; c=${canonicalization}; d=${domain}; s=${selector}; ` +
    `${extraTags ? extraTags + '; ' : ''}h=${hTag}; bh=${bh}; b=`;

  const rawHeaderLines = headers.map((h) => `${h.name}: ${h.value}`);
  const parsedHeaders = rawHeaderLines.map((raw, i) => ({
    lowerName: headers[i].name.toLowerCase(),
    raw,
  }));

  const consumed = new Set();
  const signingParts = [];
  for (const hName of signedHeaders.map((x) => x.toLowerCase())) {
    for (let i = parsedHeaders.length - 1; i >= 0; i--) {
      if (!consumed.has(i) && parsedHeaders[i].lowerName === hName) {
        consumed.add(i);
        signingParts.push(`${canonHeaderFn(parsedHeaders[i].raw)}\r\n`);
        break;
      }
    }
  }
  signingParts.push(canonHeaderFn(dkimTemplate));
  const signingInput = signingParts.join('');

  const signer = createSign('RSA-SHA256');
  signer.update(signingInput, 'utf8');
  signer.end();
  const bSig = signer.sign(privateKeyPem, 'base64');

  const fullDkimHeader = `${dkimTemplate}${bSig}`;
  return `${[fullDkimHeader, ...rawHeaderLines].join('\r\n')}\r\n\r\n${body}`;
}

export function runCli(args) {
  const help =
    'Usage: node scripts/verify-dkim-statement.mjs MESSAGE.eml --domain DOMAIN --pubkey-pem FILE\n' +
    'Offline RFC 6376 DKIM (rsa-sha256) broker statement attachment verifier.\n';
  if (args.length === 1 && args[0] === '--help') return { exitCode: 0, output: help };
  try {
    let emlFile = null;
    let domain = null;
    let pubkeyFile = null;
    for (let i = 0; i < args.length; i++) {
      if (args[i] === '--domain' && i + 1 < args.length) domain = args[++i];
      else if (args[i] === '--pubkey-pem' && i + 1 < args.length) pubkeyFile = args[++i];
      else if (!args[i].startsWith('--') && !emlFile) emlFile = args[i];
      else return { exitCode: 3, output: JSON.stringify({ status: 'INVALID_INPUT' }) + '\n' };
    }
    if (!emlFile || !domain || !pubkeyFile) {
      return { exitCode: 3, output: JSON.stringify({ status: 'INVALID_INPUT' }) + '\n' };
    }
    const rawEml = readFileSync(emlFile, 'utf8');
    const publicKeyPem = readFileSync(pubkeyFile, 'utf8');
    const res = verifyDkimStatementEml(rawEml, { expectedDomain: domain, publicKeyPem });
    return {
      exitCode: 0,
      output: JSON.stringify({
        status: res.status,
        domain: res.domain,
        selector: res.selector,
        attachments: res.attachments.map((a) => ({
          filename: a.filename,
          contentType: a.contentType,
          bytes: a.bytes.length,
          sha256: a.sha256,
        })),
      }, null, 2) + '\n',
    };
  } catch (e) {
    return {
      exitCode: 1,
      output: JSON.stringify({ status: 'REJECTED', code: e.code || 'DKIM_INVALID' }) + '\n',
    };
  }
}

if (process.argv[1] && process.argv[1].endsWith('verify-dkim-statement.mjs')) {
  const r = runCli(process.argv.slice(2));
  process.stdout.write(r.output);
  process.exitCode = r.exitCode;
}
