// src/directBrokerSource.js: Browser + Node zero-dependency direct broker provenance & cross-contamination verifier.

export const CONSUMER_AND_RELAY_DOMAINS = Object.freeze([
  'gmail.com',
  'googlemail.com',
  'outlook.com',
  'hotmail.com',
  'live.com',
  'yahoo.com',
  'icloud.com',
  'me.com',
  'proton.me',
  'protonmail.com',
  'aol.com',
  'zoho.com',
  'gmx.com',
  'fastmail.com',
  'comcast.net',
]);

const CONSUMER_DOMAIN_SET = new Set(CONSUMER_AND_RELAY_DOMAINS);

export const BROKER_PROVENANCE_MATRIX = Object.freeze({
  IBKR: Object.freeze({
    institution: 'IBKR',
    displayName: 'Interactive Brokers',
    tier: 1,
    allowedDkimDomains: Object.freeze(['interactivebrokers.com', 'ibkr.com']),
    supportedArtifacts: Object.freeze(['DKIM_EML_STATEMENT_ATTACHMENT', 'FLEX_V3_TLS_WITNESS']),
    pdfSignatureType: 'UNSIGNED_PDF',
    fullPeriodNavCryptographic: true,
    defaultScope: 'FULL_PERIOD_NAV_AND_FLOWS',
    defaultQualification: null,
  }),
  SAXO: Object.freeze({
    institution: 'SAXO',
    displayName: 'SAXO Bank',
    tier: 1,
    allowedDkimDomains: Object.freeze([]),
    supportedArtifacts: Object.freeze(['ECH0196_XMLDSIG']),
    pdfSignatureType: 'ECH0196_BARCODE_XMLDSIG_OR_UNSIGNED_STANDARD_PDF',
    fullPeriodNavCryptographic: true,
    defaultScope: 'ANNUAL_ECH0196_TAX_STATEMENT',
    defaultQualification: 'ANNUAL_SWISS_TAX_STATEMENT_SCOPE',
  }),
  SWISSQUOTE: Object.freeze({
    institution: 'SWISSQUOTE',
    displayName: 'Swissquote',
    tier: 1,
    allowedDkimDomains: Object.freeze(['swissquote.ch', 'swissquote.com']),
    supportedArtifacts: Object.freeze(['ECH0196_XMLDSIG', 'DKIM_EML_TRADE_CONFIRM']),
    pdfSignatureType: 'ECH0196_BARCODE_XMLDSIG_OR_UNSIGNED_STANDARD_PDF',
    fullPeriodNavCryptographic: true,
    defaultScope: 'ANNUAL_ECH0196_TAX_STATEMENT',
    defaultQualification: 'ANNUAL_SWISS_TAX_STATEMENT_SCOPE',
  }),
  SCHWAB: Object.freeze({
    institution: 'SCHWAB',
    displayName: 'Charles Schwab',
    tier: 2,
    allowedDkimDomains: Object.freeze(['schwab.com', 'mail.schwab.com']),
    supportedArtifacts: Object.freeze(['DKIM_EML_TRADE_CONFIRM']),
    pdfSignatureType: 'UNSIGNED_PDF',
    fullPeriodNavCryptographic: false,
    defaultScope: 'SINGLE_TRADE_CONFIRMATION',
    defaultQualification: 'SINGLE_TRADE_ONLY_NO_FULL_NAV',
  }),
  VANGUARD: Object.freeze({
    institution: 'VANGUARD',
    displayName: 'Vanguard',
    tier: 2,
    allowedDkimDomains: Object.freeze(['vanguard.com', 'vanguard.com.au', 'e-vanguard.com.au']),
    supportedArtifacts: Object.freeze(['DKIM_EML_TRADE_CONFIRM']),
    pdfSignatureType: 'UNSIGNED_PDF',
    fullPeriodNavCryptographic: false,
    defaultScope: 'SINGLE_TRADE_CONFIRMATION',
    defaultQualification: 'SINGLE_TRADE_ONLY_NO_FULL_NAV',
  }),
  WISE: Object.freeze({
    institution: 'WISE',
    displayName: 'Wise',
    tier: 3,
    allowedDkimDomains: Object.freeze(['wise.com', 'transferwise.com']),
    supportedArtifacts: Object.freeze(['WISE_WEBHOOK_RSA_SHA256', 'DKIM_EML_TRANSFER_RECEIPT']),
    pdfSignatureType: 'VISUAL_STAMP_TRAP',
    fullPeriodNavCryptographic: false,
    defaultScope: 'SINGLE_TRANSFER_WEBHOOK',
    defaultQualification: 'SINGLE_TRANSFER_ONLY_NO_FULL_NAV',
  }),
  REVOLUT: Object.freeze({
    institution: 'REVOLUT',
    displayName: 'Revolut',
    tier: 3,
    allowedDkimDomains: Object.freeze(['revolut.com']),
    supportedArtifacts: Object.freeze(['DKIM_EML_TRANSFER_RECEIPT']),
    pdfSignatureType: 'VISUAL_STAMP_TRAP',
    fullPeriodNavCryptographic: false,
    defaultScope: 'SINGLE_TRANSFER_RECEIPT',
    defaultQualification: 'SINGLE_TRANSFER_ONLY_NO_FULL_NAV',
  }),
  FIDELITY: Object.freeze({
    institution: 'FIDELITY',
    displayName: 'Fidelity Investments',
    tier: 4,
    allowedDkimDomains: Object.freeze(['fidelity.com', 'mail.fidelity.com']),
    supportedArtifacts: Object.freeze([]),
    pdfSignatureType: 'UNSIGNED_PDF',
    fullPeriodNavCryptographic: false,
    defaultScope: 'NONE_LOGIN_WALL_AND_SELF_EMAIL_TRAP',
    defaultQualification: 'UNVERIFIABLE_WITHOUT_TLS_WITNESS',
  }),
  TRADESTATION: Object.freeze({
    institution: 'TRADESTATION',
    displayName: 'TradeStation',
    tier: 4,
    allowedDkimDomains: Object.freeze(['tradestation.com']),
    supportedArtifacts: Object.freeze([]),
    pdfSignatureType: 'UNSIGNED_PDF',
    fullPeriodNavCryptographic: false,
    defaultScope: 'NONE_USER_SMTP_TRAP',
    defaultQualification: 'UNVERIFIABLE_USER_SMTP_SELF_ATTESTATION',
  }),
});

export class BrokerSourceError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.code = code;
    this.details = details;
  }
}

function assertNeverInstitution(institution) {
  throw new BrokerSourceError(
    'REFUSE_UNSUPPORTED_INSTITUTION',
    `Unsupported broker institution: "${String(institution)}"`
  );
}

function toUint8Array(input) {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  return new TextEncoder().encode(String(input ?? ''));
}

function bytesToLatin1(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += String.fromCharCode(bytes[i]);
  }
  return out;
}

function b64ToBytes(b64) {
  const clean = String(b64).replace(/\s+/g, '');
  if (typeof globalThis.atob === 'function') {
    const bin = globalThis.atob(clean);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  return new Uint8Array(globalThis.Buffer.from(clean, 'base64'));
}

function bytesToB64(bytes) {
  if (typeof globalThis.btoa === 'function') {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return globalThis.btoa(bin);
  }
  return globalThis.Buffer.from(bytes).toString('base64');
}

function bytesToHex(bytes) {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

function pemToDerBytes(pem) {
  const clean = String(pem)
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '');
  return b64ToBytes(clean);
}

/**
 * Inspects a PDF byte stream for ISO 32000-1 / PAdES cryptographic signature dictionaries
 * (/ByteRange + /Contents) vs. visual-only graphic stamp traps.
 */
export function inspectPdfCryptographicSignature(pdfInput) {
  const bytes =
    typeof pdfInput === 'string'
      ? Uint8Array.from(pdfInput, (c) => c.charCodeAt(0) & 0xff)
      : toUint8Array(pdfInput);
  const rawLatin1 = bytesToLatin1(bytes);
  const isPdf = rawLatin1.startsWith('%PDF-');
  if (!isPdf) {
    return Object.freeze({
      isPdf: false,
      hasCryptographicSignature: false,
      hasVisualStampOverlay: false,
      subFilter: null,
      byteRange: null,
      byteRangeCoversEntireFile: false,
      reason: 'NOT_A_PDF',
    });
  }

  const hasVisualStampOverlay =
    /Signed and stamped|Stamp and sign this document|Stamped and Signed|Visual Stamp|Facsimile Signature|Revolut Business.*Stamp|Wise.*Stamp/i.test(
      rawLatin1
    );

  const hasSigType = /\/(?:Type|FT)\s*\/Sig\b/.test(rawLatin1);
  const subFilterMatch = /\/SubFilter\s*\/(adbe\.pkcs7\.detached|ETSI\.CAdES\.detached|ETSI\.RFC3161)\b/.exec(
    rawLatin1
  );
  const byteRangeMatch = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/.exec(rawLatin1);
  const contentsMatch = /\/Contents\s*<([0-9A-Fa-f\s]+)>/.exec(rawLatin1);

  if (!hasSigType || !subFilterMatch || !byteRangeMatch || !contentsMatch) {
    return Object.freeze({
      isPdf: true,
      hasCryptographicSignature: false,
      hasVisualStampOverlay,
      subFilter: subFilterMatch ? subFilterMatch[1] : null,
      byteRange: byteRangeMatch ? byteRangeMatch.slice(1, 5).map(Number) : null,
      byteRangeCoversEntireFile: false,
      reason: hasVisualStampOverlay ? 'VISUAL_STAMP_NOT_CRYPTOGRAPHIC' : 'UNSIGNED_PDF',
    });
  }

  const [o1, l1, o2, l2] = byteRangeMatch.slice(1, 5).map(Number);
  const contentsHex = contentsMatch[1].replace(/\s+/g, '');
  const byteRangeCoversEntireFile =
    o1 === 0 &&
    l1 > 0 &&
    o2 > l1 &&
    o2 + l2 === bytes.length &&
    contentsHex.length >= 128 &&
    !/^0+$/.test(contentsHex);

  return Object.freeze({
    isPdf: true,
    hasCryptographicSignature: byteRangeCoversEntireFile,
    hasVisualStampOverlay,
    subFilter: subFilterMatch[1],
    byteRange: Object.freeze([o1, l1, o2, l2]),
    byteRangeCoversEntireFile,
    reason: byteRangeCoversEntireFile ? 'VALID_PADES_STRUCTURE' : 'BYTE_RANGE_INCOMPLETE',
  });
}

function extractEmailAddressAndDomain(rawHeaderValue) {
  const text = String(rawHeaderValue || '').trim();
  const angleMatch = /<([^<>@\s]+@[^<>@\s]+)>/.exec(text);
  const directMatch = /([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})/.exec(text);
  const address = (angleMatch ? angleMatch[1] : directMatch ? directMatch[1] : '').toLowerCase();
  const atIdx = address.lastIndexOf('@');
  const domain = atIdx >= 0 ? address.slice(atIdx + 1) : '';
  return { address, domain };
}

function parseEmlHeadersAndBody(rawEml) {
  const text =
    rawEml instanceof Uint8Array
      ? new TextDecoder('utf-8').decode(rawEml)
      : String(rawEml ?? '');
  const normalized = text.replace(/\r?\n/g, '\r\n');
  const splitIdx = normalized.indexOf('\r\n\r\n');
  if (splitIdx < 0) {
    throw new BrokerSourceError('DKIM_MALFORMED_EML', 'EML missing header/body CRLFCRLF separator');
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
        throw new BrokerSourceError('DKIM_MALFORMED_HEADER', `Malformed header line: ${line}`);
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

function parseDkimHeaderTags(rawDkimHeader) {
  const colonIdx = rawDkimHeader.indexOf(':');
  const val = colonIdx >= 0 ? rawDkimHeader.slice(colonIdx + 1) : rawDkimHeader;
  const unfolded = val.replace(/\r?\n[ \t]+/g, ' ').trim();
  const tags = {};
  for (const part of unfolded.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx < 0) {
      throw new BrokerSourceError('DKIM_MALFORMED_TAG', `Malformed DKIM tag: ${trimmed}`);
    }
    const k = trimmed.slice(0, eqIdx).trim();
    const v = trimmed.slice(eqIdx + 1).trim();
    if (Object.hasOwn(tags, k)) {
      throw new BrokerSourceError('DKIM_DUPLICATE_TAG', `Duplicate DKIM tag "${k}="`);
    }
    tags[k] = v;
  }
  return tags;
}

function canonicalizeHeaderSimple(rawHeader) {
  return rawHeader.replace(/\r?\n$/, '');
}

function canonicalizeHeaderRelaxed(rawHeader) {
  const noTrailing = rawHeader.replace(/\r?\n$/, '');
  const colonIdx = noTrailing.indexOf(':');
  const name = noTrailing.slice(0, colonIdx).toLowerCase().trim();
  const unfoldedVal = noTrailing
    .slice(colonIdx + 1)
    .replace(/\r?\n[ \t]+/g, ' ')
    .replace(/[ \t]+/g, ' ')
    .trim();
  return `${name}:${unfoldedVal}`;
}

function canonicalizeBodySimple(rawBody) {
  const crlf = String(rawBody ?? '').replace(/\r?\n/g, '\r\n');
  const stripped = crlf.replace(/(\r\n)+$/, '');
  return `${stripped}\r\n`;
}

function canonicalizeBodyRelaxed(rawBody) {
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

function resolveBrokerConfig(rawInstitution) {
  const code = String(rawInstitution || '').toUpperCase().trim();
  switch (code) {
    case 'IBKR':
      return BROKER_PROVENANCE_MATRIX.IBKR;
    case 'SAXO':
      return BROKER_PROVENANCE_MATRIX.SAXO;
    case 'SWISSQUOTE':
      return BROKER_PROVENANCE_MATRIX.SWISSQUOTE;
    case 'SCHWAB':
      return BROKER_PROVENANCE_MATRIX.SCHWAB;
    case 'VANGUARD':
      return BROKER_PROVENANCE_MATRIX.VANGUARD;
    case 'WISE':
      return BROKER_PROVENANCE_MATRIX.WISE;
    case 'REVOLUT':
      return BROKER_PROVENANCE_MATRIX.REVOLUT;
    case 'FIDELITY':
      return BROKER_PROVENANCE_MATRIX.FIDELITY;
    case 'TRADESTATION':
      return BROKER_PROVENANCE_MATRIX.TRADESTATION;
    default:
      return assertNeverInstitution(code);
  }
}

/**
 * Verifies a Wise X-Signature-SHA256 webhook signature using WebCrypto RSASSA-PKCS1-v1_5.
 */
export async function verifyWiseWebhookSignatureWeb(rawJsonBody, signatureBase64, publicKeyPem) {
  if (!rawJsonBody || !signatureBase64 || !publicKeyPem) {
    throw new BrokerSourceError(
      'REFUSE_WISE_WEBHOOK_SIGNATURE_INVALID',
      'Wise webhook verification requires rawJsonBody, signatureBase64, and publicKeyPem'
    );
  }
  const rawBytes = toUint8Array(rawJsonBody);
  const derBytes = pemToDerBytes(publicKeyPem);
  let cryptoKey;
  try {
    cryptoKey = await globalThis.crypto.subtle.importKey(
      'spki',
      derBytes,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      true,
      ['verify']
    );
  } catch (err) {
    throw new BrokerSourceError('REFUSE_WISE_WEBHOOK_SIGNATURE_INVALID', `Invalid Wise SPKI key: ${err.message}`);
  }
  const jwk = await globalThis.crypto.subtle.exportKey('jwk', cryptoKey);
  const modBytes = jwk.n ? b64ToBytes(jwk.n.replace(/-/g, '+').replace(/_/g, '/')) : new Uint8Array(0);
  const modBits = modBytes.length * 8;
  if (modBits < 2048) {
    throw new BrokerSourceError('REFUSE_WEAK_RSA_KEY', `Wise webhook RSA key modulus ${modBits} < 2048 bits`);
  }

  const sigBytes = b64ToBytes(signatureBase64);
  const valid = await globalThis.crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    cryptoKey,
    sigBytes,
    rawBytes
  );
  if (!valid) {
    throw new BrokerSourceError(
      'REFUSE_WISE_WEBHOOK_SIGNATURE_INVALID',
      'Wise X-Signature-SHA256 RSA-SHA256 verification failed over raw JSON body'
    );
  }

  let parsed;
  try {
    parsed = JSON.parse(new TextDecoder('utf-8').decode(rawBytes));
  } catch {
    throw new BrokerSourceError('REFUSE_WISE_WEBHOOK_MALFORMED_JSON', 'Wise webhook payload is not valid JSON');
  }

  const digestBuf = await globalThis.crypto.subtle.digest('SHA-256', rawBytes);
  return Object.freeze({
    ok: true,
    status: 'BROKER_PROVENANCE_VERIFIED',
    institution: 'WISE',
    artifactType: 'WISE_WEBHOOK_RSA_SHA256',
    scope: 'SINGLE_TRANSFER_WEBHOOK',
    qualification: 'SINGLE_TRANSFER_ONLY_NO_FULL_NAV',
    payloadSha256: bytesToHex(new Uint8Array(digestBuf)),
    eventType: parsed?.event_type || null,
    transferId: parsed?.data?.resource?.id !== undefined ? String(parsed.data.resource.id) : null,
    currentState: parsed?.data?.current_state || null,
  });
}

/**
 * Browser / WebCrypto verifier for direct broker artifacts and cross-contamination refusal gates.
 */
export async function verifyDirectBrokerArtifactWeb(input, options = {}) {
  const brokerConfig = resolveBrokerConfig(input?.institution || options?.institution);
  const rawPayload =
    input?.content ??
    input?.rawEml ??
    input?.xmlText ??
    input?.pdfBytes ??
    input?.rawJsonBody ??
    '';
  const payloadBytes = toUint8Array(rawPayload);
  const explicitType = String(input?.artifactType || '').toUpperCase().trim();
  const headText = new TextDecoder('utf-8', { fatal: false })
    .decode(payloadBytes.subarray(0, 512))
    .replace(/^\uFEFF/, '')
    .trimStart();

  const artifactType =
    explicitType && explicitType !== 'AUTO'
      ? explicitType
      : input?.signatureBase64 || options?.signatureBase64
        ? 'WISE_WEBHOOK'
        : headText.startsWith('%PDF-')
          ? 'PDF'
          : headText.startsWith('<?xml') || /^<(?:\w+:)?taxStatement\b/i.test(headText)
            ? 'ECH0196_XML'
            : /^(?:DKIM-Signature|From|Return-Path|Received|MIME-Version)\s*:/im.test(headText)
              ? 'EML'
              : 'UNKNOWN';

  if (artifactType === 'WISE_WEBHOOK') {
    if (brokerConfig.institution !== 'WISE') {
      throw new BrokerSourceError(
        'REFUSE_UNSUPPORTED_ARTIFACT_FOR_INSTITUTION',
        `X-Signature-SHA256 webhook verification is only supported for WISE, not ${brokerConfig.institution}`
      );
    }
    return verifyWiseWebhookSignatureWeb(
      payloadBytes,
      input?.signatureBase64 ?? options?.signatureBase64,
      options?.publicKeyPem ?? input?.publicKeyPem
    );
  }

  if (artifactType === 'PDF') {
    const pdfInspection = inspectPdfCryptographicSignature(payloadBytes);
    if (!pdfInspection.hasCryptographicSignature) {
      if (
        brokerConfig.institution === 'REVOLUT' ||
        brokerConfig.institution === 'WISE' ||
        pdfInspection.hasVisualStampOverlay ||
        pdfInspection.reason === 'BYTE_RANGE_INCOMPLETE'
      ) {
        throw new BrokerSourceError(
          'REFUSE_VISUAL_STAMP_NOT_CRYPTOGRAPHIC',
          `${brokerConfig.displayName} PDF contains a visual graphic stamp or facsimile signature overlay without an ISO 32000-1 / PAdES cryptographic /ByteRange + /Contents signature`,
          { pdfInspection }
        );
      }
      throw new BrokerSourceError(
        'REFUSE_UNSIGNED_PORTAL_PDF',
        `${brokerConfig.displayName} portal PDF carries no cryptographic PAdES / PKCS#7 signature`,
        { pdfInspection }
      );
    }
  }

  if (artifactType === 'EML') {
    const { rawHeaders, bodyBlock } = parseEmlHeadersAndBody(payloadBytes);
    const fromHeader = rawHeaders.find((h) => h.lowerName === 'from');
    const toHeader = rawHeaders.find((h) => h.lowerName === 'to');
    const subjectHeader = rawHeaders.find((h) => h.lowerName === 'subject');
    const dkimHeader = rawHeaders.find((h) => h.lowerName === 'dkim-signature');

    const { address: fromAddress, domain: fromDomain } = extractEmailAddressAndDomain(
      fromHeader ? fromHeader.raw.slice(fromHeader.raw.indexOf(':') + 1) : ''
    );
    const { address: toAddress } = extractEmailAddressAndDomain(
      toHeader ? toHeader.raw.slice(toHeader.raw.indexOf(':') + 1) : ''
    );
    const subject = subjectHeader ? subjectHeader.raw.slice(subjectHeader.raw.indexOf(':') + 1).trim() : '';
    const dkimTags = dkimHeader ? parseDkimHeaderTags(dkimHeader.raw) : {};
    const dkimDomain = String(dkimTags.d || '').toLowerCase();

    if (
      brokerConfig.institution === 'TRADESTATION' ||
      /TradeManager|TradeStation.*Order.*Fill/i.test(subject)
    ) {
      if (
        (fromAddress && toAddress && fromAddress === toAddress) ||
        CONSUMER_DOMAIN_SET.has(dkimDomain) ||
        CONSUMER_DOMAIN_SET.has(fromDomain) ||
        dkimDomain !== 'tradestation.com'
      ) {
        throw new BrokerSourceError(
          'REFUSE_USER_SMTP_SELF_ATTESTATION',
          'TradeStation order-fill alert is routed via user-configured SMTP (From == To or user mail server) and has zero broker cryptographic authority',
          { fromAddress, toAddress, dkimDomain }
        );
      }
    }

    if (
      CONSUMER_DOMAIN_SET.has(dkimDomain) ||
      CONSUMER_DOMAIN_SET.has(fromDomain) ||
      (fromAddress && toAddress && fromAddress === toAddress) ||
      !brokerConfig.allowedDkimDomains.includes(dkimDomain) ||
      (fromDomain && !brokerConfig.allowedDkimDomains.some((d) => fromDomain === d || fromDomain.endsWith(`.${d}`)))
    ) {
      throw new BrokerSourceError(
        'REFUSE_SELF_EMAILED_RELAY_CONTAMINATION',
        `Message DKIM domain "${dkimDomain}" / From domain "${fromDomain}" is a consumer/personal relay or does not match pinned domains for ${brokerConfig.institution}`,
        { institution: brokerConfig.institution, dkimDomain, fromDomain, fromAddress, toAddress }
      );
    }

    if (Object.hasOwn(dkimTags, 'l')) {
      throw new BrokerSourceError('DKIM_BODY_LENGTH_TAG_FORBIDDEN', 'DKIM l= body-length tag is forbidden');
    }

    const canonSpec = String(dkimTags.c || 'simple/simple').toLowerCase().split('/');
    const hCanon = canonSpec[0] === 'relaxed' ? canonicalizeHeaderRelaxed : canonicalizeHeaderSimple;
    const bCanon = canonSpec[1] === 'relaxed' ? canonicalizeBodyRelaxed : canonicalizeBodySimple;
    const canonBodyBytes = new TextEncoder().encode(bCanon(bodyBlock));
    const bodyHashBuf = await globalThis.crypto.subtle.digest('SHA-256', canonBodyBytes);
    const computedBh = bytesToB64(new Uint8Array(bodyHashBuf));
    if (computedBh !== String(dkimTags.bh || '').replace(/\s+/g, '')) {
      throw new BrokerSourceError('DKIM_BODY_HASH_MISMATCH', 'Canonicalized body SHA-256 does not match DKIM bh=');
    }

    const pubPem = options?.publicKeyPem ?? input?.publicKeyPem;
    if (!pubPem) {
      throw new BrokerSourceError('DKIM_KEY_NOT_FOUND', 'Missing trusted DKIM public key PEM');
    }
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      'spki',
      pemToDerBytes(pubPem),
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const signedHeaderList = String(dkimTags.h || '')
      .split(':')
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);
    const consumedIndices = new Set();
    const signedLines = [];
    for (const hName of signedHeaderList) {
      for (let i = rawHeaders.length - 1; i >= 0; i--) {
        if (!consumedIndices.has(i) && rawHeaders[i].lowerName === hName) {
          consumedIndices.add(i);
          signedLines.push(`${hCanon(rawHeaders[i].raw)}\r\n`);
          break;
        }
      }
    }
    const dkimWithoutB = dkimHeader.raw.replace(/(\bb\s*=\s*)([^;]*)/, '$1');
    signedLines.push(hCanon(dkimWithoutB));
    const signingInputBytes = new TextEncoder().encode(signedLines.join(''));
    const sigBytes = b64ToBytes(dkimTags.b || '');
    const sigValid = await globalThis.crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      cryptoKey,
      sigBytes,
      signingInputBytes
    );
    if (!sigValid) {
      throw new BrokerSourceError('DKIM_SIGNATURE_INVALID', 'DKIM RSASSA-PKCS1-v1_5 signature invalid');
    }

    if (brokerConfig.institution === 'FIDELITY') {
      throw new BrokerSourceError(
        'REFUSE_NOTIFICATION_LINK_ONLY_NO_PAYLOAD',
        'Fidelity email is a portal login-link notification and contains no cryptographic statement payload'
      );
    }

    return Object.freeze({
      ok: true,
      status: 'BROKER_PROVENANCE_VERIFIED',
      institution: brokerConfig.institution,
      artifactType:
        brokerConfig.institution === 'IBKR'
          ? 'DKIM_EML_STATEMENT_ATTACHMENT'
          : brokerConfig.institution === 'WISE' || brokerConfig.institution === 'REVOLUT'
            ? 'DKIM_EML_TRANSFER_RECEIPT'
            : 'DKIM_EML_TRADE_CONFIRM',
      scope:
        brokerConfig.institution === 'IBKR'
          ? 'FULL_PERIOD_NAV_AND_FLOWS'
          : brokerConfig.institution === 'WISE' || brokerConfig.institution === 'REVOLUT'
            ? 'SINGLE_TRANSFER_RECEIPT'
            : 'SINGLE_TRADE_CONFIRMATION',
      qualification:
        brokerConfig.institution === 'IBKR'
          ? null
          : brokerConfig.institution === 'WISE' || brokerConfig.institution === 'REVOLUT'
            ? 'SINGLE_TRANSFER_ONLY_NO_FULL_NAV'
            : 'SINGLE_TRADE_ONLY_NO_FULL_NAV',
      dkimDomain,
      dkimSelector: dkimTags.s || '',
      bodyHash: computedBh,
    });
  }

  throw new BrokerSourceError(
    'REFUSE_UNSUPPORTED_ARTIFACT_FOR_INSTITUTION',
    `Unsupported artifact type "${artifactType}" for institution "${brokerConfig.institution}"`
  );
}
