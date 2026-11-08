#!/usr/bin/env node
// scripts/verify-ech0196-statement.mjs: Offline Swiss eCH-0196 v2.2.0 eSteuerauszug W3C XMLDSIG verifier.
import {
  X509Certificate,
  createHash,
  createPublicKey,
  createSign,
  createVerify,
  generateKeyPairSync,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export const XMLDSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';
export const ECH0196_NS = 'http://www.ech.ch/xmlns/eCH-0196/2';

export const C14N_WITH_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
export const C14N_NO_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
export const TRANSFORM_ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

export const DIGEST_SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';
export const DIGEST_SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';

export const SIG_RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
export const SIG_RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';

const DEFAULT_TRUSTED_SUBJECT_RE = /Saxo|Swissquote|SwissSign|QuoVadis|DigiCert|Swisscom/i;

export class Ech0196Error extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function assertNever(value, code, message) {
  throw new Ech0196Error(code, `${message}: ${String(value)}`);
}

/**
 * Parses a decimal string into a 1e8-scaled BigInt without IEEE-754 float drift.
 */
export function parseScaledChfDecimal(raw, fieldName = 'amount') {
  if (raw === undefined || raw === null || raw === '') return 0n;
  const cleaned = String(raw).trim();
  if (!/^-?\d+(?:\.\d+)?$/.test(cleaned)) {
    throw new Ech0196Error('REFUSE_CORRUPT_DECIMAL', `Invalid decimal "${raw}" in ${fieldName}`);
  }
  const negative = cleaned.startsWith('-');
  const unsigned = negative ? cleaned.slice(1) : cleaned;
  const [intPart, fracPart = ''] = unsigned.split('.');
  if (fracPart.length > 8 && !/^0+$/.test(fracPart.slice(8))) {
    throw new Ech0196Error('REFUSE_CORRUPT_DECIMAL', `Excess decimal precision in "${raw}" on ${fieldName}`);
  }
  const paddedFrac = (fracPart + '00000000').slice(0, 8);
  const scaled = BigInt(intPart) * 100000000n + BigInt(paddedFrac);
  return negative ? -scaled : scaled;
}

function unescapeXmlEntities(str) {
  return String(str)
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#x9;/gi, '\t')
    .replace(/&#xA;/gi, '\n')
    .replace(/&#xD;/gi, '\r')
    .replace(/&amp;/g, '&');
}

function escapeXmlAttr(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/"/g, '&quot;')
    .replace(/\t/g, '&#x9;')
    .replace(/\n/g, '&#xA;')
    .replace(/\r/g, '&#xD;');
}

function escapeXmlText(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\r/g, '&#xD;');
}

function parseRawAttributes(attrText) {
  const attrs = [];
  const re = /([A-Za-z_][A-Za-z0-9_.:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
  let m;
  while ((m = re.exec(attrText)) !== null) {
    const name = m[1];
    const value = unescapeXmlEntities(m[2] !== undefined ? m[2] : m[3]);
    attrs.push({ name, value });
  }
  return attrs;
}

/**
 * Pure JavaScript W3C Canonical XML 1.0 (xml-c14n-20010315 and #WithComments) serializer.
 */
export function canonicalizeXmlC14n(xmlInput, options = {}) {
  const withComments = options.withComments !== false;
  const inheritedNs = options.inheritedNamespaces || {};

  let text = String(xmlInput ?? '').replace(/\r\n?/g, '\n');
  text = text.replace(/^\uFEFF/, '').replace(/^<\?xml[^>]*\?>\s*/i, '');

  const tokenRe = /<!--([\s\S]*?)--!?>|<\/([A-Za-z_][A-Za-z0-9_.:-]*)\s*>|<([A-Za-z_][A-Za-z0-9_.:-]*)((?:\s+[A-Za-z_][A-Za-z0-9_.:-]*\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>|([^<]+)/g;

  const nsStack = [{ ...inheritedNs }];
  let isRootElement = true;
  const out = [];
  let m;

  while ((m = tokenRe.exec(text)) !== null) {
    if (m[1] !== undefined) {
      if (withComments) {
        out.push(`<!--${m[1]}-->`);
      }
      continue;
    }

    if (m[2] !== undefined) {
      const closeTag = m[2];
      nsStack.pop();
      out.push(`</${closeTag}>`);
      continue;
    }

    if (m[3] !== undefined) {
      const tagName = m[3];
      const rawAttrs = parseRawAttributes(m[4] || '');
      const selfClosing = m[5] === '/';

      const parentNs = nsStack[nsStack.length - 1] || {};
      const currentNs = { ...parentNs };
      const nsDecls = [];
      const regularAttrs = [];

      for (const attr of rawAttrs) {
        if (attr.name === 'xmlns') {
          nsDecls.push({ prefix: '', uri: attr.value });
        } else if (attr.name.startsWith('xmlns:')) {
          nsDecls.push({ prefix: attr.name.slice(6), uri: attr.value });
        } else {
          regularAttrs.push(attr);
        }
      }

      if (isRootElement) {
        for (const [prefix, uri] of Object.entries(inheritedNs)) {
          const alreadyDeclared = nsDecls.some((d) => d.prefix === prefix);
          if (!alreadyDeclared) {
            nsDecls.push({ prefix, uri });
          }
        }
      }

      const renderedNs = [];
      for (const decl of nsDecls) {
        const prevUri = isRootElement ? undefined : parentNs[decl.prefix];
        if (prevUri !== decl.uri) {
          if (decl.prefix === '' && decl.uri === '' && prevUri === undefined) {
            continue;
          }
          renderedNs.push(decl);
          currentNs[decl.prefix] = decl.uri;
        }
      }

      renderedNs.sort((a, b) => (a.prefix < b.prefix ? -1 : a.prefix > b.prefix ? 1 : 0));

      regularAttrs.sort((a, b) => {
        const aColon = a.name.indexOf(':');
        const bColon = b.name.indexOf(':');
        const aPrefix = aColon >= 0 ? a.name.slice(0, aColon) : '';
        const bPrefix = bColon >= 0 ? b.name.slice(0, bColon) : '';
        const aLocal = aColon >= 0 ? a.name.slice(aColon + 1) : a.name;
        const bLocal = bColon >= 0 ? b.name.slice(bColon + 1) : b.name;
        const aUri = aPrefix ? (currentNs[aPrefix] || '') : '';
        const bUri = bPrefix ? (currentNs[bPrefix] || '') : '';
        if (aUri !== bUri) return aUri < bUri ? -1 : 1;
        return aLocal < bLocal ? -1 : aLocal > bLocal ? 1 : 0;
      });

      const renderedAttrStrings = [
        ...renderedNs.map((d) =>
          d.prefix === '' ? `xmlns="${escapeXmlAttr(d.uri)}"` : `xmlns:${d.prefix}="${escapeXmlAttr(d.uri)}"`
        ),
        ...regularAttrs.map((a) => `${a.name}="${escapeXmlAttr(a.value)}"`),
      ];

      const openTagStr =
        renderedAttrStrings.length > 0
          ? `<${tagName} ${renderedAttrStrings.join(' ')}>`
          : `<${tagName}>`;

      if (selfClosing) {
        out.push(`${openTagStr}</${tagName}>`);
      } else {
        nsStack.push(currentNs);
        out.push(openTagStr);
      }
      isRootElement = false;
      continue;
    }

    if (m[6] !== undefined) {
      if (!isRootElement) {
        out.push(escapeXmlText(unescapeXmlEntities(m[6])));
      }
    }
  }

  return out.join('');
}

function resolveCanonicalizationMode(algorithmUri) {
  switch (algorithmUri) {
    case C14N_WITH_COMMENTS:
      return { withComments: true, uri: C14N_WITH_COMMENTS };
    case C14N_NO_COMMENTS:
      return { withComments: false, uri: C14N_NO_COMMENTS };
    default:
      return assertNever(
        algorithmUri,
        'REFUSE_UNSUPPORTED_XMLDSIG_ALGORITHM',
        'Unsupported XMLDSIG CanonicalizationMethod'
      );
  }
}

function resolveDigestAlgorithm(algorithmUri) {
  switch (algorithmUri) {
    case DIGEST_SHA1:
    case 'sha1':
      return { nodeAlg: 'sha1', uri: DIGEST_SHA1 };
    case DIGEST_SHA256:
    case 'sha256':
      return { nodeAlg: 'sha256', uri: DIGEST_SHA256 };
    default:
      return assertNever(
        algorithmUri,
        'REFUSE_UNSUPPORTED_XMLDSIG_ALGORITHM',
        'Unsupported XMLDSIG DigestMethod'
      );
  }
}

function resolveSignatureAlgorithm(algorithmUri) {
  switch (algorithmUri) {
    case SIG_RSA_SHA1:
    case 'rsa-sha1':
      return { nodeAlg: 'RSA-SHA1', uri: SIG_RSA_SHA1 };
    case SIG_RSA_SHA256:
    case 'rsa-sha256':
      return { nodeAlg: 'RSA-SHA256', uri: SIG_RSA_SHA256 };
    default:
      return assertNever(
        algorithmUri,
        'REFUSE_UNSUPPORTED_XMLDSIG_ALGORITHM',
        'Unsupported XMLDSIG SignatureMethod'
      );
  }
}

// --- Pure ASN.1 DER X.509 v3 Certificate Generator for Deterministic Offline Tests ---

function derLength(len) {
  if (len < 128) return Buffer.from([len]);
  if (len < 256) return Buffer.from([0x81, len]);
  return Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
}

function derTlv(tag, content) {
  const buf = Buffer.isBuffer(content) ? content : Buffer.from(content);
  return Buffer.concat([Buffer.from([tag]), derLength(buf.length), buf]);
}

function derSequence(items) {
  return derTlv(0x30, Buffer.concat(items));
}

function derSet(items) {
  return derTlv(0x31, Buffer.concat(items));
}

function derOid(oidBytes) {
  return derTlv(0x06, Buffer.from(oidBytes));
}

function derPrintableString(str) {
  return derTlv(0x13, Buffer.from(str, 'ascii'));
}

function derUtf8String(str) {
  return derTlv(0x0c, Buffer.from(str, 'utf8'));
}

function derUtcTime(yyMMddHHmmssZ) {
  return derTlv(0x17, Buffer.from(yyMMddHHmmssZ, 'ascii'));
}

function derInteger(bytes) {
  let buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (buf[0] & 0x80) {
    buf = Buffer.concat([Buffer.from([0x00]), buf]);
  }
  return derTlv(0x02, buf);
}

function derBitString(bytes) {
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  return derTlv(0x03, Buffer.concat([Buffer.from([0x00]), buf]));
}

function encodeRdnSequence({ C = 'CH', O = 'Saxo Bank (Schweiz) AG', CN = 'Saxo Bank eCH-0196 Signing' }) {
  const rdns = [];
  if (C) {
    rdns.push(derSet([derSequence([derOid([0x55, 0x04, 0x06]), derPrintableString(C)])]));
  }
  if (O) {
    rdns.push(derSet([derSequence([derOid([0x55, 0x04, 0x0a]), derUtf8String(O)])]));
  }
  if (CN) {
    rdns.push(derSet([derSequence([derOid([0x55, 0x04, 0x03]), derUtf8String(CN)])]));
  }
  return derSequence(rdns);
}

/**
 * Generates an X.509 v3 certificate in PEM format using pure Node.js crypto (no openssl CLI dependency).
 */
export function generateTestBankCertificate(options = {}) {
  const institution = String(options.institution || 'SAXO').toUpperCase();
  const defaultOrg = institution === 'SWISSQUOTE' ? 'Swissquote Bank SA' : 'Saxo Bank (Schweiz) AG';
  const defaultCn =
    institution === 'SWISSQUOTE'
      ? 'Swissquote Bank SA eCH-0196 Tax Signing'
      : 'Saxo Bank (Schweiz) AG eCH-0196 Tax Signing';

  const country = options.country || 'CH';
  const org = options.organization || defaultOrg;
  const cn = options.commonName || defaultCn;
  const modulusLength = options.modulusLength || 2048;

  let publicKeyPem = options.publicKeyPem;
  let privateKeyPem = options.privateKeyPem;
  if (!publicKeyPem || !privateKeyPem) {
    const kp = generateKeyPairSync('rsa', {
      modulusLength,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    publicKeyPem = kp.publicKey;
    privateKeyPem = kp.privateKey;
  }

  const spkiDer = createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  const versionExplicit = derTlv(0xa0, derInteger(Buffer.from([0x02])));
  const serial = derInteger(Buffer.from([0x01, 0x20, 0x26, 0x11, 0x02]));
  // sha256WithRSAEncryption (1.2.840.113549.1.1.11)
  const sigAlgDer = derSequence([
    derOid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]),
    Buffer.from([0x05, 0x00]),
  ]);

  const issuerNameDer = encodeRdnSequence({
    C: options.issuerCountry || country,
    O: options.issuerOrganization || org,
    CN: options.issuerCommonName || cn,
  });
  const subjectNameDer = encodeRdnSequence({ C: country, O: org, CN: cn });

  const notBeforeUtc = options.notBeforeUtc || '240101000000Z';
  const notAfterUtc = options.notAfterUtc || '301231235959Z';
  const validityDer = derSequence([derUtcTime(notBeforeUtc), derUtcTime(notAfterUtc)]);

  const tbsDer = derSequence([
    versionExplicit,
    serial,
    sigAlgDer,
    issuerNameDer,
    validityDer,
    subjectNameDer,
    spkiDer,
  ]);

  const signerKey = options.issuerPrivateKeyPem || privateKeyPem;
  const signer = createSign('RSA-SHA256');
  signer.update(tbsDer);
  signer.end();
  const sigBytes = signer.sign(signerKey);

  const certDer = derSequence([tbsDer, sigAlgDer, derBitString(sigBytes)]);
  const b64Lines = certDer.toString('base64').match(/.{1,64}/g) || [];
  const certificatePem = `-----BEGIN CERTIFICATE-----\n${b64Lines.join('\n')}\n-----END CERTIFICATE-----`;
  const certificateBase64 = certDer.toString('base64');
  const subjectName = `CN=${cn},O=${org},C=${country}`;

  return {
    institution,
    subjectName,
    certificatePem,
    certificateBase64,
    publicKeyPem,
    privateKeyPem,
  };
}

/**
 * Deterministically signs an eCH-0196 v2.2.0 <taxStatement> XML payload using W3C XMLDSIG.
 */
export function signEch0196TaxStatementXml(params = {}) {
  const institution = String(params.institution || 'SAXO').toUpperCase();
  const instName =
    params.institutionName ||
    (institution === 'SWISSQUOTE' ? 'Swissquote Bank SA' : 'Saxo Bank (Schweiz) AG');
  const lei = params.lei || (institution === 'SWISSQUOTE' ? '549300650S8J72C89012' : '549300770D3G23B45678');
  const canton = params.canton || 'ZH';
  const taxPeriod = String(params.taxPeriod || '2025');
  const periodFrom = params.periodFrom || `${taxPeriod}-01-01`;
  const periodTo = params.periodTo || `${taxPeriod}-12-31`;
  const currency = params.currency !== undefined ? params.currency : 'CHF';
  const totalTaxValue = params.totalTaxValue || '250000.00';
  const totalGrossRevenueA = params.totalGrossRevenueA || '3500.00';
  const totalGrossRevenueB = params.totalGrossRevenueB || '1200.00';

  const canonSpec = resolveCanonicalizationMode(params.canonicalizationMethod || C14N_WITH_COMMENTS);
  const digestSpec = resolveDigestAlgorithm(params.digestMethod || DIGEST_SHA1);
  const sigSpec = resolveSignatureAlgorithm(params.signatureMethod || SIG_RSA_SHA1);

  let certBundle;
  if (params.privateKeyPem && params.certificatePem) {
    const cleanCertB64 = params.certificatePem
      .replace(/-----BEGIN CERTIFICATE-----/g, '')
      .replace(/-----END CERTIFICATE-----/g, '')
      .replace(/\s+/g, '');
    const x509 = new X509Certificate(params.certificatePem);
    certBundle = {
      privateKeyPem: params.privateKeyPem,
      certificatePem: params.certificatePem,
      certificateBase64: cleanCertB64,
      subjectName: params.subjectName || x509.subject.replace(/\n/g, ','),
    };
  } else {
    certBundle = generateTestBankCertificate({
      institution,
      organization: params.organization,
      commonName: params.commonName,
      issuerOrganization: params.issuerOrganization,
      issuerCommonName: params.issuerCommonName,
      modulusLength: params.modulusLength || 2048,
      privateKeyPem: params.privateKeyPem,
      publicKeyPem: params.publicKeyPem,
    });
  }

  const unsignedXml =
    params.unsignedXml ||
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<taxStatement xmlns="${ECH0196_NS}" id="CH-${taxPeriod}-${institution}-001" ` +
      `creationDate="2026-01-15T08:30:00" taxPeriod="${taxPeriod}" periodFrom="${periodFrom}" ` +
      `periodTo="${periodTo}"${currency ? ` currency="${currency}"` : ''} canton="${canton}" ` +
      `totalTaxValue="${totalTaxValue}" totalGrossRevenueA="${totalGrossRevenueA}" ` +
      `totalGrossRevenueB="${totalGrossRevenueB}" minorVersion="22">` +
      `<institution name="${instName}" lei="${lei}"></institution>` +
      `<listOfBankAccounts totalTaxValue="50000.00" totalGrossRevenueA="500.00" totalGrossRevenueB="0.00">` +
      `<bankAccount bankAccountCurrency="CHF" taxValue="50000.00" grossRevenueA="500.00" grossRevenueB="0.00"></bankAccount>` +
      `</listOfBankAccounts>` +
      `<listOfSecurities totalTaxValue="200000.00" totalGrossRevenueA="3000.00" totalGrossRevenueB="1200.00">` +
      `<depot><security positionId="1" country="CH" currency="CHF" quotationType="PIECE" securityCategory="SHARE" ` +
      `securityName="Synthetic Swiss Equity Index" taxValue="200000.00" grossRevenueA="3000.00" grossRevenueB="1200.00"></security></depot>` +
      `</listOfSecurities>` +
      `</taxStatement>`;

  const withoutXmlDecl = unsignedXml.replace(/^\uFEFF/, '').replace(/^<\?xml[^>]*\?>\s*/i, '');
  const canonicalTaxStatement = canonicalizeXmlC14n(withoutXmlDecl, {
    withComments: canonSpec.withComments,
  });
  const digestBase64 = createHash(digestSpec.nodeAlg)
    .update(canonicalTaxStatement, 'utf8')
    .digest('base64');

  const signedInfoXml =
    `<SignedInfo>` +
    `<CanonicalizationMethod Algorithm="${canonSpec.uri}"></CanonicalizationMethod>` +
    `<SignatureMethod Algorithm="${sigSpec.uri}"></SignatureMethod>` +
    `<Reference URI="">` +
    `<Transforms>` +
    `<Transform Algorithm="${TRANSFORM_ENVELOPED}"></Transform>` +
    `<Transform Algorithm="${canonSpec.uri}"></Transform>` +
    `</Transforms>` +
    `<DigestMethod Algorithm="${digestSpec.uri}"></DigestMethod>` +
    `<DigestValue>${digestBase64}</DigestValue>` +
    `</Reference>` +
    `</SignedInfo>`;

  const canonicalSignedInfo = canonicalizeXmlC14n(signedInfoXml, {
    withComments: canonSpec.withComments,
    inheritedNamespaces: { '': XMLDSIG_NS },
  });

  const signer = createSign(sigSpec.nodeAlg);
  signer.update(canonicalSignedInfo, 'utf8');
  signer.end();
  const signatureValueBase64 = signer.sign(certBundle.privateKeyPem, 'base64');

  const keyInfoContent =
    params.includeX509Data === false
      ? `<KeyValue><RSAKeyValue><Modulus>AQAB</Modulus><Exponent>AQAB</Exponent></RSAKeyValue></KeyValue>`
      : `<X509Data>` +
        `<X509SubjectName>${escapeXmlText(certBundle.subjectName)}</X509SubjectName>` +
        `<X509Certificate>${certBundle.certificateBase64}</X509Certificate>` +
        `</X509Data>`;

  const signatureBlock =
    `<Signature xmlns="${XMLDSIG_NS}">` +
    `${signedInfoXml}` +
    `<SignatureValue>${signatureValueBase64}</SignatureValue>` +
    `<KeyInfo>${keyInfoContent}</KeyInfo>` +
    `</Signature>`;

  const closeTagIdx = unsignedXml.lastIndexOf('</taxStatement>');
  if (closeTagIdx < 0) {
    throw new Ech0196Error('REFUSE_INVALID_ECH0196_XML', 'Missing closing </taxStatement> tag');
  }
  return (
    unsignedXml.slice(0, closeTagIdx) +
    signatureBlock +
    unsignedXml.slice(closeTagIdx)
  );
}

function parseAttributesMap(attrText) {
  const map = {};
  for (const { name, value } of parseRawAttributes(attrText)) {
    map[name] = value;
  }
  return map;
}

/**
 * Verifies an eCH-0196 v2.2.0 <taxStatement> XML document and its enveloped W3C XMLDSIG signature.
 */
export function verifyEch0196StatementXml(xmlText, options = {}) {
  const rawString =
    Buffer.isBuffer(xmlText) || xmlText instanceof Uint8Array
      ? Buffer.from(xmlText).toString('utf8')
      : String(xmlText ?? '');

  const payloadSha256 = createHash('sha256').update(rawString, 'utf8').digest('hex');
  const normalized = rawString.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n').trim();

  const rootMatch = /<(?:\w+:)?taxStatement\b([^>]*)>([\s\S]*?)<\/(?:\w+:)?taxStatement\s*>/i.exec(normalized);
  if (!rootMatch) {
    throw new Ech0196Error(
      'REFUSE_INVALID_ECH0196_XML',
      'Root element is not an eCH-0196 <taxStatement> document'
    );
  }

  const rootAttrs = parseAttributesMap(rootMatch[1]);
  const innerXml = rootMatch[2];

  const sigMatch = /<(?:\w+:)?Signature\b([^>]*)>([\s\S]*?)<\/(?:\w+:)?Signature\s*>/i.exec(innerXml);
  if (!sigMatch) {
    throw new Ech0196Error(
      'REFUSE_UNSIGNED_ECH0196_XML',
      'eCH-0196 <taxStatement> lacks an enveloped W3C XMLDSIG <Signature> element'
    );
  }

  // Enforce CHF reporting currency requirement on Swissquote/SAXO eCH-0196 statements
  const stmtCurrency = rootAttrs.currency || rootAttrs.taxCurrency || rootAttrs.reportingCurrency;
  if (stmtCurrency !== undefined && stmtCurrency !== 'CHF') {
    throw new Ech0196Error(
      'REFUSE_NON_CHF_ECH0196_CURRENCY',
      `eCH-0196 taxStatement currency must be CHF, found "${stmtCurrency}"`
    );
  }

  const sigFullElement = sigMatch[0];
  const sigAttrs = parseAttributesMap(sigMatch[1]);
  const sigInner = sigMatch[2];

  // Enforce eCH-0196 v2.2.0 Technische Wegleitung: <KeyInfo> MUST include <X509Data> with both <X509SubjectName> and <X509Certificate>
  const keyInfoMatch = /<(?:\w+:)?KeyInfo\b[^>]*>([\s\S]*?)<\/(?:\w+:)?KeyInfo\s*>/i.exec(sigInner);
  if (!keyInfoMatch) {
    throw new Ech0196Error('REFUSE_MISSING_X509_DATA', 'XMLDSIG <Signature> lacks <KeyInfo>');
  }
  const x509DataMatch = /<(?:\w+:)?X509Data\b[^>]*>([\s\S]*?)<\/(?:\w+:)?X509Data\s*>/i.exec(keyInfoMatch[1]);
  if (!x509DataMatch) {
    throw new Ech0196Error(
      'REFUSE_MISSING_X509_DATA',
      'eCH-0196 v2.2.0 requires <X509Data> inside <KeyInfo>; <KeyValue> alone is prohibited'
    );
  }
  const subjectNameMatch = /<(?:\w+:)?X509SubjectName\b[^>]*>([\s\S]*?)<\/(?:\w+:)?X509SubjectName\s*>/i.exec(
    x509DataMatch[1]
  );
  const certMatch = /<(?:\w+:)?X509Certificate\b[^>]*>([\s\S]*?)<\/(?:\w+:)?X509Certificate\s*>/i.exec(
    x509DataMatch[1]
  );
  const x509SubjectName = subjectNameMatch ? unescapeXmlEntities(subjectNameMatch[1]).trim() : '';
  const certBase64Clean = certMatch ? certMatch[1].replace(/\s+/g, '') : '';
  if (!x509SubjectName || !certBase64Clean) {
    throw new Ech0196Error(
      'REFUSE_MISSING_X509_DATA',
      'eCH-0196 <X509Data> must contain both non-empty <X509SubjectName> and <X509Certificate>'
    );
  }

  const certLines = certBase64Clean.match(/.{1,64}/g) || [];
  const certPem = `-----BEGIN CERTIFICATE-----\n${certLines.join('\n')}\n-----END CERTIFICATE-----`;
  let x509;
  try {
    x509 = new X509Certificate(certPem);
  } catch (err) {
    throw new Ech0196Error('REFUSE_MISSING_X509_DATA', `Invalid X.509 certificate in <X509Certificate>: ${err.message}`);
  }

  const pubKey = x509.publicKey;
  const modLen = pubKey.asymmetricKeyDetails?.modulusLength ?? 0;
  if (pubKey.asymmetricKeyType !== 'rsa' || modLen < 2048) {
    throw new Ech0196Error(
      'REFUSE_WEAK_RSA_KEY',
      `eCH-0196 v2.2.0 mandates RSA >= 2048 bits (got ${pubKey.asymmetricKeyType} ${modLen} bits)`
    );
  }

  if (options.checkDate) {
    const checkMs = new Date(options.checkDate).getTime();
    const fromMs = Date.parse(x509.validFrom);
    const toMs = Date.parse(x509.validTo);
    if (!Number.isFinite(checkMs) || checkMs < fromMs || checkMs > toMs) {
      throw new Ech0196Error(
        'REFUSE_CERT_EXPIRED_OR_NOT_YET_VALID',
        `X.509 certificate validity [${x509.validFrom} .. ${x509.validTo}] does not cover ${options.checkDate}`
      );
    }
  }

  // Verify X.509 certificate trust chain against caller-supplied trust anchors (no implicit DN regex trust)
  if (!Array.isArray(options.trustedCertsPem) || options.trustedCertsPem.length === 0) {
    throw new Ech0196Error(
      'REFUSE_UNTRUSTED_CERT_ISSUER',
      'Offline eCH-0196 verification requires at least one pinned CA or bank certificate in trustedCertsPem (--trusted-cert)'
    );
  }

  let matchedTrustedCert = false;
  for (const trustedPem of options.trustedCertsPem) {
    let trustedX509;
    try {
      trustedX509 = new X509Certificate(trustedPem);
    } catch {
      continue;
    }
    if (
      trustedX509.fingerprint256 === x509.fingerprint256 ||
      (x509.issuer === trustedX509.subject && x509.verify(trustedX509.publicKey))
    ) {
      matchedTrustedCert = true;
      break;
    }
  }
  if (!matchedTrustedCert) {
    throw new Ech0196Error(
      'REFUSE_UNTRUSTED_CERT_ISSUER',
      `Certificate "${x509.subject}" is not anchored in trustedCertsPem`
    );
  }

  if (Array.isArray(options.trustedSubjectPatterns) && options.trustedSubjectPatterns.length > 0) {
    const matchesPattern = options.trustedSubjectPatterns.some((pat) =>
      pat instanceof RegExp
        ? pat.test(x509.subject) || pat.test(x509SubjectName)
        : x509.subject.includes(String(pat)) || x509SubjectName.includes(String(pat))
    );
    if (!matchesPattern) {
      throw new Ech0196Error(
        'REFUSE_UNTRUSTED_CERT_ISSUER',
        `Certificate subject "${x509.subject}" does not match trustedSubjectPatterns`
      );
    }
  } else if (!DEFAULT_TRUSTED_SUBJECT_RE.test(x509.subject) && !DEFAULT_TRUSTED_SUBJECT_RE.test(x509.issuer)) {
    throw new Ech0196Error(
      'REFUSE_UNTRUSTED_CERT_ISSUER',
      `Certificate subject "${x509.subject}" / issuer "${x509.issuer}" is not a recognized Swiss eCH-0196 institution or CA`
    );
  }

  // Extract and validate <SignedInfo>
  const signedInfoMatch = /<(?:\w+:)?SignedInfo\b[^>]*>[\s\S]*?<\/(?:\w+:)?SignedInfo\s*>/i.exec(sigInner);
  if (!signedInfoMatch) {
    throw new Ech0196Error('REFUSE_INVALID_ECH0196_XML', 'XMLDSIG <Signature> lacks <SignedInfo>');
  }
  const signedInfoXml = signedInfoMatch[0];

  const canonMethodMatch = /<(?:\w+:)?CanonicalizationMethod\b[^>]*Algorithm\s*=\s*["']([^"']+)["']/i.exec(
    signedInfoXml
  );
  const sigMethodMatch = /<(?:\w+:)?SignatureMethod\b[^>]*Algorithm\s*=\s*["']([^"']+)["']/i.exec(
    signedInfoXml
  );
  const refUriMatch = /<(?:\w+:)?Reference\b[^>]*URI\s*=\s*["']([^"']*)["']/i.exec(signedInfoXml);
  const digestMethodMatch = /<(?:\w+:)?DigestMethod\b[^>]*Algorithm\s*=\s*["']([^"']+)["']/i.exec(
    signedInfoXml
  );
  const digestValueMatch = /<(?:\w+:)?DigestValue\b[^>]*>([\s\S]*?)<\/(?:\w+:)?DigestValue\s*>/i.exec(
    signedInfoXml
  );
  const sigValueMatch = /<(?:\w+:)?SignatureValue\b[^>]*>([\s\S]*?)<\/(?:\w+:)?SignatureValue\s*>/i.exec(
    sigInner
  );

  if (!canonMethodMatch || !sigMethodMatch || !digestMethodMatch || !digestValueMatch || !sigValueMatch) {
    throw new Ech0196Error('REFUSE_INVALID_ECH0196_XML', 'Incomplete XMLDSIG <SignedInfo> or <SignatureValue>');
  }
  if (refUriMatch && refUriMatch[1] !== '') {
    throw new Ech0196Error(
      'REFUSE_UNSUPPORTED_XMLDSIG_ALGORITHM',
      `eCH-0196 requires whole-document enveloped Reference URI, got non-empty URI (${refUriMatch[1]})`
    );
  }

  const transformMatches = [
    ...signedInfoXml.matchAll(/<(?:\w+:)?Transform\b[^>]*Algorithm\s*=\s*["']([^"']+)["']/gi),
  ].map((m) => m[1]);
  if (!transformMatches.includes(TRANSFORM_ENVELOPED)) {
    throw new Ech0196Error(
      'REFUSE_UNSUPPORTED_XMLDSIG_ALGORITHM',
      'Missing required enveloped-signature transform in <Reference>'
    );
  }

  const canonSpec = resolveCanonicalizationMode(canonMethodMatch[1]);
  const digestSpec = resolveDigestAlgorithm(digestMethodMatch[1]);
  const sigSpec = resolveSignatureAlgorithm(sigMethodMatch[1]);

  // Step 1: Enveloped signature transform (remove <Signature> element from <taxStatement>) and verify <DigestValue>
  const taxStatementElementOnly = rootMatch[0];
  const withoutSignature = taxStatementElementOnly.replace(sigFullElement, '');
  const canonicalTaxStatement = canonicalizeXmlC14n(withoutSignature, {
    withComments: canonSpec.withComments,
  });

  const computedDigestB64 = createHash(digestSpec.nodeAlg)
    .update(canonicalTaxStatement, 'utf8')
    .digest('base64');
  const expectedDigestB64 = digestValueMatch[1].replace(/\s+/g, '');

  if (computedDigestB64 !== expectedDigestB64) {
    throw new Ech0196Error(
      'REFUSE_XMLDSIG_DIGEST_MISMATCH',
      `Canonicalized <taxStatement> ${digestSpec.nodeAlg} digest (${computedDigestB64}) does not match <DigestValue> (${expectedDigestB64})`
    );
  }

  // Step 2: Canonicalize <SignedInfo> with inherited xmlns from <Signature> and verify <SignatureValue>
  const sigNs = sigAttrs.xmlns || XMLDSIG_NS;
  const canonicalSignedInfo = canonicalizeXmlC14n(signedInfoXml, {
    withComments: canonSpec.withComments,
    inheritedNamespaces: { '': sigNs },
  });

  const sigBytes = Buffer.from(sigValueMatch[1].replace(/\s+/g, ''), 'base64');
  const verifier = createVerify(sigSpec.nodeAlg);
  verifier.update(canonicalSignedInfo, 'utf8');
  verifier.end();

  if (!verifier.verify(pubKey, sigBytes)) {
    throw new Ech0196Error(
      'REFUSE_XMLDSIG_SIGNATURE_INVALID',
      `RSA signature verification over canonicalized <SignedInfo> failed (${sigSpec.uri})`
    );
  }

  // Extract zero-disclosure summary metadata and enforce institution binding across signed XML and X.509 subject
  const instMatch = /<(?:\w+:)?institution\b([^>]*)\/?>/i.exec(withoutSignature);
  const instAttrs = instMatch ? parseAttributesMap(instMatch[1]) : {};
  const xmlInstText = String(instAttrs.name || '');
  const certSubjText = String(x509.subject || '');

  const detectSingleInstitution = (sourceText, label) => {
    const hasSq = /swissquote/i.test(sourceText);
    const hasSaxo = /saxo/i.test(sourceText);
    if (hasSq && hasSaxo) {
      throw new Ech0196Error(
        'REFUSE_INSTITUTION_MISMATCH',
        `Ambiguous institution in ${label}: matches both SWISSQUOTE and SAXO`
      );
    }
    return hasSq ? 'SWISSQUOTE' : hasSaxo ? 'SAXO' : null;
  };

  const xmlInstitution = detectSingleInstitution(xmlInstText, '<institution>');
  const certInstitution = detectSingleInstitution(certSubjText, 'X.509 certificate subject');
  const unsignedKeyInfoInstitution = detectSingleInstitution(x509SubjectName, '<X509SubjectName>');

  if (xmlInstitution && certInstitution && xmlInstitution !== certInstitution) {
    throw new Ech0196Error(
      'REFUSE_INSTITUTION_MISMATCH',
      `Signed <institution> ("${xmlInstitution}") does not match X.509 certificate subject ("${certInstitution}")`
    );
  }
  const detectedFromStatement = certInstitution || xmlInstitution;
  if (
    unsignedKeyInfoInstitution &&
    detectedFromStatement &&
    unsignedKeyInfoInstitution !== detectedFromStatement
  ) {
    throw new Ech0196Error(
      'REFUSE_INSTITUTION_MISMATCH',
      `<X509SubjectName> ("${unsignedKeyInfoInstitution}") conflicts with signed certificate/statement institution ("${detectedFromStatement}")`
    );
  }

  const requestedInstitution = options.institution
    ? String(options.institution).toUpperCase().trim()
    : null;
  if (
    requestedInstitution &&
    detectedFromStatement &&
    requestedInstitution !== detectedFromStatement
  ) {
    throw new Ech0196Error(
      'REFUSE_INSTITUTION_MISMATCH',
      `Requested institution "${requestedInstitution}" does not match statement/certificate institution "${detectedFromStatement}"`
    );
  }
  const detectedInstitution = detectedFromStatement || requestedInstitution || 'SAXO';

  const totalTaxValueScaled = parseScaledChfDecimal(rootAttrs.totalTaxValue || '0', 'totalTaxValue');
  const totalGrossRevenueAScaled = parseScaledChfDecimal(
    rootAttrs.totalGrossRevenueA || '0',
    'totalGrossRevenueA'
  );
  const totalGrossRevenueBScaled = parseScaledChfDecimal(
    rootAttrs.totalGrossRevenueB || '0',
    'totalGrossRevenueB'
  );
  const canonicalStatementSha256 = createHash('sha256')
    .update(canonicalTaxStatement, 'utf8')
    .digest('hex');

  return {
    ok: true,
    status: 'ECH0196_VERIFIED',
    institution: detectedInstitution,
    canton: rootAttrs.canton || null,
    taxPeriod: rootAttrs.taxPeriod || null,
    periodFrom: rootAttrs.periodFrom || null,
    periodTo: rootAttrs.periodTo || null,
    currency: 'CHF',
    totalTaxValueScaled,
    totalGrossRevenueAScaled,
    totalGrossRevenueBScaled,
    payloadSha256,
    canonicalStatementSha256,
    certFingerprint256: x509.fingerprint256,
    certSubject: x509.subject.replace(/\n/g, ', '),
    x509SubjectName,
    signatureMethod: sigSpec.uri,
    digestMethod: digestSpec.uri,
    canonicalizationMethod: canonSpec.uri,
  };
}

export function runCli(args) {
  const help =
    'Usage: node scripts/verify-ech0196-statement.mjs STATEMENT.xml [--trusted-cert FILE] [--institution SAXO|SWISSQUOTE]\n' +
    'Offline Swiss eCH-0196 v2.2.0 eSteuerauszug W3C XMLDSIG (rsa-sha1 / rsa-sha256) statement verifier.\n';
  if (args.length === 1 && args[0] === '--help') {
    return { exitCode: 0, output: help };
  }
  try {
    let xmlFile = null;
    let trustedCertFile = null;
    let institution = null;
    for (let i = 0; i < args.length; i++) {
      if (args[i] === '--trusted-cert' && i + 1 < args.length) {
        trustedCertFile = args[++i];
      } else if (args[i] === '--institution' && i + 1 < args.length) {
        institution = args[++i];
      } else if (!args[i].startsWith('--') && !xmlFile) {
        xmlFile = args[i];
      } else {
        return { exitCode: 3, output: JSON.stringify({ status: 'INVALID_INPUT' }) + '\n' };
      }
    }
    if (!xmlFile) {
      return { exitCode: 3, output: JSON.stringify({ status: 'INVALID_INPUT' }) + '\n' };
    }
    const xmlText = readFileSync(xmlFile, 'utf8');
    const trustedCertsPem = trustedCertFile ? [readFileSync(trustedCertFile, 'utf8')] : undefined;
    const res = verifyEch0196StatementXml(xmlText, { trustedCertsPem, institution });
    return {
      exitCode: 0,
      output:
        JSON.stringify(
          {
            status: res.status,
            institution: res.institution,
            canton: res.canton,
            taxPeriod: res.taxPeriod,
            periodFrom: res.periodFrom,
            periodTo: res.periodTo,
            currency: res.currency,
            totalTaxValueScaled: res.totalTaxValueScaled.toString(),
            totalGrossRevenueAScaled: res.totalGrossRevenueAScaled.toString(),
            totalGrossRevenueBScaled: res.totalGrossRevenueBScaled.toString(),
            payloadSha256: res.payloadSha256,
            canonicalStatementSha256: res.canonicalStatementSha256,
            certFingerprint256: res.certFingerprint256,
            certSubject: res.certSubject,
          },
          null,
          2
        ) + '\n',
    };
  } catch (err) {
    return {
      exitCode: 1,
      output:
        JSON.stringify({
          status: 'REJECTED',
          code: err.code || 'ECH0196_INVALID',
          message: err.message,
        }) + '\n',
    };
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const r = runCli(process.argv.slice(2));
  process.stdout.write(r.output);
  process.exitCode = r.exitCode;
}
