#!/usr/bin/env node
// scripts/verify-broker-source.mjs: Direct Multi-Broker Zero-Contamination Source Verifier (9 Audited Institutions).
import { createHash, createPublicKey, createSign, createVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import {
  extractMimeAttachments,
  parseDkimTags,
  parseEmlStructure,
  verifyDkimStatementEml,
} from './verify-dkim-statement.mjs';
import { verifyEch0196StatementXml } from './verify-ech0196-statement.mjs';
import {
  canonicalizeFlexCsv,
  canonicalizeFlexXml,
  validateFixtureF05,
} from './witness-fetch.mjs';

export const CONSUMER_AND_RELAY_DOMAINS = new Set([
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

function extractEmailAddressAndDomain(rawHeaderValue) {
  const text = String(rawHeaderValue || '').trim();
  const angleMatch = /<([^<>@\s]+@[^<>@\s]+)>/.exec(text);
  const directMatch = /([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})/.exec(text);
  const address = (angleMatch ? angleMatch[1] : directMatch ? directMatch[1] : '').toLowerCase();
  const atIdx = address.lastIndexOf('@');
  const domain = atIdx >= 0 ? address.slice(atIdx + 1) : '';
  return { address, domain };
}

/**
 * Inspects a PDF byte stream for ISO 32000-1 / PAdES cryptographic signature dictionaries
 * (/ByteRange + /Contents with detached CMS/CAdES SubFilter) vs. visual-only graphic stamp traps.
 */
export function inspectPdfCryptographicSignature(pdfBytes) {
  const buf =
    Buffer.isBuffer(pdfBytes)
      ? pdfBytes
      : pdfBytes instanceof Uint8Array
        ? Buffer.from(pdfBytes.buffer, pdfBytes.byteOffset, pdfBytes.byteLength)
        : Buffer.from(String(pdfBytes ?? ''), 'latin1');

  const rawLatin1 = buf.toString('latin1');
  const isPdf = rawLatin1.startsWith('%PDF-');
  if (!isPdf) {
    return {
      isPdf: false,
      hasCryptographicSignature: false,
      hasVisualStampOverlay: false,
      subFilter: null,
      byteRange: null,
      byteRangeCoversEntireFile: false,
      reason: 'NOT_A_PDF',
    };
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
    return {
      isPdf: true,
      hasCryptographicSignature: false,
      hasVisualStampOverlay,
      subFilter: subFilterMatch ? subFilterMatch[1] : null,
      byteRange: byteRangeMatch ? byteRangeMatch.slice(1, 5).map(Number) : null,
      byteRangeCoversEntireFile: false,
      reason: hasVisualStampOverlay ? 'VISUAL_STAMP_NOT_CRYPTOGRAPHIC' : 'UNSIGNED_PDF',
    };
  }

  const [o1, l1, o2, l2] = byteRangeMatch.slice(1, 5).map(Number);
  const contentsHex = contentsMatch[1].replace(/\s+/g, '');
  const byteRangeCoversEntireFile =
    o1 === 0 && l1 > 0 && o2 > l1 && o2 + l2 === buf.length && contentsHex.length >= 128 && !/^0+$/.test(contentsHex);

  return {
    isPdf: true,
    hasCryptographicSignature: byteRangeCoversEntireFile,
    hasVisualStampOverlay,
    subFilter: subFilterMatch[1],
    byteRange: [o1, l1, o2, l2],
    byteRangeCoversEntireFile,
    reason: byteRangeCoversEntireFile ? 'VALID_PADES_STRUCTURE' : 'BYTE_RANGE_INCOMPLETE',
  };
}

/**
 * Parses and validates an IBKR Flex v3 XML or CSV statement payload, enforcing F05 Capital Flow Conservation.
 */
export function parseAndValidateIbkrFlex(rawText, options = {}) {
  const text =
    Buffer.isBuffer(rawText) || rawText instanceof Uint8Array
      ? Buffer.from(rawText).toString('utf8')
      : String(rawText ?? '');
  const trimmed = text.replace(/^\uFEFF/, '').trim();

  if (trimmed.startsWith('<')) {
    const canonical = canonicalizeFlexXml(trimmed, options);
    const f05 = validateFixtureF05(
      canonical.changeInNav,
      canonical.cashReportRows,
      canonical.corporateActionRows,
      {
        cashTransactionRows: canonical.cashTransactionRows,
        dividendAccrualRows: canonical.dividendAccrualRows,
        accountInfo: canonical.accountInfo,
      }
    );
    return {
      format: 'XML',
      canonicalSha256: canonical.canonicalSha256,
      sectionsPresent: canonical.sectionsPresent,
      f05,
      flags: [...new Set([...canonical.flags, ...f05.flags])],
    };
  }

  const canonical = canonicalizeFlexCsv(trimmed, options);
  return {
    format: 'CSV',
    canonicalSha256: canonical.canonicalSha256,
    sectionsPresent: canonical.sectionsPresent,
    f05: null,
    flags: canonical.flags,
  };
}

/**
 * Verifies a Wise Webhook HTTP POST payload using its X-Signature-SHA256 RSA-SHA256 signature.
 */
export function verifyWiseWebhookSignature(rawJsonBody, signatureBase64, publicKeyPem) {
  if (!rawJsonBody || !signatureBase64 || !publicKeyPem) {
    throw new BrokerSourceError(
      'REFUSE_WISE_WEBHOOK_SIGNATURE_INVALID',
      'Wise webhook verification requires rawJsonBody, signatureBase64, and publicKeyPem'
    );
  }
  const rawBytes =
    Buffer.isBuffer(rawJsonBody)
      ? rawJsonBody
      : rawJsonBody instanceof Uint8Array
        ? Buffer.from(rawJsonBody.buffer, rawJsonBody.byteOffset, rawJsonBody.byteLength)
        : Buffer.from(String(rawJsonBody), 'utf8');

  let pubKeyObj;
  try {
    pubKeyObj = createPublicKey(publicKeyPem);
  } catch (err) {
    throw new BrokerSourceError('REFUSE_WISE_WEBHOOK_SIGNATURE_INVALID', `Invalid Wise public key: ${err.message}`);
  }

  const modLen = pubKeyObj.asymmetricKeyDetails?.modulusLength ?? 0;
  if (pubKeyObj.asymmetricKeyType !== 'rsa' || modLen < 2048) {
    throw new BrokerSourceError('REFUSE_WEAK_RSA_KEY', `Wise webhook RSA key modulus ${modLen} < 2048 bits`);
  }

  const sigBytes = Buffer.from(String(signatureBase64).replace(/\s+/g, ''), 'base64');
  const verifier = createVerify('RSA-SHA256');
  verifier.update(rawBytes);
  verifier.end();

  if (!verifier.verify(pubKeyObj, sigBytes)) {
    throw new BrokerSourceError(
      'REFUSE_WISE_WEBHOOK_SIGNATURE_INVALID',
      'Wise X-Signature-SHA256 RSA-SHA256 verification failed over raw JSON body'
    );
  }

  let parsed;
  try {
    parsed = JSON.parse(rawBytes.toString('utf8'));
  } catch {
    throw new BrokerSourceError('REFUSE_WISE_WEBHOOK_MALFORMED_JSON', 'Wise webhook payload is not valid JSON');
  }

  const payloadSha256 = createHash('sha256').update(rawBytes).digest('hex');

  return {
    ok: true,
    status: 'BROKER_PROVENANCE_VERIFIED',
    institution: 'WISE',
    artifactType: 'WISE_WEBHOOK_RSA_SHA256',
    scope: 'SINGLE_TRANSFER_WEBHOOK',
    qualification: 'SINGLE_TRANSFER_ONLY_NO_FULL_NAV',
    payloadSha256,
    eventType: parsed?.event_type || null,
    transferId: parsed?.data?.resource?.id !== undefined ? String(parsed.data.resource.id) : null,
    currentState: parsed?.data?.current_state || null,
  };
}

/**
 * Deterministic test helper to sign a raw JSON Wise webhook payload with RSA-SHA256.
 */
export function signWiseWebhookPayload(rawJsonBody, privateKeyPem) {
  const rawBytes =
    Buffer.isBuffer(rawJsonBody)
      ? rawJsonBody
      : rawJsonBody instanceof Uint8Array
        ? Buffer.from(rawJsonBody.buffer, rawJsonBody.byteOffset, rawJsonBody.byteLength)
        : Buffer.from(String(rawJsonBody), 'utf8');
  const signer = createSign('RSA-SHA256');
  signer.update(rawBytes);
  signer.end();
  return signer.sign(privateKeyPem, 'base64');
}

function detectArtifactType(input, payloadBytes) {
  const explicit = String(input?.artifactType || '').toUpperCase().trim();
  if (explicit && explicit !== 'AUTO') return explicit;
  if (input?.signatureBase64 || input?.headers?.['x-signature-sha256'] || input?.headers?.['X-Signature-SHA256']) {
    return 'WISE_WEBHOOK';
  }
  if (input?.pdfBytes !== undefined) return 'PDF';
  if (input?.xmlText !== undefined) return 'ECH0196_XML';
  if (input?.rawEml !== undefined) return 'EML';

  const head = payloadBytes.subarray(0, 512).toString('utf8').replace(/^\uFEFF/, '').trimStart();
  if (head.startsWith('%PDF-')) return 'PDF';
  if (head.startsWith('<?xml') || /^<(?:\w+:)?taxStatement\b/i.test(head)) return 'ECH0196_XML';
  if (/^(?:DKIM-Signature|From|Return-Path|Received|MIME-Version)\s*:/im.test(head)) return 'EML';
  return 'UNKNOWN';
}

function isLoginLinkOnlyNotification(subject, bodyText, attachments) {
  if (attachments && attachments.length > 0) return false;
  const combined = `${subject}\n${bodyText}`;
  const hasPortalLinkIndicator =
    /view your (?:statement|trade confirmation|document)s? online|log\s*in to (?:your account|fidelity|netbenefits|schwab|vanguard)|edelivery notification|new (?:statement|document) available|download your statement|\.zip[\s\S]{0,80}download link|7-day download link/i.test(
      combined
    );
  const hasTradeExecutionFields =
    /\b(?:BOUGHT|SOLD|BUY|SELL|Execution|Contract Note)\b/i.test(combined) &&
    /\b(?:Quantity|Qty|Shares)\b\s*[:=]?\s*\d+/i.test(combined) &&
    /\b(?:Price)\b\s*[:=]?\s*[$€£¥₣]?\s*\d+/i.test(combined);
  const hasTransferReceiptFields =
    /\b(?:transfer|paid out|received your money|sent|payment)\b/i.test(combined) &&
    /\b\d+(?:\.\d{2})?\s*(?:USD|EUR|GBP|CHF|AUD|CAD|SGD|JPY)\b/i.test(combined);

  if (hasPortalLinkIndicator && !hasTradeExecutionFields && !hasTransferReceiptFields) {
    return true;
  }
  return !hasTradeExecutionFields && !hasTransferReceiptFields;
}

function extractTradeConfirmationSummary(bodyText) {
  const actionMatch = /\b(?:Action\s*:\s*)?(BOUGHT|SOLD|BUY|SELL)\b/i.exec(bodyText);
  const qtyMatch = /\b(?:Quantity|Qty|Shares)\s*[:=]?\s*([0-9,]+(?:\.[0-9]+)?)/i.exec(bodyText);
  const priceMatch = /\bPrice\s*[:=]?\s*[$€£¥]?\s*([0-9,]+(?:\.[0-9]+)?)/i.exec(bodyText);
  const netMatch = /\b(?:Net Amount|Total|Principal)\s*[:=]?\s*[$€£¥]?\s*([0-9,]+(?:\.[0-9]+)?)/i.exec(bodyText);
  return {
    action: actionMatch ? actionMatch[1].toUpperCase() : null,
    quantity: qtyMatch ? qtyMatch[1].replace(/,/g, '') : null,
    price: priceMatch ? priceMatch[1].replace(/,/g, '') : null,
    netAmount: netMatch ? netMatch[1].replace(/,/g, '') : null,
  };
}

function extractTransferReceiptSummary(bodyText) {
  const amtMatch = /\b(\d+(?:\.\d{2})?)\s*(USD|EUR|GBP|CHF|AUD|CAD|SGD|JPY)\b/i.exec(bodyText);
  const idMatch = /\b(?:Transfer|Reference|Transaction)\s*(?:ID|#)?\s*[:=]?\s*([A-Za-z0-9_-]{4,32})/i.exec(bodyText);
  return {
    amount: amtMatch ? amtMatch[1] : null,
    currency: amtMatch ? amtMatch[2].toUpperCase() : null,
    transferReference: idMatch ? idMatch[1] : null,
  };
}

/**
 * Verifies a direct broker artifact across all 9 audited institutions, enforcing zero-contamination refusal gates.
 */
export function verifyDirectBrokerArtifact(input, options = {}) {
  const rawInstitution = String(input?.institution || options?.institution || '')
    .toUpperCase()
    .trim();

  let brokerConfig;
  switch (rawInstitution) {
    case 'IBKR':
      brokerConfig = BROKER_PROVENANCE_MATRIX.IBKR;
      break;
    case 'SAXO':
      brokerConfig = BROKER_PROVENANCE_MATRIX.SAXO;
      break;
    case 'SWISSQUOTE':
      brokerConfig = BROKER_PROVENANCE_MATRIX.SWISSQUOTE;
      break;
    case 'SCHWAB':
      brokerConfig = BROKER_PROVENANCE_MATRIX.SCHWAB;
      break;
    case 'VANGUARD':
      brokerConfig = BROKER_PROVENANCE_MATRIX.VANGUARD;
      break;
    case 'WISE':
      brokerConfig = BROKER_PROVENANCE_MATRIX.WISE;
      break;
    case 'REVOLUT':
      brokerConfig = BROKER_PROVENANCE_MATRIX.REVOLUT;
      break;
    case 'FIDELITY':
      brokerConfig = BROKER_PROVENANCE_MATRIX.FIDELITY;
      break;
    case 'TRADESTATION':
      brokerConfig = BROKER_PROVENANCE_MATRIX.TRADESTATION;
      break;
    default:
      return assertNeverInstitution(rawInstitution);
  }

  const rawPayload =
    input?.content ??
    input?.rawEml ??
    input?.xmlText ??
    input?.pdfBytes ??
    input?.rawJsonBody ??
    (typeof input === 'string' || Buffer.isBuffer(input) || input instanceof Uint8Array ? input : '');

  const payloadBytes =
    Buffer.isBuffer(rawPayload)
      ? rawPayload
      : rawPayload instanceof Uint8Array
        ? Buffer.from(rawPayload.buffer, rawPayload.byteOffset, rawPayload.byteLength)
        : Buffer.from(String(rawPayload ?? ''), 'utf8');

  const artifactType = detectArtifactType(input, payloadBytes);

  // 1. Handle Wise Signed Webhook
  if (artifactType === 'WISE_WEBHOOK') {
    if (brokerConfig.institution !== 'WISE') {
      throw new BrokerSourceError(
        'REFUSE_UNSUPPORTED_ARTIFACT_FOR_INSTITUTION',
        `X-Signature-SHA256 webhook verification is only supported for WISE, not ${brokerConfig.institution}`
      );
    }
    const sigB64 =
      input?.signatureBase64 ??
      input?.headers?.['x-signature-sha256'] ??
      input?.headers?.['X-Signature-SHA256'] ??
      options?.signatureBase64;
    const pubKey = options?.publicKeyPem ?? input?.publicKeyPem;
    return verifyWiseWebhookSignature(payloadBytes, sigB64, pubKey);
  }

  // 2. Handle PDF Artifacts (Visual Stamp Trap vs. Unsigned Portal PDF)
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

  // 3. Handle Swiss eCH-0196 v2.2.0 Tax Statement XML (SAXO & SWISSQUOTE)
  if (artifactType === 'ECH0196_XML') {
    if (brokerConfig.institution !== 'SAXO' && brokerConfig.institution !== 'SWISSQUOTE') {
      throw new BrokerSourceError(
        'REFUSE_UNSUPPORTED_ARTIFACT_FOR_INSTITUTION',
        `Swiss eCH-0196 XMLDSIG is only supported for SAXO and SWISSQUOTE, not ${brokerConfig.institution}`
      );
    }
    const echRes = verifyEch0196StatementXml(payloadBytes, {
      ...options,
      institution: brokerConfig.institution,
    });
    if (echRes.institution !== brokerConfig.institution) {
      throw new BrokerSourceError(
        'REFUSE_INSTITUTION_MISMATCH',
        `eCH-0196 statement institution "${echRes.institution}" does not match requested broker "${brokerConfig.institution}"`
      );
    }
    return {
      ok: true,
      status: 'BROKER_PROVENANCE_VERIFIED',
      institution: echRes.institution,
      artifactType: 'ECH0196_XMLDSIG',
      scope: 'ANNUAL_ECH0196_TAX_STATEMENT',
      qualification: 'ANNUAL_SWISS_TAX_STATEMENT_SCOPE',
      canton: echRes.canton,
      taxPeriod: echRes.taxPeriod,
      periodFrom: echRes.periodFrom,
      periodTo: echRes.periodTo,
      currency: echRes.currency,
      totalTaxValueScaled: echRes.totalTaxValueScaled,
      totalGrossRevenueAScaled: echRes.totalGrossRevenueAScaled,
      totalGrossRevenueBScaled: echRes.totalGrossRevenueBScaled,
      payloadSha256: echRes.payloadSha256,
      canonicalStatementSha256: echRes.canonicalStatementSha256,
      certFingerprint256: echRes.certFingerprint256,
      certSubject: echRes.certSubject,
    };
  }

  // 4. Handle RFC 6376 DKIM .eml Artifacts
  if (artifactType === 'EML') {
    const { rawHeaders, bodyBlock } = parseEmlStructure(payloadBytes);
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

    const dkimTags = dkimHeader ? parseDkimTags(dkimHeader.raw) : {};
    const dkimDomain = String(dkimTags.d || '').toLowerCase();

    // Gate 2: TradeStation Desktop / User-SMTP Self-Attestation Trap (From == To or user SMTP server)
    if (
      brokerConfig.institution === 'TRADESTATION' ||
      /TradeManager|TradeStation.*Order.*Fill/i.test(subject)
    ) {
      if (
        (fromAddress && toAddress && fromAddress === toAddress) ||
        CONSUMER_AND_RELAY_DOMAINS.has(dkimDomain) ||
        CONSUMER_AND_RELAY_DOMAINS.has(fromDomain) ||
        dkimDomain !== 'tradestation.com'
      ) {
        throw new BrokerSourceError(
          'REFUSE_USER_SMTP_SELF_ATTESTATION',
          'TradeStation order-fill alert is routed via user-configured SMTP (From == To or user mail server) and has zero broker cryptographic authority',
          { fromAddress, toAddress, dkimDomain }
        );
      }
    }

    // Gate 1: Self-Emailed / Consumer Relay / Mismatched DKIM Domain Cross-Contamination
    if (
      CONSUMER_AND_RELAY_DOMAINS.has(dkimDomain) ||
      CONSUMER_AND_RELAY_DOMAINS.has(fromDomain) ||
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

    // Verify cryptographic RFC 6376 DKIM signature offline
    const dkimRes = verifyDkimStatementEml(payloadBytes, {
      expectedDomain: dkimDomain,
      publicKeyPem: options.publicKeyPem ?? input.publicKeyPem,
      trustedKeys: options.trustedKeys ?? input.trustedKeys,
    });

    const attachments = extractMimeAttachments(rawHeaders, bodyBlock);

    // Gate 4: Notification Link Only (No Payload)
    if (
      brokerConfig.institution === 'FIDELITY' ||
      (brokerConfig.institution === 'IBKR' && attachments.length === 0) ||
      isLoginLinkOnlyNotification(subject, bodyBlock, attachments)
    ) {
      throw new BrokerSourceError(
        'REFUSE_NOTIFICATION_LINK_ONLY_NO_PAYLOAD',
        `${brokerConfig.displayName} email is a portal login/download-link notification and contains no cryptographic statement or execution payload`,
        { institution: brokerConfig.institution, subject }
      );
    }

    // Verified Provenance Dispatch by Institution
    if (brokerConfig.institution === 'IBKR') {
      const primaryAttachment = attachments[0];
      const attText = primaryAttachment.bytes.toString('utf8');
      const trimmedAtt = attText.replace(/^\uFEFF/, '').trimStart();
      let flexValidation = null;
      if (
        /^<(?:<\?xml[^>]*\?>\s*)?FlexQueryResponse\b/i.test(trimmedAtt) ||
        trimmedAtt.includes('<FlexQueryResponse') ||
        trimmedAtt.startsWith('BOF,')
      ) {
        flexValidation = parseAndValidateIbkrFlex(attText, options.flexOptions || {});
      }

      return {
        ok: true,
        status: 'BROKER_PROVENANCE_VERIFIED',
        institution: 'IBKR',
        artifactType: 'DKIM_EML_STATEMENT_ATTACHMENT',
        scope: 'FULL_PERIOD_NAV_AND_FLOWS',
        qualification: null,
        dkimDomain: dkimRes.domain,
        dkimSelector: dkimRes.selector,
        bodyHash: dkimRes.bodyHash,
        attachmentFilename: primaryAttachment.filename,
        attachmentSha256: primaryAttachment.sha256,
        attachments: attachments.map((a) => ({
          filename: a.filename,
          contentType: a.contentType,
          sha256: a.sha256,
          bytes: a.bytes.length,
        })),
        flexValidation,
      };
    }

    if (
      brokerConfig.institution === 'SCHWAB' ||
      brokerConfig.institution === 'VANGUARD' ||
      brokerConfig.institution === 'SWISSQUOTE'
    ) {
      return {
        ok: true,
        status: 'BROKER_PROVENANCE_VERIFIED',
        institution: brokerConfig.institution,
        artifactType: 'DKIM_EML_TRADE_CONFIRM',
        scope: 'SINGLE_TRADE_CONFIRMATION',
        qualification: 'SINGLE_TRADE_ONLY_NO_FULL_NAV',
        dkimDomain: dkimRes.domain,
        dkimSelector: dkimRes.selector,
        bodyHash: dkimRes.bodyHash,
        tradeSummary: extractTradeConfirmationSummary(bodyBlock),
      };
    }

    if (brokerConfig.institution === 'WISE' || brokerConfig.institution === 'REVOLUT') {
      return {
        ok: true,
        status: 'BROKER_PROVENANCE_VERIFIED',
        institution: brokerConfig.institution,
        artifactType: 'DKIM_EML_TRANSFER_RECEIPT',
        scope: 'SINGLE_TRANSFER_RECEIPT',
        qualification: 'SINGLE_TRANSFER_ONLY_NO_FULL_NAV',
        dkimDomain: dkimRes.domain,
        dkimSelector: dkimRes.selector,
        bodyHash: dkimRes.bodyHash,
        transferSummary: extractTransferReceiptSummary(bodyBlock),
      };
    }
  }

  throw new BrokerSourceError(
    'REFUSE_UNSUPPORTED_ARTIFACT_FOR_INSTITUTION',
    `Unsupported or unrecognized artifact type "${artifactType}" for institution "${brokerConfig.institution}"`
  );
}

function serializeBigInts(obj) {
  return JSON.parse(
    JSON.stringify(obj, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2)
  );
}

export function runCli(args) {
  const help =
    'Usage: node scripts/verify-broker-source.mjs ARTIFACT_FILE --institution BROKER [--pubkey-pem FILE] [--trusted-cert FILE] [--webhook-sig BASE64]\n' +
    'Direct Multi-Broker Zero-Contamination Source Verifier across 9 audited institutions.\n';
  if (args.length === 1 && args[0] === '--help') {
    return { exitCode: 0, output: help };
  }
  try {
    let artifactFile = null;
    let institution = null;
    let pubkeyFile = null;
    let trustedCertFile = null;
    let webhookSig = null;

    for (let i = 0; i < args.length; i++) {
      if (args[i] === '--institution' && i + 1 < args.length) {
        institution = args[++i];
      } else if (args[i] === '--pubkey-pem' && i + 1 < args.length) {
        pubkeyFile = args[++i];
      } else if (args[i] === '--trusted-cert' && i + 1 < args.length) {
        trustedCertFile = args[++i];
      } else if (args[i] === '--webhook-sig' && i + 1 < args.length) {
        webhookSig = args[++i];
      } else if (!args[i].startsWith('--') && !artifactFile) {
        artifactFile = args[i];
      } else {
        return { exitCode: 3, output: JSON.stringify({ status: 'INVALID_INPUT' }) + '\n' };
      }
    }

    if (!artifactFile || !institution) {
      return { exitCode: 3, output: JSON.stringify({ status: 'INVALID_INPUT' }) + '\n' };
    }

    const content = readFileSync(artifactFile);
    const publicKeyPem = pubkeyFile ? readFileSync(pubkeyFile, 'utf8') : undefined;
    const trustedCertsPem = trustedCertFile ? [readFileSync(trustedCertFile, 'utf8')] : undefined;

    const res = verifyDirectBrokerArtifact(
      {
        institution,
        content,
        signatureBase64: webhookSig || undefined,
      },
      {
        publicKeyPem,
        trustedCertsPem,
      }
    );

    return {
      exitCode: 0,
      output: JSON.stringify(serializeBigInts(res), null, 2) + '\n',
    };
  } catch (err) {
    return {
      exitCode: 1,
      output:
        JSON.stringify({
          status: 'REJECTED',
          code: err.code || 'BROKER_SOURCE_REJECTED',
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
