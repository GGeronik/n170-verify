#!/usr/bin/env node
// scripts/witness-fetch.mjs (SPEC-08 Core Canonicalizer, F05 Validator & Witness Fetcher - Node.js Built-ins Only)
import https from 'node:https';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { URL, pathToFileURL } from 'node:url';

export const IBKR_BASE_URL = 'https://ndcdyn.interactivebrokers.com/AccountManagement/FlexWebService';
export const BACKOFF_SCHEDULE_MS = [2000, 4000, 8000, 12000, 16000, 20000];

export const PERMANENT_ABORT_CODES = new Set([
  '1003', '1010', '1011', '1012', '1013', '1014', '1015', '1016', '1017', '1020',
]);

export const MUTABLE_ACCOUNT_ATTRS = new Set([
  'lastTradedDate', 'dateClosed', 'accountRepName', 'accountRepPhone',
  'syepEnrollmentStatus', 'unsignedPendingDocumentsStatus', 'dividendReinvestmentStatus',
]);

export const DATE_ATTRS = new Set([
  'fromDate', 'toDate', 'reportDate', 'settleDate', 'tradeDate',
  'dateOpened', 'dateFunded', 'exDate', 'expiry', 'availableForTradingDate',
]);

export const DATETIME_ATTRS = new Set([
  'dateTime', 'orderTime', 'openDateTime', 'holdingPeriodDateTime', 'whenRealized', 'whenReopened',
]);

export const MONETARY_DECIMAL_ATTRS = new Set([
  'startingValue', 'mtm', 'realized', 'changeInUnrealized', 'costAdjustments',
  'depositsWithdrawals', 'internalCashTransfers', 'assetTransfers', 'dividends',
  'withholdingTax', 'withholding871m', 'withholdingTaxCollected', 'changeInDividendAccruals',
  'interest', 'changeInInterestAccruals', 'advisorFees', 'clientFees', 'otherFees',
  'feesReceivables', 'commissions', 'commissionReceivables', 'forexCommissions',
  'transactionTax', 'taxReceivables', 'salesTax', 'softDollars', 'netFxTrading',
  'fxTranslation', 'linkingAdjustments', 'debitCardActivity', 'billPayActivity',
  'other', 'grantActivity', 'endingValue', 'twr', 'startingCash', 'depositWithdrawals', 'deposits',
  'withdrawals', 'accountTransfers', 'internalTransfers', 'brokerInterest', 'bondInterest',
  'cashSettlingMtm', 'netTradesSales', 'netTradesPurchases', 'paymentInLieu',
  'fxTranslationGainLoss', 'endingCash', 'endingSettledCash', 'amount', 'fxRateToBase',
  'proceeds', 'value', 'quantity', 'fifoPnlRealized', 'mtmPnl', 'grossAmount',
  'fineness', 'weight', 'cashAmount', 'marketValue',
]);

const STANDARD_ACCOUNT_ID_RE = /^(?:U|DU|F|DF|I|Q)[0-9]{5,12}$/;

/**
 * Exact string-based decimal parser into scaled BigInt (8 decimal places).
 * Avoids IEEE-754 floating-point drift during F05 tie-out checks.
 */
export function parseScaledDecimal(raw, attrName = '') {
  if (raw === undefined || raw === null || raw === '') return 0n;
  const cleaned = String(raw).trim();
  if (!/^-?\d+(\.\d+)?$/.test(cleaned)) {
    throw new Error(`REFUSE_CORRUPT_DECIMAL: Invalid numeric value "${raw}" in attribute "${attrName}"`);
  }
  const negative = cleaned.startsWith('-');
  const unsigned = negative ? cleaned.slice(1) : cleaned;
  const [intPart, fracPart = ''] = unsigned.split('.');
  if (fracPart.length > 8 && !/^0+$/.test(fracPart.slice(8))) {
    throw new Error(`REFUSE_CORRUPT_DECIMAL: Excess decimal places in "${raw}" on "${attrName}"`);
  }
  const paddedFrac = (fracPart + '00000000').slice(0, 8);
  const scaled = BigInt(intPart) * 100000000n + BigInt(paddedFrac);
  return negative ? -scaled : scaled;
}

/**
 * Normalizes decimal strings deterministically without precision loss (CANON-XML-06 / ADV-14).
 */
export function normalizeDecimalString(raw, attrName = '') {
  if (raw === '' || raw === undefined || raw === null) return '';
  let val = String(raw).trim();
  if ((attrName === 'weight' || attrName.endsWith('.weight')) && val.endsWith(' ()')) {
    val = val.slice(0, -3).trim();
  }
  if (!/^-?\d+(\.\d+)?$/.test(val)) {
    throw new Error(`REFUSE_CORRUPT_DECIMAL: "${raw}" on attribute "${attrName}"`);
  }
  if (val.includes('.')) {
    val = val.replace(/\.?0+$/, '');
  }
  if (val === '-0' || val === '') val = '0';
  return val;
}

/**
 * Normalizes dates (YYYYMMDD -> YYYY-MM-DD) and rejects ambiguous European dates (CANON-XML-05 / ADV-13).
 */
export function normalizeDateString(raw, attrName = '') {
  if (!raw) return '';
  const val = String(raw).trim();
  if (val.includes('/')) {
    throw new Error(`REFUSE_AMBIGUOUS_DATE_FORMAT: Slash date "${val}" in "${attrName}"`);
  }
  let iso = val;
  if (/^\d{8}$/.test(val)) {
    iso = `${val.slice(0, 4)}-${val.slice(4, 6)}-${val.slice(6, 8)}`;
  } else if (!/^\d{4}-\d{2}-\d{2}$/.test(val)) {
    throw new Error(`REFUSE_INVALID_DATE_FORMAT: Unrecognized date "${val}" in "${attrName}"`);
  }
  const parsed = new Date(`${iso}T00:00:00Z`);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString().slice(0, 10) !== iso) {
    throw new Error(`REFUSE_INVALID_DATE_FORMAT: Invalid calendar date "${val}" in "${attrName}"`);
  }
  return iso;
}

/**
 * Normalizes timestamps and strips volatile timezone suffixes like EST/EDT (CANON-XML-05).
 */
export function normalizeDateTimeString(raw, attrName = '') {
  if (!raw) return '';
  const val = String(raw).trim().replace(/\s+(EST|EDT|UTC|GMT)$/i, '');
  if (val.includes('/')) {
    throw new Error(`REFUSE_AMBIGUOUS_DATE_FORMAT: Slash datetime "${val}" in "${attrName}"`);
  }
  const [datePart, timePart] = val.split(/[; ]+/);
  const normDate = normalizeDateString(datePart, attrName);
  if (!timePart) return normDate;
  if (/^\d{6}$/.test(timePart)) {
    return `${normDate};${timePart.slice(0, 2)}:${timePart.slice(2, 4)}:${timePart.slice(4, 6)}`;
  }
  if (/^\d{2}:\d{2}:\d{2}$/.test(timePart)) {
    return `${normDate};${timePart}`;
  }
  throw new Error(`REFUSE_INVALID_DATETIME_FORMAT: "${raw}" in "${attrName}"`);
}

export function validateAccountId(accountId) {
  if (!accountId || typeof accountId !== 'string') {
    return { valid: false, flag: 'FLAG_ALIAS_OR_VIRTUAL_ID' };
  }
  if (accountId.includes('-') || !STANDARD_ACCOUNT_ID_RE.test(accountId.trim())) {
    return { valid: false, flag: 'FLAG_ALIAS_OR_VIRTUAL_ID' };
  }
  return { valid: true, flag: null };
}

/**
 * Validates pre-flight date window parameters (fd, td, p) per ADV-18.
 */
export function validateDateWindow({ fd, td, p } = {}) {
  const hasP = p !== undefined && p !== null && p !== '';
  const hasFd = fd !== undefined && fd !== null && fd !== '';
  const hasTd = td !== undefined && td !== null && td !== '';
  if (hasP && (hasFd || hasTd)) {
    throw new Error('REFUSE_INVALID_DATE_WINDOW: Cannot combine p with fd or td');
  }
  if (hasP) {
    const pNum = Number(p);
    if (!Number.isInteger(pNum) || pNum < 1 || pNum > 365) {
      throw new Error('REFUSE_INVALID_DATE_WINDOW: Relative period p must be an integer in 1..365');
    }
    return { mode: 'period', p: pNum };
  }
  if (hasFd !== hasTd) {
    throw new Error('REFUSE_INVALID_DATE_WINDOW: fd and td must both be supplied together');
  }
  if (hasFd && hasTd) {
    const normFrom = normalizeDateString(fd, 'fd');
    const normTo = normalizeDateString(td, 'td');
    const fromMs = Date.parse(`${normFrom}T00:00:00Z`);
    const toMs = Date.parse(`${normTo}T00:00:00Z`);
    if (fromMs > toMs) {
      throw new Error('REFUSE_INVALID_DATE_WINDOW: fd must not be after td');
    }
    const inclusiveDays = Math.round((toMs - fromMs) / 86400000) + 1;
    if (inclusiveDays > 365 || inclusiveDays < 1) {
      throw new Error(`REFUSE_INVALID_DATE_WINDOW: Inclusive window of ${inclusiveDays} days exceeds 365-day maximum`);
    }
    return {
      mode: 'range',
      fromDate: normFrom,
      toDate: normTo,
      fd: normFrom.replaceAll('-', ''),
      td: normTo.replaceAll('-', ''),
      inclusiveDays,
    };
  }
  return { mode: 'template_default' };
}

/**
 * Classifies IBKR Flex XML error/status envelopes, enforcing ADV-09, ADV-10, ADV-11.
 */
export function classifyFlexError(xmlText) {
  const text = String(xmlText || '').trim();
  if (/^<\?xml[^>]*\?>\s*<code\b/i.test(text) || /^<code\b/i.test(text)) {
    return {
      status: 'Fail',
      code: 'V2_DOWNGRADE',
      message: 'Version 2 protocol downgrade detected (root tag <code>)',
      action: 'REFUSE_PROTOCOL_DOWNGRADE_V2',
      retryable: false,
      circuitBreaker: false,
      enforcedEndpoint: `${IBKR_BASE_URL}/GetStatement`,
    };
  }
  const statusMatch = /<Status>([^<]*)<\/Status>/i.exec(text);
  const codeMatch = /<ErrorCode>([^<]*)<\/ErrorCode>/i.exec(text);
  const msgMatch = /<ErrorMessage>([^<]*)<\/ErrorMessage>/i.exec(text);
  const refMatch = /<ReferenceCode>([^<]*)<\/ReferenceCode>/i.exec(text);
  const urlMatch = /<Url>([^<]*)<\/Url>/i.exec(text);

  const status = statusMatch ? statusMatch[1].trim() : 'Unknown';
  const code = codeMatch ? codeMatch[1].trim() : null;
  const message = msgMatch ? msgMatch[1].trim() : '';
  const referenceCode = refMatch ? refMatch[1].trim() : null;
  const ignoredUrl = urlMatch ? urlMatch[1].trim() : null;
  const enforcedEndpoint = `${IBKR_BASE_URL}/GetStatement`;

  if (status === 'Success' && referenceCode && !code) {
    return {
      status: 'Success',
      code: null,
      message: '',
      referenceCode,
      ignoredUrl,
      enforcedEndpoint,
      hostPolicy: 'ENFORCE_NDCDYN_HOST',
      action: 'POLL_GET_STATEMENT',
      retryable: false,
      circuitBreaker: false,
    };
  }

  if (code === '1025') {
    return {
      status,
      code: '1025',
      message,
      ignoredUrl,
      enforcedEndpoint,
      action: 'REFUSE_LOCKOUT_1025',
      retryable: false,
      circuitBreaker: true,
      maxRetries: 0,
    };
  }

  if (code === '1019') {
    return {
      status,
      code: '1019',
      message,
      ignoredUrl,
      enforcedEndpoint,
      action: 'RETRY_GENERATION_IN_PROGRESS',
      retryable: true,
      circuitBreaker: false,
    };
  }

  if (code === '1018') {
    return {
      status,
      code: '1018',
      message,
      ignoredUrl,
      enforcedEndpoint,
      action: 'RETRY_THROTTLED_COOLDOWN_60S',
      retryable: true,
      cooldownMs: 60000,
      circuitBreaker: false,
    };
  }

  if (code && PERMANENT_ABORT_CODES.has(code)) {
    return {
      status,
      code,
      message,
      ignoredUrl,
      enforcedEndpoint,
      action: `ABORT_${code}`,
      retryable: false,
      circuitBreaker: false,
    };
  }

  if (code && ['1001', '1004', '1005', '1006', '1007', '1008', '1009', '1021'].includes(code)) {
    return {
      status,
      code,
      message,
      ignoredUrl,
      enforcedEndpoint,
      action: `RETRY_${code}`,
      retryable: true,
      circuitBreaker: false,
    };
  }

  return {
    status,
    code: code || 'UNKNOWN',
    message,
    ignoredUrl,
    enforcedEndpoint,
    action: 'ABORT_UNKNOWN_CODE',
    retryable: false,
    circuitBreaker: false,
  };
}

function parseXmlAttributes(attrString) {
  const attrs = {};
  const re = /([A-Za-z0-9_:-]+)\s*=\s*"([^"]*)"/g;
  let m;
  while ((m = re.exec(attrString)) !== null) {
    attrs[m[1]] = m[2];
  }
  return attrs;
}

function normalizeElementAttributes(tagName, rawAttrs) {
  const out = {};
  for (const [k, v] of Object.entries(rawAttrs)) {
    if (tagName === 'FlexStatement' && (k === 'whenGenerated' || k === 'period')) continue;
    if (tagName === 'AccountInformation' && MUTABLE_ACCOUNT_ATTRS.has(k)) continue;
    if (DATE_ATTRS.has(k)) {
      out[k] = normalizeDateString(v, `${tagName}.${k}`);
    } else if (DATETIME_ATTRS.has(k)) {
      out[k] = normalizeDateTimeString(v, `${tagName}.${k}`);
    } else if (MONETARY_DECIMAL_ATTRS.has(k)) {
      out[k] = normalizeDecimalString(v, `${tagName}.${k}`);
    } else {
      out[k] = v;
    }
  }
  return out;
}

function serializeSelfClosingTag(tagName, attrs) {
  const sortedKeys = Object.keys(attrs).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  if (sortedKeys.length === 0) return `<${tagName} />`;
  const attrStr = sortedKeys.map((k) => `${k}="${attrs[k]}"`).join(' ');
  return `<${tagName} ${attrStr} />`;
}

function serializeOpenTag(tagName, attrs) {
  const sortedKeys = Object.keys(attrs).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  if (sortedKeys.length === 0) return `<${tagName}>`;
  const attrStr = sortedKeys.map((k) => `${k}="${attrs[k]}"`).join(' ');
  return `<${tagName} ${attrStr}>`;
}

function compositeSortKey(attrs) {
  const fields = [
    'accountId', 'currency', 'levelOfDetail', 'reportDate', 'dateTime',
    'transactionID', 'tradeID', 'actionID', 'type', 'symbol', 'amount',
  ];
  return fields.map((f) => attrs[f] ?? '').join('\x00');
}

/**
 * Canonicalizes an IBKR Flex XML v3 payload (CANON-XML-01..08).
 */
export function canonicalizeFlexXml(rawXml, options = {}) {
  let text;
  if (rawXml instanceof Uint8Array || Buffer.isBuffer(rawXml)) {
    const u8 = rawXml instanceof Uint8Array ? rawXml : new Uint8Array(rawXml);
    text = new TextDecoder('utf-8', { fatal: true }).decode(u8);
  } else {
    text = String(rawXml);
  }
  if (text.startsWith('\uFEFF')) text = text.slice(1);
  text = text.replace(/\r\n?/g, '\n').trim();

  if (/^(?:<\?xml[^>]*\?>\s*)?<code\b/i.test(text)) {
    throw new Error('REFUSE_PROTOCOL_DOWNGRADE_V2: Root tag is <code> (missing v=3)');
  }
  if (/^(?:<\?xml[^>]*\?>\s*)?<FlexStatementResponse\b/i.test(text)) {
    const classified = classifyFlexError(text);
    throw new Error(`${classified.action}: ${classified.code} ${classified.message}`);
  }
  const rootMatch = /<FlexQueryResponse\b([^>]*)>/i.exec(text);
  if (!rootMatch) {
    throw new Error('REFUSE_INVALID_XML_ENVELOPE: Root element is not <FlexQueryResponse>');
  }
  const rootAttrs = normalizeElementAttributes('FlexQueryResponse', parseXmlAttributes(rootMatch[1]));
  const stmtsContainerMatch = /<FlexStatements\b([^>]*)>/i.exec(text);
  if (!stmtsContainerMatch) {
    throw new Error('REFUSE_INVALID_XML_ENVELOPE: Missing <FlexStatements> container');
  }
  const stmtsContainerAttrs = parseXmlAttributes(stmtsContainerMatch[1]);
  const stmtRegex = /<FlexStatement\b([^>]*)>([\s\S]*?)<\/FlexStatement>/g;
  const stmtMatches = [...text.matchAll(stmtRegex)];
  if (stmtsContainerAttrs.count !== undefined && Number(stmtsContainerAttrs.count) !== stmtMatches.length) {
    throw new Error(`REFUSE_INVALID_XML_ENVELOPE: FlexStatements declared count (${stmtsContainerAttrs.count}) != ${stmtMatches.length}`);
  }

  const flags = [];
  const canonicalLines = [
    serializeOpenTag('FlexQueryResponse', rootAttrs),
    serializeOpenTag('FlexStatements', { count: String(stmtMatches.length) }),
  ];

  let accountInfo = null;
  let changeInNav = null;
  const cashReportRows = [];
  const cashTransactionRows = [];
  const corporateActionRows = [];
  const transferRows = [];
  const dividendAccrualRows = [];
  const sectionsPresent = new Set();

  for (const match of stmtMatches) {
    const stmtAttrs = normalizeElementAttributes('FlexStatement', parseXmlAttributes(match[1]));
    if (options.requestedFrom) {
      const reqFrom = normalizeDateString(options.requestedFrom, 'requestedFrom');
      if (stmtAttrs.fromDate !== reqFrom) {
        throw new Error(`REFUSE_PERIOD_MISMATCH: Statement fromDate ${stmtAttrs.fromDate} != requested ${reqFrom}`);
      }
    }
    if (options.requestedTo) {
      const reqTo = normalizeDateString(options.requestedTo, 'requestedTo');
      if (stmtAttrs.toDate !== reqTo) {
        throw new Error(`REFUSE_PERIOD_MISMATCH: Statement toDate ${stmtAttrs.toDate} != requested ${reqTo}`);
      }
    }
    if (stmtAttrs.accountId) {
      const acctCheck = validateAccountId(stmtAttrs.accountId);
      if (!acctCheck.valid && !flags.includes(acctCheck.flag)) flags.push(acctCheck.flag);
    }

    canonicalLines.push(serializeOpenTag('FlexStatement', stmtAttrs));
    const inner = match[2];

    const acctMatch = /<AccountInformation\b([^>]*)\/>/.exec(inner);
    if (acctMatch) {
      sectionsPresent.add('AccountInformation');
      accountInfo = normalizeElementAttributes('AccountInformation', parseXmlAttributes(acctMatch[1]));
      if (accountInfo.accountId) {
        const acctCheck = validateAccountId(accountInfo.accountId);
        if (!acctCheck.valid && !flags.includes(acctCheck.flag)) flags.push(acctCheck.flag);
      }
      if (accountInfo.dateOpened && stmtAttrs.fromDate && stmtAttrs.fromDate < accountInfo.dateOpened) {
        if (!flags.includes('FLAG_PRE_INCEPTION_WINDOW')) flags.push('FLAG_PRE_INCEPTION_WINDOW');
      }
      canonicalLines.push(serializeSelfClosingTag('AccountInformation', accountInfo));
    }

    const navMatch = /<ChangeInNAV\b([^>]*)\/>/.exec(inner);
    if (navMatch) {
      sectionsPresent.add('ChangeInNAV');
      changeInNav = normalizeElementAttributes('ChangeInNAV', parseXmlAttributes(navMatch[1]));
      canonicalLines.push(serializeSelfClosingTag('ChangeInNAV', changeInNav));
    }

    const containerSpecs = [
      ['CashReport', 'CashReportCurrency', cashReportRows],
      ['CashTransactions', 'CashTransaction', cashTransactionRows],
      ['CorporateActions', 'CorporateAction', corporateActionRows],
      ['Transfers', 'Transfer', transferRows],
      ['ChangeInDividendAccruals', 'ChangeInDividendAccrual', dividendAccrualRows],
    ];

    for (const [containerTag, childTag, targetArray] of containerSpecs) {
      const cRe = new RegExp(`<${containerTag}\\b[^>]*>([\\s\\S]*?)<\\/${containerTag}>`);
      const cMatch = cRe.exec(inner);
      if (!cMatch) continue;
      sectionsPresent.add(containerTag);
      const childRe = new RegExp(`<${childTag}\\b([^>]*)\\/>`, 'g');
      const rows = [];
      let cm;
      while ((cm = childRe.exec(cMatch[1])) !== null) {
        const normAttrs = normalizeElementAttributes(childTag, parseXmlAttributes(cm[1]));
        rows.push(normAttrs);
        targetArray.push(normAttrs);
      }
      rows.sort((a, b) => {
        const ka = compositeSortKey(a);
        const kb = compositeSortKey(b);
        return ka < kb ? -1 : ka > kb ? 1 : 0;
      });
      if (rows.length === 0) {
        canonicalLines.push(`<${containerTag}></${containerTag}>`);
      } else {
        canonicalLines.push(`<${containerTag}>`);
        for (const r of rows) canonicalLines.push(serializeSelfClosingTag(childTag, r));
        canonicalLines.push(`</${containerTag}>`);
      }
    }

    const emptyContainers = [...inner.matchAll(/<([A-Za-z0-9_]+)>\s*<\/\1>/g)];
    for (const ec of emptyContainers) {
      const tag = ec[1];
      if (!sectionsPresent.has(tag)) {
        canonicalLines.push(`<${tag}></${tag}>`);
      }
    }

    canonicalLines.push('</FlexStatement>');
  }

  if (!options.allowPartialSections) {
    for (const req of ['AccountInformation', 'ChangeInNAV', 'CashReport', 'CashTransactions']) {
      if (!sectionsPresent.has(req)) {
        throw new Error(`REFUSE_MISSING_REQUIRED_SECTION: Missing required XML section <${req}>`);
      }
    }
  }

  canonicalLines.push('</FlexStatements>');
  canonicalLines.push('</FlexQueryResponse>');

  const canonicalXml = canonicalLines.join('\n');
  const canonicalSha256 = crypto.createHash('sha256').update(canonicalXml, 'utf8').digest('hex');

  return {
    canonicalXml,
    canonicalSha256,
    accountInfo,
    changeInNav,
    cashReportRows,
    cashTransactionRows,
    corporateActionRows,
    transferRows,
    dividendAccrualRows,
    sectionsPresent: [...sectionsPresent].sort(),
    flags,
  };
}

function parseRfc4180Line(line, delimiter = ',') {
  const fields = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (i + 1 < line.length && line[i + 1] === '"') {
          cur += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        cur += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === delimiter) {
      fields.push(cur);
      cur = '';
    } else {
      cur += ch;
    }
  }
  fields.push(cur);
  return fields;
}

function serializeCsvField(val) {
  const s = String(val ?? '');
  if (s.includes(',') || s.includes('"') || s.includes(';') || s.includes('\n')) {
    return `"${s.replaceAll('"', '""')}"`;
  }
  return s;
}

const DESCRIPTOR_TOKENS = new Set(['BOS', 'HEADER', 'DATA', 'EOS']);
const SECTION_CODE_RE = /^[A-Z]{4}$/;

/**
 * Canonicalizes an IBKR Flex CSV payload (CANON-CSV-01..06, ADV-16, ADV-17).
 */
export function canonicalizeFlexCsv(rawCsv, options = {}) {
  let text = String(rawCsv ?? '');
  if (text.startsWith('\uFEFF')) text = text.slice(1);
  text = text.replace(/\r\n?/g, '\n').trim();
  const rawLines = text.split('\n').filter((l) => l.trim().length > 0);
  if (rawLines.length === 0) {
    throw new Error('REFUSE_EMPTY_CSV: CSV input is empty');
  }

  const firstLine = rawLines[0];
  const delimiter = firstLine.includes('|') && !firstLine.includes(',') ? '|'
    : firstLine.includes('\t') && !firstLine.includes(',') ? '\t' : ',';

  const parsedRows = rawLines.map((l) => parseRfc4180Line(l, delimiter));
  const bosSections = [];
  const sectionState = new Map();
  const canonicalRows = [];
  const flags = [];
  let currentSection = null;

  const flushSectionData = (sec) => {
    if (!sec || sec.flushed) return;
    sec.dataRows.sort((a, b) => {
      const sa = a.join('\x00');
      const sb = b.join('\x00');
      return sa < sb ? -1 : sa > sb ? 1 : 0;
    });
    for (const dr of sec.dataRows) {
      canonicalRows.push(dr.map(serializeCsvField).join(','));
    }
    sec.flushed = true;
  };

  for (let row of parsedRows) {
    row = row.map((c) => c.trim());
    if (row[0] === 'BOF') {
      const bof = row.slice();
      if (bof.length >= 5) {
        bof[3] = normalizeDateString(bof[3], 'BOF.FromDate');
        bof[4] = normalizeDateString(bof[4], 'BOF.ToDate');
      }
      if (bof.length >= 6) bof[5] = 'CANONICAL_TS';
      if (bof.length >= 7) bof[6] = '100';
      if (bof.length >= 8) bof[7] = '100';
      canonicalRows.push(bof.map(serializeCsvField).join(','));
      continue;
    }

    if (row[0] === 'BOA' || row[0] === 'EOA' || row[0] === 'EOF') {
      canonicalRows.push(row.map(serializeCsvField).join(','));
      continue;
    }

    if (row.length >= 2 && SECTION_CODE_RE.test(row[0]) && DESCRIPTOR_TOKENS.has(row[1])) {
      const swapped = row.slice();
      swapped[0] = row[1];
      swapped[1] = row[0];
      row = swapped;
    }

    const descriptor = row[0];
    const sectionCode = row[1];

    if (descriptor === 'BOS') {
      bosSections.push(sectionCode);
      currentSection = {
        code: sectionCode,
        headers: [],
        dataRows: [],
        rawMappedRows: [],
        flushed: false,
      };
      sectionState.set(sectionCode, currentSection);
      canonicalRows.push(row.map(serializeCsvField).join(','));
    } else if (descriptor === 'HEADER') {
      const sec = sectionState.get(sectionCode) || currentSection;
      if (sec) sec.headers = row.slice(2);
      canonicalRows.push(row.map(serializeCsvField).join(','));
    } else if (descriptor === 'DATA') {
      const sec = sectionState.get(sectionCode) || currentSection;
      if (!sec) {
        throw new Error(`REFUSE_MALFORMED_CSV: DATA row for ${sectionCode} without BOS`);
      }
      const values = row.slice(2);
      const mapped = {};
      const scrubbedValues = [];
      for (let i = 0; i < sec.headers.length; i++) {
        const colName = sec.headers[i];
        let cell = values[i] ?? '';
        const lowerFirst = colName.charAt(0).toLowerCase() + colName.slice(1);
        if (sectionCode === 'ACCT' && (MUTABLE_ACCOUNT_ATTRS.has(colName) || MUTABLE_ACCOUNT_ATTRS.has(lowerFirst))) {
          cell = '';
        } else if (DATE_ATTRS.has(colName) || DATE_ATTRS.has(lowerFirst)) {
          cell = cell ? normalizeDateString(cell, `${sectionCode}.${colName}`) : '';
        } else if (DATETIME_ATTRS.has(colName) || DATETIME_ATTRS.has(lowerFirst)) {
          cell = cell ? normalizeDateTimeString(cell, `${sectionCode}.${colName}`) : '';
        } else if (MONETARY_DECIMAL_ATTRS.has(colName) || MONETARY_DECIMAL_ATTRS.has(lowerFirst) ||
                   colName === 'NetTradeMoney' || colName === 'PositionValue') {
          cell = cell ? normalizeDecimalString(cell, `${sectionCode}.${colName}`) : '';
        }
        mapped[colName] = cell;
        scrubbedValues.push(cell);
      }
      if (sectionCode === 'ACCT') {
        const acctId = mapped.ClientAccountID || mapped['Account ID'] || mapped.accountId;
        if (acctId) {
          const check = validateAccountId(acctId);
          if (!check.valid && !flags.includes(check.flag)) flags.push(check.flag);
        }
      }
      sec.rawMappedRows.push(mapped);
      sec.dataRows.push(['DATA', sectionCode, ...scrubbedValues]);
    } else if (descriptor === 'EOS') {
      const sec = sectionState.get(sectionCode) || currentSection;
      if (!sec) {
        throw new Error(`REFUSE_MALFORMED_CSV: EOS row for ${sectionCode} without BOS`);
      }
      flushSectionData(sec);
      const expectedCount = Number(row[2]);
      if (!Number.isInteger(expectedCount) || sec.dataRows.length !== expectedCount) {
        throw new Error(
          `REFUSE_CSV_EOS_CHECKSUM_MISMATCH: Section ${sectionCode} has ${sec.dataRows.length} DATA rows, EOS expects ${row[2]}`
        );
      }
      if (row[3] !== undefined && row[3] !== '') {
        const expectedAmount = parseScaledDecimal(row[3], `EOS.${sectionCode}.AmountChecksum`);
        if (['TRNT', 'TRNS', 'POST', 'POSS'].includes(sectionCode)) {
          const col = sectionCode.startsWith('TRN') ? 'NetTradeMoney' : 'PositionValue';
          if (sec.headers.includes(col)) {
            let sum = 0n;
            for (const m of sec.rawMappedRows) {
              sum += parseScaledDecimal(m[col] || '0', `${sectionCode}.${col}`);
            }
            if (sum !== expectedAmount) {
              throw new Error(
                `REFUSE_CSV_EOS_CHECKSUM_MISMATCH: Section ${sectionCode} amount checksum mismatch`
              );
            }
          }
        }
      }
      const normEos = ['EOS', sectionCode, String(expectedCount)];
      if (row[3] !== undefined) normEos.push(normalizeDecimalString(row[3], 'EOS.AmountChecksum'));
      canonicalRows.push(normEos.map(serializeCsvField).join(','));
    } else {
      canonicalRows.push(row.map(serializeCsvField).join(','));
    }
  }

  if (!options.allowPartialSections) {
    const hasAcct = bosSections.includes('ACCT');
    const hasNav = bosSections.includes('EQUT') || bosSections.includes('EQUS');
    const hasCashReport = bosSections.includes('CRTT') || bosSections.includes('CRTS');
    const hasCashTx = bosSections.includes('CTRN');
    if (!hasAcct || !hasNav || !hasCashReport || !hasCashTx) {
      throw new Error(
        `REFUSE_MISSING_REQUIRED_SECTION: CSV BOS census [${bosSections.join(', ')}] missing required ACCT/EQUT/CRTT/CTRN`
      );
    }
  }

  const canonicalCsv = canonicalRows.join('\n');
  const canonicalSha256 = crypto.createHash('sha256').update(canonicalCsv, 'utf8').digest('hex');

  return {
    canonicalCsv,
    canonicalSha256,
    sectionsPresent: bosSections,
    flags,
  };
}

/**
 * Validates Fixture F05 invariants across ChangeInNAV, CashReportCurrency, and CorporateActions (ADV-01..08, ADV-15).
 */
export function validateFixtureF05(changeInNavAttrs, cashReportRows, corporateActionRows = [], extra = {}) {
  if (!changeInNavAttrs || typeof changeInNavAttrs !== 'object') {
    throw new Error('REFUSE_MISSING_REQUIRED_SECTION: Missing ChangeInNAV attributes');
  }
  if (!Array.isArray(cashReportRows)) {
    throw new Error('REFUSE_MISSING_REQUIRED_SECTION: Missing CashReport rows');
  }

  const navOther = parseScaledDecimal(changeInNavAttrs.other, 'ChangeInNAV.other');
  const navGrant = parseScaledDecimal(changeInNavAttrs.grantActivity, 'ChangeInNAV.grantActivity');
  if (navOther !== 0n || navGrant !== 0n) {
    throw new Error(
      `REFUSE_UNCLASSIFIED_RETURN_EVENT: ChangeInNAV contains non-zero other (${changeInNavAttrs.other || 0}) or grantActivity`
    );
  }

  for (const ca of corporateActionRows) {
    if (ca.type === 'UE') {
      throw new Error('REFUSE_UNCLASSIFIED_RETURN_EVENT: CorporateAction contains Unknown Event (type="UE")');
    }
  }

  const baseRow = cashReportRows.find(
    (r) => r.currency === 'BASE_SUMMARY' || r.levelOfDetail === 'BaseCurrency'
  );
  if (!baseRow) {
    throw new Error('REFUSE_MISSING_BASE_SUMMARY: CashReport lacks currency="BASE_SUMMARY" row');
  }
  const currencyRows = cashReportRows.filter(
    (r) => r !== baseRow && (r.levelOfDetail === 'Currency' || r.currency !== 'BASE_SUMMARY')
  );

  const navDepWith = parseScaledDecimal(changeInNavAttrs.depositsWithdrawals, 'ChangeInNAV.depositsWithdrawals');
  const navIntCash = parseScaledDecimal(changeInNavAttrs.internalCashTransfers, 'ChangeInNAV.internalCashTransfers');
  const navAssetTrf = parseScaledDecimal(changeInNavAttrs.assetTransfers, 'ChangeInNAV.assetTransfers');
  const navLinkAdj = parseScaledDecimal(changeInNavAttrs.linkingAdjustments, 'ChangeInNAV.linkingAdjustments');
  const navSpend = parseScaledDecimal(changeInNavAttrs.debitCardActivity, 'ChangeInNAV.debitCardActivity') +
                   parseScaledDecimal(changeInNavAttrs.billPayActivity, 'ChangeInNAV.billPayActivity');

  const crDepWith = parseScaledDecimal(baseRow.depositWithdrawals, 'CashReport.depositWithdrawals');
  const crIntTrf = parseScaledDecimal(baseRow.internalTransfers, 'CashReport.internalTransfers');

  const diffTotal = (navDepWith + navIntCash) - (crDepWith + crIntTrf);
  const diffDep = navDepWith - crDepWith;
  const diffInt = navIntCash - crIntTrf;
  if (
    diffTotal > 5000000n || diffTotal < -5000000n ||
    diffDep > 5000000n || diffDep < -5000000n ||
    diffInt > 5000000n || diffInt < -5000000n
  ) {
    throw new Error(
      'REFUSE_F05_CASH_TIEOUT_MISMATCH: ChangeInNAV cash flows do not tie out to CashReport BASE_SUMMARY'
    );
  }

  const startNav = parseScaledDecimal(changeInNavAttrs.startingValue, 'ChangeInNAV.startingValue');
  const endNav = parseScaledDecimal(changeInNavAttrs.endingValue, 'ChangeInNAV.endingValue');
  const totalExternalFlows = navDepWith + navIntCash + navAssetTrf + navLinkAdj + navSpend;
  const economicReturnScaled = (endNav - startNav) - totalExternalFlows;

  const flags = [];
  if (navDepWith !== 0n) flags.push('F05_DEPOSIT_ISOLATED');
  if (navIntCash !== 0n || navAssetTrf !== 0n) flags.push('F05_TRANSFER_ISOLATED');
  if (navLinkAdj !== 0n) flags.push('F05_LINKING_ISOLATED');
  if (currencyRows.length > 0) flags.push('PARTITION_BY_LEVEL_OF_DETAIL');

  const hasCorpCash = corporateActionRows.some(
    (ca) => parseScaledDecimal(ca.amount || '0', 'CorporateAction.amount') !== 0n ||
            parseScaledDecimal(ca.proceeds || '0', 'CorporateAction.proceeds') !== 0n
  );
  const hasTradeCash =
    parseScaledDecimal(baseRow.netTradesSales || '0', 'CashReport.netTradesSales') !== 0n ||
    parseScaledDecimal(baseRow.netTradesPurchases || '0', 'CashReport.netTradesPurchases') !== 0n;
  if (hasCorpCash && hasTradeCash) {
    flags.push('FLAG_CORP_ACTION_CASH_IN_TRADES');
  }

  const cashTxRows = extra.cashTransactionRows || [];
  const divAccrualRows = extra.dividendAccrualRows || [];
  const hasSettledDiv =
    cashTxRows.some((r) => r.type === 'Dividends' && parseScaledDecimal(r.amount || '0', 'CashTransaction.amount') !== 0n) ||
    parseScaledDecimal(baseRow.dividends || '0', 'CashReport.dividends') !== 0n;
  const hasUnreversedAccrual =
    divAccrualRows.some((r) => parseScaledDecimal(r.grossAmount || r.netAmount || '0', 'ChangeInDividendAccrual') !== 0n) ||
    parseScaledDecimal(changeInNavAttrs.changeInDividendAccruals || '0', 'ChangeInNAV.changeInDividendAccruals') !== 0n;
  if (hasSettledDiv && hasUnreversedAccrual) {
    flags.push('FLAG_ACCRUAL_CASH_OVERLAP');
  }

  const acctId = changeInNavAttrs.accountId || extra.accountInfo?.accountId;
  if (acctId) {
    const check = validateAccountId(acctId);
    if (!check.valid) flags.push(check.flag);
  }

  return {
    startingNavScaled: startNav,
    endingNavScaled: endNav,
    netExternalCapitalFlowsScaled: totalExternalFlows,
    economicInvestmentReturnScaled: economicReturnScaled,
    partitionedCashReport: {
      baseSummary: baseRow,
      currencies: currencyRows,
    },
    flags,
  };
}

function defaultHttpsGet(urlString) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlString);
    const req = https.request(
      {
        hostname: u.hostname,
        port: u.port || 443,
        path: u.pathname + u.search,
        method: 'GET',
        headers: { 'User-Agent': 'N170VerifyWitness/0.2.0' },
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      }
    );
    req.on('error', reject);
    req.end();
  });
}

/**
 * Executes the two-step IBKR Flex v3 workflow with pre-flight window validation,
 * ndcdyn host enforcement (ignoring <Url>), 1025 circuit breaker, and 6-step backoff.
 */
export async function executeFlexWorkflow({
  token,
  queryId,
  fd,
  td,
  p,
  transport = defaultHttpsGet,
  sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
}) {
  if (!token || !queryId) {
    throw new Error('REFUSE_INVALID_ARGUMENTS: token and queryId are required');
  }
  const win = validateDateWindow({ fd, td, p });
  const sendUrl = new URL(`${IBKR_BASE_URL}/SendRequest`);
  sendUrl.searchParams.set('t', String(token));
  sendUrl.searchParams.set('q', String(queryId));
  sendUrl.searchParams.set('v', '3');
  if (win.mode === 'range') {
    sendUrl.searchParams.set('fd', win.fd);
    sendUrl.searchParams.set('td', win.td);
  } else if (win.mode === 'period') {
    sendUrl.searchParams.set('p', String(win.p));
  }

  const sendBody = await transport(sendUrl.toString());
  const phase1 = classifyFlexError(sendBody);
  if (phase1.action !== 'POLL_GET_STATEMENT') {
    throw new Error(`${phase1.action}: ${phase1.code} ${phase1.message}`);
  }

  const getUrl = new URL(phase1.enforcedEndpoint);
  getUrl.searchParams.set('t', String(token));
  getUrl.searchParams.set('q', phase1.referenceCode);
  getUrl.searchParams.set('v', '3');

  const delaysUsed = [];
  for (let i = 0; i < BACKOFF_SCHEDULE_MS.length; i++) {
    const delayMs = BACKOFF_SCHEDULE_MS[i];
    await sleep(delayMs);
    delaysUsed.push(delayMs);

    const pollBody = await transport(getUrl.toString());
    const trimmed = String(pollBody || '').trim();
    if (/^(?:<\?xml[^>]*\?>\s*)?<FlexQueryResponse\b/i.test(trimmed)) {
      const canonical = canonicalizeFlexXml(trimmed, {
        requestedFrom: win.fromDate,
        requestedTo: win.toDate,
      });
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
        status: 'VERIFIED_UNDER_WITNESS',
        endpointHost: new URL(IBKR_BASE_URL).hostname,
        ignoredPhase1Url: phase1.ignoredUrl,
        referenceCode: phase1.referenceCode,
        polls: i + 1,
        delaysUsed,
        canonicalSha256: canonical.canonicalSha256,
        canonicalXml: canonical.canonicalXml,
        sectionsPresent: canonical.sectionsPresent,
        f05,
        flags: [...new Set([...canonical.flags, ...f05.flags])],
      };
    }

    const pollError = classifyFlexError(trimmed);
    if (pollError.action === 'REFUSE_LOCKOUT_1025') {
      throw new Error(`REFUSE_LOCKOUT_1025: ${pollError.message}`);
    }
    if (pollError.action === 'REFUSE_PROTOCOL_DOWNGRADE_V2') {
      throw new Error(`REFUSE_PROTOCOL_DOWNGRADE_V2: ${pollError.message}`);
    }
    if (!pollError.retryable) {
      throw new Error(`${pollError.action}: ${pollError.code} ${pollError.message}`);
    }
  }

  throw new Error(
    'REFUSE_AF_GENERATION_TIMEOUT: Statement generation still in progress (1019) after 6 backoff polls (62s); set "Breakout by Day? = No" in Client Portal'
  );
}

export function generateWitnessKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const x = Buffer.from(jwk.x, 'base64url');
  const y = Buffer.from(jwk.y, 'base64url');
  const rawPub = Buffer.concat([Buffer.from([0x04]), x, y]);
  const witnessKeyId = crypto
    .createHash('sha256')
    .update(Buffer.concat([Buffer.from('n170.verify.witness-key.v1\n'), rawPub]))
    .digest('hex');
  const witnessKeyCode = witnessKeyId.slice(0, 20).match(/.{4}/g).join('-');
  return {
    witness_public_key: rawPub.toString('base64url'),
    witness_key_id: witnessKeyId,
    witness_key_code: witnessKeyCode,
    private_key_pkcs8_pem: privateKey.export({ format: 'pem', type: 'pkcs8' }),
  };
}

export function runCli(args) {
  const help =
    'Usage: node scripts/witness-fetch.mjs <keygen|stamp|fetch> [options]\n' +
    'IBKR Flex v3 canonicalizer, Fixture F05 capital flow validator, and witness client.\n';
  if (args.length === 1 && args[0] === '--help') {
    return { exitCode: 0, output: help };
  }
  const sub = args[0];
  if (sub === 'keygen') {
    const kp = generateWitnessKeypair();
    return {
      exitCode: 0,
      output: JSON.stringify({
        witness_public_key: kp.witness_public_key,
        witness_key_id: kp.witness_key_id,
        witness_key_code: kp.witness_key_code,
      }, null, 2) + '\n',
    };
  }
  if (sub === 'stamp') {
    const file = args[1];
    if (!file) return { exitCode: 3, output: JSON.stringify({ status: 'INVALID_INPUT' }) + '\n' };
    try {
      const raw = fs.readFileSync(file, 'utf8');
      if (raw.trim().startsWith('<')) {
        const res = canonicalizeFlexXml(raw);
        const f05 = validateFixtureF05(res.changeInNav, res.cashReportRows, res.corporateActionRows, {
          cashTransactionRows: res.cashTransactionRows,
          dividendAccrualRows: res.dividendAccrualRows,
          accountInfo: res.accountInfo,
        });
        return {
          exitCode: 0,
          output: JSON.stringify({
            status: 'CANONICALIZED',
            format: 'XML',
            canonical_statement_sha256: res.canonicalSha256,
            sections_present: res.sectionsPresent,
            net_external_capital_flows_e8: f05.netExternalCapitalFlowsScaled.toString(),
            economic_investment_return_e8: f05.economicInvestmentReturnScaled.toString(),
            flags: [...new Set([...res.flags, ...f05.flags])],
          }, null, 2) + '\n',
        };
      }
      const res = canonicalizeFlexCsv(raw);
      return {
        exitCode: 0,
        output: JSON.stringify({
          status: 'CANONICALIZED',
          format: 'CSV',
          canonical_statement_sha256: res.canonicalSha256,
          sections_present: res.sectionsPresent,
          flags: res.flags,
        }, null, 2) + '\n',
      };
    } catch (e) {
      return { exitCode: 1, output: JSON.stringify({ status: 'REFUSED', error: e.message }) + '\n' };
    }
  }
  return { exitCode: 3, output: JSON.stringify({ status: 'INVALID_INPUT' }) + '\n' };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const result = runCli(process.argv.slice(2));
  process.stdout.write(result.output);
  process.exitCode = result.exitCode;
}
