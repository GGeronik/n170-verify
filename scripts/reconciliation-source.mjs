// Original independent source reconstruction under the frozen source-checker v1 contract.
// No producer imports, I/O, signing, or binary floating-point monetary arithmetic.

const SCALE = 10n ** 18n;
const UNIT = 100000000n;
const MAX_AMOUNT = 1000000000000000n * SCALE;
const DAY = 86400000;
const CURRENCIES = new Set(['USD', 'EUR', 'GBP', 'CHF', 'CAD', 'AUD', 'JPY']);
const REQUIRED = ['Account ID', 'From Date', 'To Date', 'Starting Value', 'Ending Value',
  'Deposits/Withdrawals', 'Internal Cash Transfers', 'Asset Transfers', 'Linking Adjustments', 'Other'];
const ECONOMIC = ['Mark-to-Market', 'Realized', 'Change in Unrealized', 'Deposits/Withdrawals',
  'Internal Cash Transfers', 'Asset Transfers', 'Dividends', 'Withholding Tax', '871(m) Withholding',
  'Change in Dividend Accruals', 'Interest', 'Change in Interest Accruals', 'Advisor Fees',
  'Client Fees', 'Other Fees', 'Fees Receivable', 'Commissions', 'Commissions Receivable',
  'Forex Commissions', 'Transaction Tax', 'Tax Receivables', 'Sales Tax', 'Soft Dollars',
  'Net Forex Trading', 'Forex Translation', 'Linking Adjustments', 'Other'];
const UNSUPPORTED_CHANGES = ['Internal Cash Transfers', 'Asset Transfers', 'Linking Adjustments', 'Other'];
const N170_MAPPING = [
  { field: 'Observation date', column: 'date' },
  { field: 'Net asset value', column: 'nav' },
  { field: 'External flows', column: 'external_flow' },
];
const IBKR_MAPPING = [
  { field: 'Opening date and NAV', column: 'From Date + Starting Value' },
  { field: 'Closing date and NAV', column: 'To Date + Ending Value' },
  { field: 'external_flow', column: 'Deposits/Withdrawals' },
  { field: 'Reconciliation only', column: 'P&L, dividends, interest, fees, tax and FX components' },
];

function fail(status, code) {
  const error = new Error(code);
  error.status = status;
  error.code = code;
  throw error;
}
const invalid = code => fail('INVALID_INPUT', code);
const unsupported = code => fail('NOT_ASSESSABLE', code);
const headerKey = value => value.toLowerCase().replace(/[^a-z0-9]/g, '');
const absolute = value => value < 0n ? -value : value;
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value)
  && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);

// Lexing is separate from semantic assessment: malformed quoting wins over a
// source-level refusal regardless of which data row contains it.
function readTable(text) {
  if (typeof text !== 'string') invalid('INVALID_SOURCE_TEXT');
  if (Buffer.byteLength(text, 'utf8') > 10 * 1024 * 1024) invalid('SOURCE_SIZE_LIMIT');
  for (const character of text) {
    const point = character.codePointAt(0);
    if (point >= 0xd800 && point <= 0xdfff) invalid('INVALID_SOURCE_ENCODING');
  }
  const input = text.startsWith('\ufeff') ? text.slice(1) : text;
  const firstLine = input.split(/[\r\n]/, 1)[0];
  const tabSeparated = firstLine.includes('\t') && !firstLine.includes(',') && !firstLine.includes(';');
  const separator = firstLine.includes(';') && !firstLine.includes(',') ? ';' : ',';
  const records = [];
  let record = [], cell = '', state = 'bare';
  function endCell() { record.push(cell.trim()); cell = ''; state = 'bare'; }
  function endRecord() {
    endCell();
    if (record.some(value => value !== '')) records.push(record);
    record = [];
    if (records.length > 5001) invalid('SOURCE_ROW_LIMIT');
  }
  for (let i = 0; i < input.length; i += 1) {
    const character = input[i];
    if (state === 'quoted') {
      if (character !== '"') cell += character;
      else if (input[i + 1] === '"') { cell += '"'; i += 1; }
      else state = 'closed';
      continue;
    }
    if (character === '"') {
      if (cell !== '' || state === 'closed') invalid('MALFORMED_CSV_QUOTING');
      state = 'quoted';
    } else if (character === separator) endCell();
    else if (character === '\n' || character === '\r') {
      if (character === '\r' && input[i + 1] === '\n') i += 1;
      endRecord();
    } else if (state === 'closed') {
      if (!/\s/.test(character)) invalid('MALFORMED_CSV_QUOTING');
    } else cell += character;
  }
  if (state === 'quoted') invalid('MALFORMED_CSV_QUOTING');
  if (cell !== '' || record.length || state === 'closed') endRecord();
  if (!records.length) unsupported('MISSING_SOURCE_ROWS');
  const keys = records[0].map(headerKey);
  if (keys.some(value => value === '') || new Set(keys).size !== keys.length) invalid('INVALID_CSV_HEADERS');
  const rows = records.slice(1);
  if (rows.some(row => row.length !== keys.length)) invalid('CSV_COLUMN_COUNT_MISMATCH');
  if (tabSeparated) unsupported('UNSUPPORTED_DELIMITER');
  if (!rows.length) unsupported('MISSING_SOURCE_ROWS');
  return { keys, rows };
}

function money(value, bounded = true) {
  if (typeof value !== 'string') invalid('INVALID_AMOUNT_TYPE');
  if (value === '') unsupported('MISSING_AMOUNT');
  if (value.length > 40) unsupported('AMOUNT_LENGTH_UNSUPPORTED');
  if (!/^-?(?:\d+(?:\.\d*)?|\.\d+)$/.test(value)) unsupported('AMOUNT_FORMAT_UNSUPPORTED');
  const negative = value.startsWith('-');
  const [whole, fraction = ''] = (negative ? value.slice(1) : value).split('.');
  if (fraction.length > 18) unsupported('AMOUNT_PRECISION_UNSUPPORTED');
  const units = BigInt(whole || '0') * SCALE + BigInt(fraction.padEnd(18, '0'));
  if (bounded && units > MAX_AMOUNT) unsupported('AMOUNT_MAGNITUDE_UNSUPPORTED');
  return negative ? -units : units;
}

function date(value) {
  if (typeof value !== 'string') invalid('INVALID_DATE_TYPE');
  const iso = /^\d{8}$/.test(value) ? `${value.slice(0, 4)}-${value.slice(4, 6)}-${value.slice(6)}` : value;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(iso)) unsupported(value ? 'UNSUPPORTED_DATE' : 'MISSING_DATE');
  const milliseconds = Date.parse(iso);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString().slice(0, 10) !== iso) unsupported('UNSUPPORTED_DATE');
  return iso;
}

function priorDate(iso) {
  const result = new Date(Date.parse(iso) - DAY).toISOString().slice(0, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(result)) unsupported('DATE_RANGE_UNSUPPORTED');
  return result;
}

function issues() {
  const found = [];
  return {
    add(status, code) { found.push({ status, code }); },
    attempt(fn) {
      try { return fn(); } catch (error) {
        if (error.status === 'INVALID_INPUT') throw error;
        if (!['NOT_ASSESSABLE', 'MISMATCH'].includes(error.status)) invalid('INVALID_SOURCE_STRUCTURE');
        found.push({ status: error.status, code: error.code });
        return null;
      }
    },
    finish() {
      const selected = found.find(item => item.status === 'MISMATCH') || found[0];
      if (selected) fail(selected.status, selected.code);
    },
  };
}

function validateObservations(rows, findings) {
  if (rows.length > 500) invalid('OBSERVATION_LIMIT');
  if (rows.length < 2) findings.add('NOT_ASSESSABLE', 'INSUFFICIENT_OBSERVATIONS');
  const seen = new Set();
  for (let i = 0; i < rows.length; i += 1) {
    const row = rows[i];
    const normalizedDate = findings.attempt(() => date(row.date));
    if (normalizedDate !== null) row.date = normalizedDate;
    const nav = findings.attempt(() => money(row.nav));
    const flow = findings.attempt(() => money(row.flow));
    if (nav !== null && nav <= 0n) findings.add('NOT_ASSESSABLE', 'NONPOSITIVE_NAV_UNSUPPORTED');
    if (i === 0 && flow !== null && flow !== 0n) findings.add('NOT_ASSESSABLE', 'OPENING_FLOW_UNSUPPORTED');
    if (normalizedDate !== null) {
      if (seen.has(normalizedDate)) findings.add('NOT_ASSESSABLE', 'DUPLICATE_OBSERVATION_DATE');
      seen.add(normalizedDate);
      if (i && normalizedDate <= rows[i - 1].date) findings.add('NOT_ASSESSABLE', 'OBSERVATION_ORDER_UNSUPPORTED');
    }
  }
}

export function reconstructSource(text, options = {}) {
  if (!plain(options) || Object.keys(options).some(key => !['format', 'currency'].includes(key))) invalid('INVALID_SOURCE_OPTIONS');
  const table = readTable(text);
  const { format, currency } = options;
  if (!['n170', 'ibkr-flex'].includes(format)) unsupported('UNSUPPORTED_FORMAT');
  const findings = issues();
  if (!CURRENCIES.has(currency)) findings.add('NOT_ASSESSABLE', 'UNSUPPORTED_CURRENCY');
  const rows = [];
  const at = (row, label) => row[table.keys.indexOf(headerKey(label))];
  let currencyEvidence = 'owner_assertion';
  if (format === 'n170') {
    if (!['date', 'nav', 'externalflow'].every(key => table.keys.includes(key))) unsupported('MISSING_SOURCE_COLUMNS');
    if (table.keys.length !== 3) findings.add('NOT_ASSESSABLE', 'UNKNOWN_SOURCE_COLUMNS');
    table.rows.forEach((row, index) => rows.push({ date: at(row, 'date'), nav: at(row, 'nav'), flow: at(row, 'external_flow'), sourceRow: index + 2 }));
  } else {
    const permitted = new Set([...REQUIRED, ...ECONOMIC, 'Account Alias', 'Model', 'TWR', 'Currency', 'Base Currency'].map(headerKey));
    if (table.keys.some(key => !permitted.has(key))) findings.add('NOT_ASSESSABLE', 'UNKNOWN_SOURCE_COLUMNS');
    const currencies = ['Currency', 'Base Currency'].filter(name => table.keys.includes(headerKey(name)));
    currencyEvidence = currencies.length ? 'source' : 'owner_assertion';
    for (const row of table.rows) for (const name of currencies) {
      if (at(row, name) !== currency) findings.add('MISMATCH', 'SOURCE_CURRENCY_MISMATCH');
    }
    const missing = REQUIRED.some(name => !table.keys.includes(headerKey(name)));
    if (missing) findings.add('NOT_ASSESSABLE', 'MISSING_SOURCE_COLUMNS');
    if (table.keys.includes('marktomarket') && (table.keys.includes('realized') || table.keys.includes('changeinunrealized'))) findings.add('NOT_ASSESSABLE', 'MIXED_PNL_MODES_UNSUPPORTED');
    if (!missing) {
      const accounts = new Set(table.rows.map(row => at(row, 'Account ID')));
      if (accounts.has('') || accounts.size !== 1) findings.add('NOT_ASSESSABLE', 'ACCOUNT_SCOPE_UNSUPPORTED');
      const duplicates = new Set();
      let prior = null;
      const components = ECONOMIC.filter(name => table.keys.includes(headerKey(name)));
      table.rows.forEach((row, index) => {
        const sourceRow = index + 2;
        const signature = JSON.stringify(row);
        if (duplicates.has(signature)) findings.add('NOT_ASSESSABLE', 'DUPLICATE_STATEMENT');
        duplicates.add(signature);
        if (at(row, 'Model')) findings.add('NOT_ASSESSABLE', 'MODEL_SCOPE_UNSUPPORTED');
        const from = findings.attempt(() => date(at(row, 'From Date')));
        const to = findings.attempt(() => date(at(row, 'To Date')));
        // Preserve exact source-bridge contradictions even when an otherwise
        // parseable NAV is outside the later calculation magnitude boundary.
        const before = findings.attempt(() => money(at(row, 'Starting Value'), false));
        const after = findings.attempt(() => money(at(row, 'Ending Value'), false));
        findings.attempt(() => money(at(row, 'Starting Value')));
        findings.attempt(() => money(at(row, 'Ending Value')));
        findings.attempt(() => money(at(row, 'Deposits/Withdrawals')));
        const amounts = components.map(name => findings.attempt(() => money(at(row, name), false)));
        for (const name of UNSUPPORTED_CHANGES) {
          const value = amounts[components.indexOf(name)];
          if (value !== null && value !== 0n) findings.add('NOT_ASSESSABLE', 'UNSUPPORTED_SOURCE_ACTIVITY');
        }
        if (before !== null && after !== null && amounts.every(value => value !== null)
            && before + amounts.reduce((sum, value) => sum + value, 0n) !== after) findings.add('MISMATCH', 'NAV_BRIDGE_MISMATCH');
        if (from !== null && to !== null) {
          const openingDate = findings.attempt(() => priorDate(from));
          if (from > to || (prior && from <= prior.to)) findings.add('NOT_ASSESSABLE', 'OVERLAPPING_STATEMENTS');
          if (prior && openingDate !== prior.to) findings.add('NOT_ASSESSABLE', 'MISSING_STATEMENT_PERIOD');
          if (prior && before !== null && prior.after !== null && before !== prior.after) findings.add('MISMATCH', 'NAV_CONTINUITY_MISMATCH');
          if (index === 0 && openingDate !== null) rows.push({ date: openingDate, nav: at(row, 'Starting Value'), flow: '0', sourceRow });
          rows.push({ date: to, nav: at(row, 'Ending Value'), flow: at(row, 'Deposits/Withdrawals'), sourceRow });
          prior = { to, after };
        }
      });
    }
  }
  validateObservations(rows, findings);
  findings.finish();
  return {
    normalizedCsv: 'date,nav,external_flow\n' + rows.map(row => `${row.date},${row.nav},${row.flow}`).join('\n'),
    rows, mapping: (format === 'n170' ? N170_MAPPING : IBKR_MAPPING).map(item => ({ ...item })),
    sourceRows: table.rows.length, currencyEvidence,
  };
}

function decimal(units) {
  const sign = units < 0n ? '-' : '';
  const magnitude = absolute(units);
  const fraction = (magnitude % SCALE).toString().padStart(18, '0').replace(/0+$/, '');
  return `${sign}${magnitude / SCALE}${fraction ? '.' + fraction : ''}`;
}

function nearest(numerator, denominator) {
  let floor = numerator / denominator;
  if (numerator < 0n && numerator % denominator !== 0n) floor -= 1n;
  return floor + (2n * (numerator - floor * denominator) >= denominator ? 1n : 0n);
}

function gcd(a, b) {
  while (b !== 0n) { const remainder = a % b; a = b; b = remainder; }
  return a;
}

export function calculateIntervals(inputRows) {
  if (!Array.isArray(inputRows)) invalid('INVALID_OBSERVATION_STRUCTURE');
  if (inputRows.length > 500) invalid('OBSERVATION_LIMIT');
  const rows = inputRows.map(row => {
    if (!plain(row) || Object.keys(row).sort().join(',') !== 'date,flow,nav,sourceRow'
        || !Number.isSafeInteger(row.sourceRow) || row.sourceRow < 2 || row.sourceRow > 5001
        || typeof row.date !== 'string' || typeof row.nav !== 'string' || typeof row.flow !== 'string') invalid('INVALID_OBSERVATION_STRUCTURE');
    return { ...row };
  });
  const findings = issues();
  validateObservations(rows, findings);
  findings.finish();
  const intervals = [], relative_returns = [];
  let wealthNumerator = 1n, wealthDenominator = 1n, flowCount = 0;
  for (let i = 1; i < rows.length; i += 1) {
    const opening = money(rows[i - 1].nav), closing = money(rows[i].nav), flow = money(rows[i].flow);
    const adjusted = closing - flow;
    if (adjusted <= 0n) unsupported('NONPOSITIVE_ADJUSTED_NAV_UNSUPPORTED');
    const returnUnits = nearest((adjusted - opening) * UNIT, opening);
    const gross = UNIT + returnUnits;
    if (gross <= 0n || gross > 10000n * UNIT) unsupported('RETURN_RANGE_UNSUPPORTED');
    if (absolute(gross * opening - adjusted * UNIT) * 10000000n > adjusted * UNIT) unsupported('RETURN_QUANTIZATION_UNSUPPORTED');
    wealthNumerator *= gross;
    wealthDenominator *= UNIT;
    const divisor = gcd(wealthNumerator, wealthDenominator);
    wealthNumerator /= divisor; wealthDenominator /= divisor;
    if (wealthNumerator * 1000000n < wealthDenominator || wealthNumerator > wealthDenominator * 1000000n) unsupported('CUMULATIVE_WEALTH_UNSUPPORTED');
    const return_e8 = Number(returnUnits);
    if (!Number.isSafeInteger(return_e8)) unsupported('NUMERICAL_SUPPORT_EXCEEDED');
    const start = rows[i - 1].date, end = rows[i].date;
    relative_returns.push({ start, end, return_e8 });
    if (flow !== 0n) flowCount += 1;
    intervals.push({ start, end, duration_days: (Date.parse(end) - Date.parse(start)) / DAY,
      opening_nav: rows[i - 1].nav, closing_nav: rows[i].nav, external_flow: rows[i].flow,
      adjusted_closing_nav: decimal(adjusted), economic_change: decimal(adjusted - opening),
      flow_kind: flow > 0n ? 'deposit' : flow < 0n ? 'withdrawal' : 'net_zero', return_e8 });
  }
  return { period: { start: rows[0].date, end: rows.at(-1).date }, relative_returns,
    coverage: { nav_observations: rows.length, return_observations: intervals.length, external_cash_flow_count: flowCount }, intervals };
}
