// Original independent browser arithmetic. Imported data is never executed.
// Ledger operations use scaled BigInt; native replay uses Number only at the
// explicit binary64 conversion, subtraction, and addition boundaries.
export const NATIVE_POLICY = 'freqtrade-2026.8-cpython3147-serial-round8.v1';
export const METRICS = ['cash', 'quantity', 'cost_basis', 'fees', 'realized_pnl', 'unrealized_pnl', 'external_flows', 'net_pnl', 'nav'];
const Q = 100000000n, M = 10000000000000000000n;
const abs = n => n < 0n ? -n : n;
const own = (v, k) => Object.hasOwn(v, k);
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const require = (v, code) => { if (!v) throw new Error(code); };
const gcd = (a, b) => { a = abs(a); while (b) [a, b] = [b, a % b]; return a || 1n; };
function rational(n, d = 1n) { require(d > 0n, 'INVALID_RATIONAL'); const g = gcd(n, d); return { n: n / g, d: d / g }; }
function publicRational(value) { return { numerator: value.n.toString(), denominator: value.d.toString() }; }
function subtract(a, b) { return rational(a.n * b.d - b.n * a.d, a.d * b.d); }
function keys(value, required, optional = []) {
  require(object(value) && required.every(k => own(value, k)) && Object.keys(value).every(k => [...required, ...optional].includes(k)), 'UNSUPPORTED_FIELDS');
}
function decimal(value, scale, magnitude, sign = 'any') {
  require(typeof value === 'string' && value.length <= 96 && /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/.test(value), 'INVALID_DECIMAL');
  const negative = value.startsWith('-'); const [whole, fraction = ''] = value.replace(/^-/, '').split('.');
  require(fraction.length <= scale, 'UNSUPPORTED_PRECISION');
  const amount = (BigInt(whole) * 10n ** BigInt(scale) + BigInt((fraction || '0').padEnd(scale, '0'))) * (negative ? -1n : 1n);
  require(abs(amount) <= magnitude * 10n ** BigInt(scale), 'UNSUPPORTED_MAGNITUDE');
  require(sign !== 'positive' || amount > 0n, 'INVALID_AMOUNT_SIGN');
  require(sign !== 'nonnegative' || amount >= 0n, 'INVALID_AMOUNT_SIGN');
  return amount;
}
export function textDecimal(value, scale = 19) {
  if (value === 0n) return '0';
  const digits = abs(value).toString().padStart(scale + 1, '0');
  const result = scale ? (digits.slice(0, -scale) + '.' + digits.slice(-scale)).replace(/0+$/, '').replace(/\.$/, '') : digits;
  return (value < 0n ? '-' : '') + result;
}
export function exactDecimal(value, kind = 'operand') {
  const settings = { operand: [8, 10n ** 12n], fee: [19, 10n ** 21n], result: [19, 10n ** 30n] }[kind];
  require(settings, 'UNSUPPORTED_NUMERIC_DOMAIN');
  return textDecimal(decimal(value, ...settings), settings[0]);
}
function decimalRational(value) {
  require(typeof value === 'string' && value.length <= 128, 'INVALID_NATIVE_SPELLING');
  const match = /^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]{1,3}))?$/.exec(value);
  require(match, 'INVALID_NATIVE_SPELLING');
  const exponent = Number(match[4] || '0') - (match[3]?.length || 0);
  require(Math.abs(exponent) <= 450, 'NATIVE_EXPONENT_LIMIT');
  const n = BigInt(match[2] + (match[3] || '')) * (match[1] ? -1n : 1n);
  return exponent >= 0 ? rational(n * 10n ** BigInt(exponent)) : rational(n, 10n ** BigInt(-exponent));
}
export function rationalDecimal(value) {
  let { n, d } = typeof value.n === 'bigint' ? value : rational(BigInt(value.numerator), BigInt(value.denominator));
  const negative = n < 0n; n = abs(n); let twos = 0, fives = 0;
  while (d % 2n === 0n) { d /= 2n; twos++; }
  while (d % 5n === 0n) { d /= 5n; fives++; }
  require(d === 1n && Math.max(twos, fives) <= 1200, 'NONTERMINATING_DECIMAL');
  const scale = Math.max(twos, fives);
  return textDecimal(n * 2n ** BigInt(scale - twos) * 5n ** BigInt(scale - fives) * (negative ? -1n : 1n), scale);
}
export function expandNativeDecimal(value) { return rationalDecimal(decimalRational(value)); }

const buffer = new ArrayBuffer(8), view = new DataView(buffer);
export function numberHex(value) {
  require(typeof value === 'number' && Number.isFinite(value), 'NONFINITE_NATIVE');
  view.setFloat64(0, value, false); const bits = view.getBigUint64(0, false);
  const sign = bits >> 63n ? '-' : ''; const exponent = Number((bits >> 52n) & 2047n); const fraction = bits & ((1n << 52n) - 1n);
  if (exponent === 0 && fraction === 0n) return sign + '0x0.0p+0';
  const power = exponent === 0 ? -1022 : exponent - 1023;
  return `${sign}0x${exponent === 0 ? '0' : '1'}.${fraction.toString(16).padStart(13, '0')}p${power >= 0 ? '+' : ''}${power}`;
}
export function canonicalNativeRepr(value) {
  require(typeof value === 'number' && Number.isFinite(value), 'NONFINITE_NATIVE');
  if (value === 0) return Object.is(value, -0) ? '-0.0' : '0.0';
  const sign = value < 0 ? '-' : '', match = /^(\d+)(?:\.(\d+))?(?:e([+-]?\d+))?$/.exec(String(Math.abs(value)));
  const untrimmed = match[1] + (match[2] || '');
  const leading = untrimmed.search(/[1-9]/), exponent = match[1].length + Number(match[3] || 0) - leading - 1;
  const digits = untrimmed.slice(leading).replace(/0+$/, '');
  if (exponent < -4 || exponent >= 16) return sign + digits[0] + (digits.length > 1 ? '.' + digits.slice(1) : '')
    + 'e' + (exponent < 0 ? '-' : '+') + String(Math.abs(exponent)).padStart(2, '0');
  if (exponent < 0) return sign + '0.' + '0'.repeat(-exponent - 1) + digits;
  if (digits.length <= exponent + 1) return sign + digits.padEnd(exponent + 1, '0') + '.0';
  return sign + digits.slice(0, exponent + 1) + '.' + digits.slice(exponent + 1);
}
export function decodeBinary64(input) {
  if (typeof input === 'number') require(Number.isSafeInteger(input) && !Object.is(input, -0), 'INVALID_NATIVE_INTEGER');
  if (object(input)) { keys(input, ['encoding', 'repr', 'hex']); require(input.encoding === 'binary64', 'UNSUPPORTED_NATIVE_ENCODING'); }
  const hex = typeof input === 'number' ? numberHex(input) : typeof input === 'string' ? input : input?.hex;
  require(typeof hex === 'string' && hex.length <= 32, 'INVALID_BINARY64_HEX');
  const match = /^(-?)0x([01])\.([0-9a-f]{13}|0)p([+-][0-9]{1,4})$/.exec(hex);
  require(match, 'INVALID_BINARY64_HEX');
  const power = Number(match[4]); const negative = Boolean(match[1]);
  let bits;
  if (match[3] === '0') { require(match[2] === '0' && power === 0, 'INVALID_BINARY64_HEX'); bits = 0n; }
  else {
    require(power >= -1022 && power <= 1023 && (match[2] === '1' || power === -1022), 'INVALID_BINARY64_HEX');
    const fraction = BigInt('0x' + match[3]); const exponent = match[2] === '0' ? 0 : power + 1023;
    bits = (BigInt(exponent) << 52n) | fraction;
  }
  if (negative) bits |= 1n << 63n;
  view.setBigUint64(0, bits, false); const number = view.getFloat64(0, false);
  require(Number.isFinite(number) && numberHex(number) === hex, 'NONCANONICAL_BINARY64_HEX');
  const exponent = Number((bits >> 52n) & 2047n); const fraction = bits & ((1n << 52n) - 1n);
  const significand = (exponent ? 1n << 52n : 0n) + fraction;
  const shift = (exponent ? exponent - 1023 : -1022) - 52;
  const exact = shift >= 0 ? rational(significand << BigInt(shift)) : rational(significand, 1n << BigInt(-shift));
  if (negative) exact.n = -exact.n;
  if (object(input)) {
    const repr = input.repr; const spelling = decimalRational(repr);
    require(Number.isFinite(Number(repr)) && numberHex(Number(repr)) === hex && !(spelling.n !== 0n && number === 0), 'NATIVE_REPR_HEX_MISMATCH');
    // Decimal operand provenance matters in addition to binary identity. A
    // longer decimal can map to the same float while changing modeled fees.
    // Accept formatting differences only when the exact decimal is identical
    // to the browser's shortest round-trip spelling. Any Python/ECMAScript
    // shortest-spelling tie disagreement is explicitly outside this policy.
    const shortest = decimalRational(String(number));
    require(spelling.n * shortest.d === shortest.n * spelling.d, 'UNSUPPORTED_NATIVE_SPELLING');
    require(repr === canonicalNativeRepr(number), 'NONCANONICAL_NATIVE_REPR');
  }
  return { number, hex, negative_zero: Object.is(number, -0), exact: publicRational(exact), exact_decimal: rationalDecimal(exact) };
}
export function roundBinary64ToDecimal8(value) {
  const decoded = decodeBinary64(typeof value === 'number' ? numberHex(value) : value);
  const n = BigInt(decoded.exact.numerator), d = BigInt(decoded.exact.denominator);
  const scaled = abs(n) * Q; let result = scaled / d; const remainder = scaled % d;
  if (remainder * 2n > d || (remainder * 2n === d && result % 2n === 1n)) result++;
  const negative = n < 0n || decoded.negative_zero;
  const decimal = result === 0n && negative ? '-0' : textDecimal(negative ? -result : result, 8);
  const number = Number(decimal);
  require(Number.isFinite(number), 'NONFINITE_NATIVE');
  return { decimal, number, hex: numberHex(number) };
}
export function compareNativeMetric(captured, modeled) {
  const native = decodeBinary64(captured), exact = rational(BigInt(native.exact.numerator), BigInt(native.exact.denominator));
  const target = decimalRational(modeled); const binaryDifference = subtract(exact, target);
  const repr = typeof captured === 'number' ? String(captured) : captured.repr;
  const printedDifference = subtract(decimalRational(repr), target);
  return { exact_decimal_equal: binaryDifference.n === 0n, native_hex: native.hex, native_repr: repr,
    native_exact: native.exact, exact_binary_difference: publicRational(binaryDifference),
    exact_binary_difference_decimal: rationalDecimal(binaryDifference), display_decimal_difference: rationalDecimal(printedDifference), negative_zero: native.negative_zero };
}
function timestamp(value) {
  require(typeof value === 'string' && /^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$/.test(value), 'INVALID_TIMESTAMP');
  const match = /^(.*?)(?:\.([0-9]+))?Z$/.exec(value); const millis = Date.parse(match[1] + 'Z');
  require(Number.isFinite(millis) && new Date(millis).toISOString().slice(0, 19) === match[1], 'INVALID_TIMESTAMP');
  return BigInt(millis) * 1000n + BigInt((match[2] || '').padEnd(6, '0') || '0');
}
function reason(error) { return /^[A-Z][A-Z0-9_]+$/.test(error?.message || '') ? error.message : 'INVALID_ACCOUNTING_INPUT'; }

export function computeExactLedger(document) {
  const report = { schema: 'n170.accounting.reconciliation.v2', status: 'NOT_ASSESSABLE', computed: null, event_checkpoints: [], checks: {}, reason_codes: [],
    source_authenticity: 'not_established', selected_source_completeness: 'unknown', oracle: { status: 'NOT_RUN' } };
  try {
    keys(document, ['schema', 'evidence_class', 'asset', 'cash_currency', 'opening', 'events', 'closing']);
    require(document.schema === 'n170.accounting.events.v2', 'UNSUPPORTED_ACCOUNTING_SCHEMA');
    require(['synthetic_fixture', 'supplied_events'].includes(document.evidence_class), 'UNSUPPORTED_EVIDENCE_CLASS');
    require(document.asset === 'BTC' && document.cash_currency === 'USDT', 'UNSUPPORTED_COMMODITIES');
    keys(document.opening, ['timestamp', 'cash']); keys(document.closing, ['timestamp', 'mark_price', 'reported']);
    keys(document.closing.reported, [], METRICS);
    const start = timestamp(document.opening.timestamp), end = timestamp(document.closing.timestamp); require(end > start, 'INVALID_PERIOD');
    const opening = decimal(document.opening.cash, 8, 10n ** 12n, 'nonnegative') * (M / Q);
    const mark = decimal(document.closing.mark_price, 8, 10n ** 12n, 'nonnegative');
    require(Array.isArray(document.events) && document.events.length <= 10000, 'INVALID_EVENT_COUNT');
    let cash = opening, quantity = 0n, fees = 0n, realized = 0n, flows = 0n, last = start;
    const lots = [], ids = new Set(); let head = 0;
    const basis = () => lots.slice(head).reduce((sum, lot) => sum + lot.quantity * lot.price * 1000n, 0n);
    for (const event of document.events) {
      require(object(event) && typeof event.event_id === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(event.event_id), 'INVALID_EVENT_ID');
      require(!ids.has(event.event_id), 'DUPLICATE_EVENT'); ids.add(event.event_id);
      const instant = timestamp(event.timestamp); require(instant >= last && instant <= end, 'EVENT_CHRONOLOGY_MISMATCH'); last = instant;
      if (['BUY', 'SELL'].includes(event.type)) {
        keys(event, ['event_id', 'timestamp', 'type', 'quantity', 'price', 'fee', 'fee_currency', 'fee_model']);
        const q = decimal(event.quantity, 8, 10n ** 12n, 'positive'), p = decimal(event.price, 8, 10n ** 12n, 'positive');
        const fee = decimal(event.fee, 19, 10n ** 21n, 'nonnegative');
        keys(event.fee_model, ['kind', 'quantity', 'price', 'rate', 'sources']);
        require(event.fee_currency === 'USDT' && event.fee_model.kind === 'modeled_fee'
          && event.fee_model.quantity === event.quantity && event.fee_model.price === event.price && event.fee_model.rate === '0.001', 'UNSUPPORTED_FEE_MODEL');
        require(Array.isArray(event.fee_model.sources) && event.fee_model.sources.length >= 1 && event.fee_model.sources.length <= 16
          && event.fee_model.sources.every(v => typeof v === 'string' && v.length > 0 && v.length <= 256), 'INVALID_FEE_SOURCE');
        require(fee === q * p, 'MODELED_FEE_MISMATCH');
        const notional = q * p * 1000n; fees += fee;
        if (event.type === 'BUY') { cash -= notional + fee; quantity += q; lots.push({ quantity: q, price: p }); }
        else {
          require(q <= quantity, 'OVERSELL'); cash += notional - fee; quantity -= q; let remaining = q, disposed = 0n;
          while (remaining > 0n) { const lot = lots[head]; const take = lot.quantity < remaining ? lot.quantity : remaining;
            disposed += take * lot.price * 1000n; lot.quantity -= take; remaining -= take; if (lot.quantity === 0n) head++; }
          realized += notional - disposed;
        }
      } else {
        keys(event, ['event_id', 'timestamp', 'type', 'amount']); require(['DEPOSIT', 'WITHDRAWAL'].includes(event.type), 'UNSUPPORTED_EVENT');
        const amount = decimal(event.amount, 8, 10n ** 12n, 'positive') * (M / Q) * (event.type === 'DEPOSIT' ? 1n : -1n);
        cash += amount; flows += amount;
      }
      require(cash >= 0n, 'NEGATIVE_CASH');
      report.event_checkpoints.push({ event_id: event.event_id, cash: textDecimal(cash), quantity: textDecimal(quantity, 8),
        fifo_cost_basis: textDecimal(basis()), gross_realized_pnl: textDecimal(realized), fees: textDecimal(fees) });
    }
    const cost = basis(), marketValue = quantity * mark * 1000n, nav = cash + marketValue;
    const values = { cash, quantity: quantity * (M / Q), cost_basis: cost, fees, realized_pnl: realized,
      unrealized_pnl: marketValue - cost, external_flows: flows, net_pnl: nav - opening - flows, nav };
    require(values.net_pnl === values.realized_pnl + values.unrealized_pnl - fees, 'ACCOUNTING_IDENTITY_MISMATCH');
    require(Object.values(values).every(v => abs(v) <= 10n ** 30n * M), 'RESULT_MAGNITUDE_LIMIT');
    report.computed = Object.fromEntries(Object.entries(values).map(([key, value]) => [key, textDecimal(value)]));
    let missing = false, mismatch = false;
    for (const name of METRICS) {
      if (!own(document.closing.reported, name)) { missing = true; report.checks[name] = { status: 'NOT_SUPPLIED', computed: report.computed[name] }; }
      else {
        const declared = decimal(document.closing.reported[name], 19, 10n ** 30n); const difference = values[name] - declared;
        mismatch ||= difference !== 0n;
        report.checks[name] = { status: difference === 0n ? 'MATCH' : 'DISCREPANCY', computed: report.computed[name], reported: textDecimal(declared), difference_reported_minus_computed: textDecimal(-difference) };
      }
    }
    report.status = mismatch ? 'DISCREPANCIES_FOUND' : missing ? 'NOT_ASSESSABLE' : 'RECONCILED_UNDER_ASSUMPTIONS';
    report.reason_codes = [...(mismatch ? ['EXACT_DECIMAL_DIFFERENCE'] : []), ...(missing ? ['MISSING_REPORTED_METRICS'] : []), ...(!missing && !mismatch ? ['EXACT_DECIMAL_MATCH'] : [])];
  } catch (error) { report.reason_codes = [reason(error)]; report.computed = null; report.event_checkpoints = []; report.checks = {}; }
  return report;
}

// This fixed ledger is generated from validated events, never from supplied
// oracle text. All arithmetic stays scaled and no native rounded claim becomes
// an assertion in the independent exact-decimal ledger.
export function generateOracleLedger(document) {
  require(computeExactLedger(document).computed !== null, 'SUPPORTED_ACCOUNTING_INPUT_REQUIRED');
  const start = document.opening.timestamp.slice(0, 10), end = document.closing.timestamp.slice(0, 10);
  const opening = decimal(document.opening.cash, 8, 10n ** 12n);
  const lines = ['; Original exact modeled ledger. Native float claims are not assertions.',
    'option "tolerance_multiplier" "0"', 'option "infer_tolerance_from_cost" "FALSE"',
    `${start} open Assets:Cash USDT`, `${start} open Assets:Position BTC "FIFO"`,
    ...['Equity:Opening', 'Equity:Flows', 'Expenses:Fees', 'Income:Trading'].map(name => `${start} open ${name} USDT`),
    `${start} * "Opening cash"`, `  Assets:Cash ${textDecimal(opening, 8)} USDT`, `  Equity:Opening ${textDecimal(-opening, 8)} USDT`];
  for (const [index, event] of document.events.entries()) {
    lines.push(`${event.timestamp.slice(0, 10)} * "Event ${index + 1}"`);
    if (['DEPOSIT', 'WITHDRAWAL'].includes(event.type)) {
      const amount = decimal(event.amount, 8, 10n ** 12n) * (event.type === 'DEPOSIT' ? 1n : -1n);
      lines.push(`  Assets:Cash ${textDecimal(amount, 8)} USDT`, `  Equity:Flows ${textDecimal(-amount, 8)} USDT`);
    } else {
      const q = decimal(event.quantity, 8, 10n ** 12n), p = decimal(event.price, 8, 10n ** 12n), fee = decimal(event.fee, 19, 10n ** 21n);
      const notional = q * p * 1000n;
      if (event.type === 'BUY') lines.push(`  Assets:Position ${textDecimal(q, 8)} BTC {${textDecimal(p, 8)} USDT, "event-${index + 1}"}`,
        `  Assets:Cash ${textDecimal(-notional - fee)} USDT`, `  Expenses:Fees ${textDecimal(fee)} USDT`);
      else lines.push(`  Assets:Position ${textDecimal(-q, 8)} BTC {} @ ${textDecimal(p, 8)} USDT`,
        `  Assets:Cash ${textDecimal(notional - fee)} USDT`, `  Expenses:Fees ${textDecimal(fee)} USDT`, '  Income:Trading');
    }
  }
  lines.push(`${end} price BTC ${exactDecimal(document.closing.mark_price)} USDT`);
  return lines.join('\n') + '\n';
}

export function replayNativeClosedTrades(input) {
  const report = { policy: NATIVE_POLICY, status: 'NOT_ASSESSABLE', trades: [], metrics: {}, reason_codes: [] };
  try {
    const runtime = input.runtime;
    require(object(runtime) && /^sha256:[a-f0-9]{64}$/.test(runtime.image_id) && runtime.engine_revision === '9f10e357a93c1dcf10c2a2b367659214d89c073e'
      && runtime.image_reference === 'freqtradeorg/freqtrade@sha256:289f403917e170ecced1f3c537a2580435a581f2b21311c488c4efcb1694f666'
      && runtime.engine_source_sha256 === 'a96f980268301b69f8fb6e423d27606ede3f174449f63ff672aebb48f97ac6de'
      && runtime.python === '3.14.7' && runtime.ccxt === '4.5.76' && runtime.numpy === '2.4.6'
      && runtime.precise_sha256 === '445721221b65f37cc198adaeec26f68b214926e82ea2bfc0195a346ec94773ed', 'UNSUPPORTED_NATIVE_RUNTIME');
    const opening = decimal(input.opening_cash, 8, 10n ** 12n, 'nonnegative');
    require(Array.isArray(input.trades) && input.trades.length > 0 && input.trades.length <= 5000, 'INVALID_NATIVE_TRADE_COUNT');
    let total = 0; let mismatch = false, missing = false; const seen = new Set();
    for (const trade of input.trades) {
      require(typeof trade.trade_id === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(trade.trade_id) && !seen.has(trade.trade_id), 'INVALID_NATIVE_CLOSE_ORDER'); seen.add(trade.trade_id);
      const q0 = decimal(trade.entry_quantity, 8, 10n ** 12n, 'positive'), q1 = decimal(trade.exit_quantity, 8, 10n ** 12n, 'positive');
      const p0 = decimal(trade.entry_price, 8, 10n ** 12n, 'positive'), p1 = decimal(trade.exit_price, 8, 10n ** 12n, 'positive');
      require(q0 === q1 && trade.fee_rate === '0.001', 'UNSUPPORTED_NATIVE_TRADE');
      const openLeg = q0 * p0 * 1001n, closeLeg = q1 * p1 * 999n;
      const openNumber = Number(textDecimal(openLeg)), closeNumber = Number(textDecimal(closeLeg));
      const difference = closeNumber - openNumber, rounded = roundBinary64ToDecimal8(difference);
      const profit = 0 + rounded.number; const before = total; total += profit;
      require(Number.isFinite(total), 'NONFINITE_NATIVE');
      const expectedHex = numberHex(profit); let status = 'NOT_SUPPLIED';
      if (trade.native_profit == null) missing = true;
      else { status = decodeBinary64(trade.native_profit).hex === expectedHex ? 'MATCHES_ENGINE_NUMERIC_POLICY' : 'MISMATCH'; mismatch ||= status === 'MISMATCH'; }
      report.trades.push({ trade_id: trade.trade_id, status, entry_leg_decimal: textDecimal(openLeg), exit_leg_decimal: textDecimal(closeLeg),
        entry_leg_hex: numberHex(openNumber), exit_leg_hex: numberHex(closeNumber), subtraction_hex: numberHex(difference),
        rounded_decimal: rounded.decimal, expected_profit_hex: expectedHex, total_before_hex: numberHex(before), total_after_hex: numberHex(total) });
    }
    const cash = Number(textDecimal(opening, 8)) + total;
    for (const [name, expected, supplied] of [['total_profit', total, input.native_total_profit], ['cash', cash, input.native_cash]]) {
      let status = 'NOT_SUPPLIED';
      if (supplied == null) missing = true;
      else { status = decodeBinary64(supplied).hex === numberHex(expected) ? 'MATCHES_ENGINE_NUMERIC_POLICY' : 'MISMATCH'; mismatch ||= status === 'MISMATCH'; }
      report.metrics[name] = { status, expected_hex: numberHex(expected), supplied_hex: supplied?.hex ?? null };
    }
    report.status = mismatch ? 'MISMATCH' : missing ? 'NOT_ASSESSABLE' : 'MATCHES_ENGINE_NUMERIC_POLICY';
    report.reason_codes = [...(mismatch ? ['NATIVE_BINARY64_REPLAY_MISMATCH'] : []), ...(missing ? ['MISSING_NATIVE_METRICS'] : []), ...(!missing && !mismatch ? ['STRICT_BINARY64_REPLAY_MATCH'] : [])];
  } catch (error) { report.status = 'NOT_ASSESSABLE'; report.reason_codes = [reason(error)]; }
  return report;
}
