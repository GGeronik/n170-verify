import { verifyRunReview as verifyRunReviewV1 } from './runReview.js';
import { computeExactLedger, decodeBinary64, expandNativeDecimal, exactDecimal, replayNativeClosedTrades, compareNativeMetric, numberHex, roundBinary64ToDecimal8, generateOracleLedger, METRICS } from './accountingExact.js';
// Original Apache-2.0 independent recipient verifier. This module processes data
// only: no execution, imports of supplied code, network, extraction, or storage.
export const RUN_REVIEW_MAX_BYTES = 96 * 1024 * 1024;
export const RUN_REVIEW_V2_SCHEMA = 'n170.run-review.v2';
const MiB = 1024 * 1024;
const REVISION = '9f10e357a93c1dcf10c2a2b367659214d89c073e';
const SOURCE_HASH = 'a96f980268301b69f8fb6e423d27606ede3f174449f63ff672aebb48f97ac6de';
const ASSESSABLE = ['NO_FINDINGS_REPORTED', 'FINDINGS_REPORTED'];
const OUTCOMES = [...ASSESSABLE, 'INSUFFICIENT', 'FAILED', 'TIMED_OUT', 'CANCELLED', 'SKIPPED', 'MISSING_OUTPUT', 'INVALID_OUTPUT', 'INPUT_CHANGED'];
const OUTPUTS = ['baseline-capture.json', 'effective-config.json', 'lookahead.csv', 'market-metadata.json', 'worker-result.json'];
const ORACLE_FILES = ['events.json', 'ledger.beancount', 'oracle-worker.py', 'oracle.stdout.json', 'oracle.stderr.txt', 'report.json'];
const ORACLE_REVISION = '9747213802acb733ce53acc6e963f5961f47d6cd';
const ORACLE_INVENTORY_HASH = 'e8613933996e605176913722520851dc65b61f479a94f5da0589facb9a829bc9';
const ORACLE_WORKER_HASH = 'c29a55d4f320a23c07e2240fbb69e555612e1868a12b24adb3fee92daf5d120c';
const TRUST = Object.freeze({
  execution: 'local_runner_receipt; recipient has not witnessed execution',
  authenticity: 'unsigned; no broker, publisher, hardware or remote execution authentication',
  completeness: 'selected attempts only; previous trials and omitted strategy families unknown',
  reproduction: 'not established by integrity verification; independently rerun the captured inputs',
  detector_coverage: 'exercised Freqtrade lookahead signals only; no profitability, fill realism or absence-of-bias guarantee',
});
const REPORT_TRUST = Object.freeze({ ...TRUST,
  integrity: 'consistency of supplied manifest and artifact bytes only; attacker-authored receipts can be self-consistent',
  identity: 'not established; a digest pin authenticates no producer or delivery channel',
  scope: 'synthetic BTC/USDT spot metadata; single pair; five-minute candles; pinned Freqtrade 2026.8 lookahead method',
  import: 'data only; no imported code, command or file is executed or extracted',
});
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const check = (value, code = 'INVALID_OR_INCOMPLETE_RUN_BUNDLE') => { if (!value) throw new Error(code); };
const own = (value, key) => Object.hasOwn(value, key);
const integer = (v, min = 0, max = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(v) && !Object.is(v, -0) && v >= min && v <= max;
const hash = v => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const string = (v, max = 8192) => typeof v === 'string' && v.length > 0 && v.length <= max;
function shape(value, required, optional = []) {
  check(isObject(value) && required.every(key => own(value, key)));
  const allowed = new Set([...required, ...optional]);
  check(Object.keys(value).every(key => allowed.has(key)));
}
function same(a, b) {
  if (a === b) return true;
  if (Array.isArray(a)) return Array.isArray(b) && a.length === b.length && a.every((item, i) => same(item, b[i]));
  if (!isObject(a) || !isObject(b)) return false;
  const keys = Object.keys(a);
  return keys.length === Object.keys(b).length && keys.every(key => own(b, key) && same(a[key], b[key]));
}
function unicode(value) {
  for (let i = 0; i < value.length; i++) {
    const n = value.charCodeAt(i);
    if (n >= 0xd800 && n <= 0xdbff) { const next = value.charCodeAt(++i); check(next >= 0xdc00 && next <= 0xdfff, 'INVALID_JSON'); }
    else check(n < 0xdc00 || n > 0xdfff, 'INVALID_JSON');
  }
}

// Parse original tokens, including decoded object keys. JSON.parse alone loses
// duplicate keys and may round an unsafe integer before it can be checked.
function strictJson(text, maxBytes, envelope = false) {
  check(typeof text === 'string' && text.length > 0 && text.length <= maxBytes, 'JSON_LIMIT_EXCEEDED');
  unicode(text);
  check(encoder.encode(text).length <= maxBytes, 'JSON_LIMIT_EXCEEDED');
  let pos = 0; let nodes = 0;
  const whitespace = () => { while (pos < text.length && /[\x20\t\r\n]/.test(text[pos])) pos++; };
  const tokenString = (large = false) => {
    check(text[pos] === '"', 'INVALID_JSON');
    const start = pos++;
    while (pos < text.length) {
      const ch = text[pos++];
      if (ch === '\\') { pos++; continue; }
      if (ch === '"') {
        const value = JSON.parse(text.slice(start, pos));
        check(large || (value.length <= 4 * MiB && encoder.encode(value).length <= 4 * MiB), 'JSON_LIMIT_EXCEEDED');
        unicode(value);
        return value;
      }
    }
    check(false, 'INVALID_JSON');
  };
  function parse(depth, largeString = false) {
    check(depth <= 24 && ++nodes <= 200_000, 'JSON_LIMIT_EXCEEDED');
    whitespace();
    if (text[pos] === '"') return tokenString(largeString);
    if (text[pos] === '{') {
      pos++; whitespace();
      const result = Object.create(null);
      if (text[pos] === '}') { pos++; return result; }
      while (true) {
        whitespace(); check(++nodes <= 200_000, 'JSON_LIMIT_EXCEEDED');
        const key = tokenString();
        check(!own(result, key) && !['__proto__', 'constructor', 'prototype'].includes(key), 'INVALID_JSON');
        whitespace(); check(text[pos++] === ':', 'INVALID_JSON');
        result[key] = parse(depth + 1, envelope && key === 'base64');
        whitespace(); if (text[pos] === '}') { pos++; return result; }
        check(text[pos++] === ',', 'INVALID_JSON');
      }
    }
    if (text[pos] === '[') {
      pos++; whitespace();
      const result = [];
      if (text[pos] === ']') { pos++; return result; }
      while (true) {
        result.push(parse(depth + 1)); whitespace();
        if (text[pos] === ']') { pos++; return result; }
        check(text[pos++] === ',', 'INVALID_JSON');
      }
    }
    const match = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(pos));
    check(match, 'INVALID_JSON'); pos += match[0].length;
    const value = JSON.parse(match[0]);
    if (typeof value === 'number') check(Number.isFinite(value) && (!Number.isInteger(value) || Number.isSafeInteger(value)) && !Object.is(value, -0), 'INVALID_JSON');
    return value;
  }
  const result = parse(0); whitespace(); check(pos === text.length, 'INVALID_JSON');
  return result;
}
function jsonBytes(bytes, limit = 16 * MiB) { return strictJson(decoder.decode(bytes), limit); }
function safePath(path) {
  check(typeof path === 'string' && /^[A-Za-z0-9_./-]{1,240}$/.test(path) && path.split('/').every(p => !['', '.', '..'].includes(p)), 'INVALID_PATH');
  return path;
}
function inventory(items, max = 128) {
  check(Array.isArray(items) && items.length <= max, 'INVALID_INVENTORY');
  const paths = new Set(); let previous = '';
  for (const item of items) {
    shape(item, ['path', 'size', 'sha256']); safePath(item.path);
    check(integer(item.size) && hash(item.sha256) && item.path > previous, 'INVALID_INVENTORY');
    const lower = item.path.toLowerCase(); check(!paths.has(lower), 'INVALID_INVENTORY');
    paths.add(lower); previous = item.path;
  }
  for (const path of paths) { const parts = path.split('/'); while (parts.pop() && parts.length) check(!paths.has(parts.join('/')), 'INVALID_PATH'); }
}
function unbase64(value, limit) {
  check(typeof value === 'string' && value.length <= Math.ceil(limit / 3) * 4 && value.length % 4 === 0, 'INVALID_BASE64');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  // A repeated-group regexp over megabytes can exhaust the JS regex stack.
  // One bounded pass handles legal maximum-sized files without that failure.
  for (let i = 0; i < value.length - padding; i++) {
    const c = value.charCodeAt(i);
    check((c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c === 43 || c === 47, 'INVALID_BASE64');
  }
  if (value.endsWith('==')) check(alphabet.indexOf(value.at(-3)) % 16 === 0, 'INVALID_BASE64');
  else if (value.endsWith('=')) check(alphabet.indexOf(value.at(-2)) % 4 === 0, 'INVALID_BASE64');
  const binary = atob(value); check(binary.length <= limit, 'FILE_LIMIT_EXCEEDED');
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
async function digest(bytes) {
  check(globalThis.crypto?.subtle, 'CRYPTO_UNAVAILABLE');
  return Array.from(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes)), v => v.toString(16).padStart(2, '0')).join('');
}
function compact(value) {
  if (Array.isArray(value)) return '[' + value.map(compact).join(',') + ']';
  if (isObject(value)) return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + compact(value[key])).join(',') + '}';
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}
function buildConfig(request) {
  return { max_open_trades: 1, stake_currency: 'USDT', stake_amount: 10000, tradable_balance_ratio: 1,
    dry_run: true, dry_run_wallet: 1000000000, trading_mode: 'spot', timeframe: request.timeframe,
    timerange: request.timerange, fee: request.fee, dataformat_ohlcv: 'json',
    exchange: { name: 'binance', pair_whitelist: ['BTC/USDT'], pair_blacklist: [], enable_ws: false },
    pairlists: [{ method: 'StaticPairList' }], entry_pricing: { price_side: 'other', use_order_book: false },
    exit_pricing: { price_side: 'other', use_order_book: false }, unfilledtimeout: { entry: 10, exit: 10, unit: 'minutes' },
    cancel_open_orders_on_exit: false, bot_name: 'n170-offline-synthetic', initial_state: 'stopped' };
}
function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (isObject(value)) return Object.fromEntries(Object.keys(value).sort().map(key => [key, sorted(value[key])]));
  return value;
}
function configBytes(request) { return encoder.encode(JSON.stringify(sorted(buildConfig(request)), null, 2).replace('"tradable_balance_ratio": 1,', '"tradable_balance_ratio": 1.0,') + '\n'); }
function equalBytes(a, b) { return a instanceof Uint8Array && b instanceof Uint8Array && a.length === b.length && a.every((v, i) => v === b[i]); }
function environment(timeout) {
  return { network: 'none', uid: 1000, read_only_root: true, input_mount: 'read_only', memory_bytes: 1073741824,
    cpus: 1, pids: 64, output_tmpfs_bytes: 16777216, temporary_tmpfs_bytes: 134217728, log_bytes: 8388608, wall_seconds: timeout };
}
function engineArguments(request) {
  return { command: 'lookahead-analysis', config: ['/input/config.json'], user_data_dir: '/tmp/n170-user', datadir: '/input/data',
    strategy_path: '/input/strategies', strategy: request.strategy, timeframe: '5m', timerange: request.timerange,
    minimum_trade_amount: request.minimum_trade_amount, targeted_trade_amount: request.targeted_trade_amount, fee: request.fee,
    dataformat_ohlcv: 'json', lookahead_analysis_exportfilename: '/output/lookahead.csv' };
}
function invocation(docker, image, input, name) {
  return [docker, 'run', '--rm', '--pull', 'never', '--name', name, '--network', 'none', '--read-only', '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges', '--user', '1000:1000', '--pids-limit', '64', '--memory', '1g', '--memory-swap', '1g', '--cpus', '1',
    '--ulimit', 'nofile=256:256', '--ulimit', 'fsize=16777216:16777216', '--log-driver', 'none', '--ipc', 'none',
    '--tmpfs', '/tmp:rw,noexec,nosuid,size=134217728,uid=1000,gid=1000,mode=0700',
    '--tmpfs', '/output:rw,noexec,nosuid,size=16777216,uid=1000,gid=1000,mode=0700',
    '--mount', `type=bind,src=${input},dst=/input,readonly`, '--workdir', '/output', '--env', 'PYTHONPATH=/freqtrade',
    '--env', 'PYTHONDONTWRITEBYTECODE=1', '--env', 'PYTHONHASHSEED=0', '--env', 'OMP_NUM_THREADS=1',
    '--env', 'OPENBLAS_NUM_THREADS=1', '--env', 'NUMEXPR_MAX_THREADS=1', '--env', 'HOME=/home/ftuser',
    '--entrypoint', 'python', image, '-B', '/input/engine_worker.py'];
}
function validateRequest(request, attempt = false) {
  shape(request, [...(attempt ? ['strategy', 'input_inventory', 'schema', 'run_id', 'attempt_id'] : ['strategies']), 'timeout_seconds', 'minimum_trade_amount',
    'targeted_trade_amount', 'timerange', 'timeframe', 'fee', 'market_metadata']);
  check(integer(request.timeout_seconds, 1, 600) && integer(request.minimum_trade_amount, 1, 99)
    && integer(request.targeted_trade_amount, request.minimum_trade_amount + 1, 100)
    && typeof request.timerange === 'string' && /^[0-9]{8}-[0-9]{8}$/.test(request.timerange)
    && request.timeframe === '5m' && request.fee === 0.001 && request.market_metadata === 'original_synthetic_spot_BTC_USDT', 'UNSUPPORTED_REQUEST');
  if (attempt) inventory(request.input_inventory);
  else check(Array.isArray(request.strategies) && request.strategies.length >= 1 && request.strategies.length <= 8
    && new Set(request.strategies).size === request.strategies.length
    && request.strategies.every(v => typeof v === 'string' && /^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(v)), 'INVALID_SELECTION');
}
function validateCandles(raw) {
  const rows = jsonBytes(raw, 8 * MiB); check(Array.isArray(rows) && rows.length >= 100 && rows.length <= 10000, 'INVALID_INPUT_DATA');
  let previous = -1;
  for (const row of rows) {
    check(Array.isArray(row) && row.length === 6 && row.every(v => typeof v === 'number' && Number.isFinite(v)), 'INVALID_INPUT_DATA');
    const [time, open, high, low, close, volume] = row;
    check(integer(time) && time > previous && time % 300000 === 0 && Math.min(open, high, low, close) > 0
      && volume >= 0 && high >= Math.max(open, close, low) && low <= Math.min(open, close), 'INVALID_INPUT_DATA');
    previous = time;
  }
}

// Small strict RFC-4180 reader: only a single assessable row is supported here.
// The observation viewer remains a separate, unchanged supplied-CSV workflow.
function csvAssessment(raw, strategy, request) {
  check(raw && raw.length <= MiB);
  const text = decoder.decode(raw).replace(/^\ufeff/, '');
  check(!/[\x00-\x09\x0b\x0c\x0e-\x1f\x7f]/.test(text));
  const rows = []; let row = []; let field = ''; let quoted = false; let closed = false; let started = false;
  const endField = () => { check(field.length <= 8192); row.push(field); field = ''; closed = false; started = false; };
  const endRow = () => { endField(); rows.push(row); row = []; check(rows.length <= 2); };
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else { quoted = false; closed = true; } }
      else field += ch;
    } else if (ch === ',') endField();
    else if (ch === '\r' || ch === '\n') { if (ch === '\r' && text[i + 1] === '\n') i++; endRow(); }
    else { check(!closed); if (ch === '"' && !started) quoted = true; else field += ch; started = true; }
    check(field.length <= 8192);
  }
  check(!quoted);
  if (field || row.length || started || closed) endRow();
  check(rows.length === 2);
  let header = rows[0].map(v => v.trim()); let values = rows[1];
  check(values.length === header.length);
  if (header[0] === '' || header[0] === 'Unnamed: 0') {
    check(/^(0|[1-9][0-9]{0,9})$/.test(values[0]) && Number(values[0]) <= 1e9);
    header = header.slice(1); values = values.slice(1);
  }
  const columns = ['filename', 'strategy', 'has_bias', 'total_signals', 'biased_entry_signals', 'biased_exit_signals', 'biased_indicators'];
  check(header.length === columns.length && new Set(header).size === header.length && columns.every(key => header.includes(key)));
  const input = Object.fromEntries(header.map((key, i) => [key, values[i].trim()]));
  check(input.filename === strategy + '.py' && input.strategy === strategy && ['true', 'false', 'yes', 'no'].includes(input.has_bias.toLowerCase()));
  const result = { filename: input.filename, strategy, has_bias: ['true', 'yes'].includes(input.has_bias.toLowerCase()) };
  for (const key of columns.slice(3, 6)) { check(/^(0|[1-9][0-9]{0,9})$/.test(input[key])); result[key] = Number(input[key]); check(integer(result[key], 0, 1e9)); }
  check(result.total_signals > request.minimum_trade_amount && result.total_signals <= request.targeted_trade_amount
    && result.biased_entry_signals <= result.total_signals && result.biased_exit_signals <= result.total_signals);
  result.biased_indicators = input.biased_indicators ? input.biased_indicators.split(',').map(v => v.trim()) : [];
  check(result.biased_indicators.length <= 128 && new Set(result.biased_indicators).size === result.biased_indicators.length
    && result.biased_indicators.every(v => /^[A-Za-z0-9_&%][A-Za-z0-9_.:&% +/()=-]{0,127}$/.test(v)));
  check(result.has_bias === Boolean(result.biased_indicators.length || result.biased_entry_signals || result.biased_exit_signals));
  return result;
}
function observedEnvironment(value) {
  shape(value, ['python', 'platform', 'machine', 'uid', 'packages']);
  check(value.uid === 1000 && ['python', 'platform', 'machine'].every(key => string(value[key])));
  check(Array.isArray(value.packages) && value.packages.length > 0 && value.packages.length <= 4096);
  for (const item of value.packages) { shape(item, ['name', 'version']); check(string(item.name) && string(item.version)); }
}
async function classifyWorker(worker, csv, strategy, request, inputs, requestRaw) {
  if (!isObject(worker) || worker.schema !== 'n170.freqtrade-worker.v2' || worker.strategy !== strategy) return 'INVALID_OUTPUT';
  const engine = worker.engine;
  if (!isObject(engine) || engine.version !== '2026.8' || engine.revision !== REVISION || engine.source_sha256 !== SOURCE_HASH) return 'INVALID_OUTPUT';
  if (!same(worker.input_inventory, inputs) || worker.request_sha256 !== await digest(requestRaw)) return 'INPUT_CHANGED';
  if (worker.outcome === 'FAILED' || worker.outcome === 'INSUFFICIENT') return worker.outcome;
  if (worker.outcome !== 'COMPLETED') return 'INVALID_OUTPUT';
  try {
    observedEnvironment(worker.environment);
    inventory(engine.source_files, 332); check(engine.source_files.length === 332);
    check(await digest(encoder.encode(compact(engine.source_files))) === SOURCE_HASH && engine.source_after_sha256 === SOURCE_HASH);
    check(same(worker.engine_arguments, engineArguments(request)));
    if (!csv) return 'MISSING_OUTPUT';
    const row = csvAssessment(csv, strategy, request);
    check(isObject(worker.analysis));
    for (const key of ['has_bias', 'total_signals', 'biased_entry_signals', 'biased_exit_signals', 'biased_indicators']) check(same(row[key], worker.analysis[key]));
    if (worker.analysis.failed_bias_check !== false) return 'INSUFFICIENT';
    return row.has_bias ? 'FINDINGS_REPORTED' : 'NO_FINDINGS_REPORTED';
  } catch { return 'INVALID_OUTPUT'; }
}
async function workerRelationships(worker, attempt, request, requestRaw, expected, retained) {
  check(isObject(worker), 'INVALID_WORKER_RECEIPT');
  const failure = ['FAILED', 'INVALID_OUTPUT', 'TIMED_OUT', 'CANCELLED'].includes(attempt.outcome);
  for (const [key, wanted] of Object.entries({ schema: 'n170.freqtrade-worker.v2', strategy: attempt.strategy,
    request_sha256: await digest(requestRaw), input_inventory: expected })) {
    if (own(worker, key)) check(same(worker[key], wanted) || (attempt.outcome === 'INPUT_CHANGED' && key === 'input_inventory'), 'WORKER_INPUT_MISMATCH');
    else check(failure, 'MISSING_WORKER_METADATA');
  }
  if (own(worker, 'engine_arguments')) check(same(worker.engine_arguments, engineArguments(request)), 'ENGINE_ARGUMENTS_MISMATCH');
  if (own(worker, 'environment') && own(attempt.environment, 'observed')) check(same(worker.environment, attempt.environment.observed), 'ENVIRONMENT_MISMATCH');
  if (own(worker, 'engine')) {
    const engine = worker.engine;
    check(isObject(engine) && engine.version === '2026.8' && engine.revision === REVISION && engine.source_sha256 === SOURCE_HASH, 'WORKER_ENGINE_MISMATCH');
    inventory(engine.source_files, 332);
    check(engine.source_files.length === 332 && await digest(encoder.encode(compact(engine.source_files))) === SOURCE_HASH
      && (!own(engine, 'source_after_sha256') || engine.source_after_sha256 === SOURCE_HASH), 'WORKER_ENGINE_SOURCE_MISMATCH');
  }
  for (const [filename, declared] of [['effective-config.json', worker.effective_config_sha256],
    ['market-metadata.json', isObject(worker.offline_adapter) ? worker.offline_adapter.market_metadata_sha256 : undefined]]) {
    if (retained[filename] || declared !== undefined) check(retained[filename] && hash(declared) && declared === await digest(retained[filename]), 'OUTPUT_DIGEST_MISMATCH');
  }
  if (own(worker, 'analysis')) {
    check(isObject(worker.analysis), 'INVALID_WORKER_ANALYSIS');
    for (const key of ['has_bias', 'failed_bias_check']) if (own(worker.analysis, key)) check(typeof worker.analysis[key] === 'boolean', 'INVALID_WORKER_ANALYSIS');
    for (const key of ['total_signals', 'biased_entry_signals', 'biased_exit_signals', 'baseline_trade_count', 'forced_exit_count', 'minimum_trade_amount', 'targeted_trade_amount']) {
      if (own(worker.analysis, key)) check(integer(worker.analysis[key]), 'INVALID_WORKER_ANALYSIS');
    }
  }
}
function outputTransport(stdout) {
  if (!stdout) return null;
  // Logs may contain arbitrary bytes. Only the fixed ASCII transport line is
  // decoded; decoding all diagnostic text is not a prerequisite for retention.
  const prefix = encoder.encode('N170_RESULT_BUNDLE_V2:');
  const matches = [];
  for (let start = 0; start < stdout.length;) {
    let end = start; while (end < stdout.length && stdout[end] !== 10 && stdout[end] !== 13) end++;
    if (end - start >= prefix.length && prefix.every((v, i) => stdout[start + i] === v)) {
      matches.push(stdout.subarray(start + prefix.length, end));
    }
    start = end + 1;
  }
  if (!matches.length) return null;
  check(matches.length === 1, 'OUTPUT_TRANSPORT_MISMATCH');
  const encoded = decoder.decode(matches[0]);
  check(encoded.length <= 6 * MiB, 'OUTPUT_TRANSPORT_MISMATCH');
  const bundle = jsonBytes(unbase64(encoded, 6 * MiB), 6 * MiB);
  shape(bundle, ['worker-result.json'], OUTPUTS.filter(name => name !== 'worker-result.json'));
  const files = Object.fromEntries(Object.entries(bundle).map(([name, value]) => [name, unbase64(value, 2 * MiB)]));
  check(Object.values(files).reduce((sum, raw) => sum + raw.length, 0) <= 3 * MiB, 'OUTPUT_TRANSPORT_MISMATCH');
  return files;
}
function summarize(attempts) {
  const counts = Object.fromEntries([...OUTCOMES].sort().map(outcome => [outcome, attempts.filter(a => a.outcome === outcome).length]));
  const completed = attempts.length > 0 && attempts.every(a => ASSESSABLE.includes(a.outcome));
  return { status: completed ? (counts.FINDINGS_REPORTED ? 'FINDINGS_REPORTED' : 'NO_FINDINGS_REPORTED') : 'NOT_ASSESSABLE',
    selected_count: attempts.length, assessed_count: counts.NO_FINDINGS_REPORTED + counts.FINDINGS_REPORTED,
    findings_count: counts.FINDINGS_REPORTED, outcome_counts: counts };
}

function missingAccounting(code) {
  return { schema: 'n170.accounting.capture-assessment.v1', status: 'NOT_ASSESSABLE', capture: { status: 'MISSING', reason_codes: [code] }, events: null,
    exact_model: null, native_compatibility: null, native_metrics: Object.fromEntries(METRICS.map(key => [key, { status: 'NOT_SUPPLIED' }])),
    oracle: { status: 'NOT_RUN' }, reason_codes: [code], trust: { source_authenticity: 'not_established', selected_source_completeness: 'unknown',
      fee_model: 'modeled quote fees from captured filled quantity, price and rate; not broker receipts', execution: 'supplied capture; not witnessed in this browser' } };
}
async function captureBinding(worker, attempt, request, requestRaw, inputs, outputs) {
  captureDescriptor(worker.capture);
  check(same(attempt.capture, worker.capture), 'CAPTURE_DESCRIPTOR_MISMATCH');
  const descriptor = worker.capture, raw = outputs['baseline-capture.json'];
  check(descriptor.schema === 'n170.freqtrade-baseline-capture.v1' && descriptor.path === 'baseline-capture.json', 'CAPTURE_SCHEMA_MISMATCH');
  if (!raw) { check(descriptor.status === 'FAILED' && descriptor.size === null && descriptor.sha256 === null, 'MISSING_CAPTURE'); return null; }
  check(raw.length <= 2 * MiB && descriptor.size === raw.length && descriptor.sha256 === await digest(raw), 'CAPTURE_BYTES_MISMATCH');
  const capture = jsonBytes(raw, 2 * MiB); const byName = Object.fromEntries(inputs.map(item => [item.path, item.sha256]));
  const expected = { run_id: request.run_id, attempt_id: request.attempt_id, strategy: request.strategy, request_sha256: await digest(requestRaw), input_inventory: inputs,
    collector_sha256: byName['accounting_collector.py'], worker_sha256: byName['engine_worker.py'], helper_sha256: byName['engine_worker_v1.py'],
    market_metadata_sha256: worker.offline_adapter?.market_metadata_sha256 ?? null, engine_revision: worker.engine?.revision ?? null,
    engine_source_sha256: worker.engine?.source_sha256 ?? null, engine_source_after_sha256: worker.engine?.source_after_sha256 ?? null };
  check(capture.schema === descriptor.schema && same(capture.binding, expected), 'CAPTURE_BINDING_MISMATCH');
  check(capture.capture?.status === descriptor.status && same(capture.capture.reason_codes, descriptor.reason_codes), 'CAPTURE_STATE_MISMATCH');
  return capture;
}
function captureDescriptor(value) {
  shape(value, ['schema', 'path', 'size', 'sha256', 'status', 'reason_codes']);
  check(value.schema === 'n170.freqtrade-baseline-capture.v1' && value.path === 'baseline-capture.json'
    && ['COMPLETE', 'INCOMPLETE', 'FAILED'].includes(value.status) && Array.isArray(value.reason_codes) && value.reason_codes.length <= 32
    && value.reason_codes.every(code => typeof code === 'string' && /^[A-Z][A-Z0-9_]{0,127}$/.test(code))
    && ((value.size === null && value.sha256 === null && value.status === 'FAILED') || (integer(value.size, 0, 2 * MiB) && hash(value.sha256))), 'INVALID_CAPTURE_DESCRIPTOR');
}
const captureShape = (value, fields) => shape(value, fields.split(' '));
const ORDER_KEYS = 'id order_id pair side type status is_open amount filled remaining price average safe_price cost fee_base created_at filled_at tag';
const TRADE_KEYS = 'trade_id pair is_open is_short trading_mode leverage amount stake_amount open_rate close_rate fee_open fee_close fee_open_cost fee_close_cost fee_open_currency fee_close_currency open_date close_date exit_reason entry_count exit_count close_profit_abs realized_profit funding_fees has_open_orders orders';
const COUNTER_KEYS = 'rejected_trades timedout_entry_orders timedout_exit_orders canceled_trade_entries canceled_entry_orders replaced_entry_orders canceled_exit_orders replaced_exit_orders';
const nativeDecimal = value => typeof value === 'number' ? (decodeBinary64(value), String(value)) : (decodeBinary64(value), expandNativeDecimal(value.repr));
const nativeEqual = (a, b) => decodeBinary64(a).hex === decodeBinary64(b).hex;
const zero = value => decodeBinary64(value).number === 0;
const identifier = value => {
  check((typeof value === 'string' && /^[A-Za-z0-9_.-]{1,128}$/.test(value)) || integer(value), 'INVALID_CAPTURE_ID');
  return `${typeof value}:${value}`;
};
function captureTime(value) {
  check(typeof value === 'string' && /^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$/.test(value), 'INVALID_CAPTURE_TIMESTAMP');
  const match = /^(.*?)(?:\.([0-9]+))?Z$/.exec(value); const millis = Date.parse(match[1] + 'Z');
  check(Number.isFinite(millis) && new Date(millis).toISOString().slice(0, 19) === match[1], 'INVALID_CAPTURE_TIMESTAMP');
  return BigInt(millis) * 1000n + BigInt((match[2] || '').padEnd(6, '0') || '0');
}
function nativeTree(value, depth = 0) {
  check(depth <= 24, 'CAPTURE_STRUCTURE_LIMIT');
  if (isObject(value)) {
    if (own(value, 'encoding')) { decodeBinary64(value); return; }
    Object.values(value).forEach(v => nativeTree(v, depth + 1));
  } else if (Array.isArray(value)) value.forEach(v => nativeTree(v, depth + 1));
  else if (typeof value === 'number') check(integer(value, -Number.MAX_SAFE_INTEGER), 'INVALID_CAPTURE_NUMBER');
  else if (typeof value === 'string') check(encoder.encode(value).length <= MiB, 'CAPTURE_STRING_LIMIT');
  else check(value === null || typeof value === 'boolean', 'INVALID_CAPTURE_TYPE');
}
function wallet(value) {
  captureShape(value, 'balances cash asset');
  check(Array.isArray(value.balances) && value.balances.length <= 32, 'INVALID_WALLET');
  const currencies = [];
  for (const row of value.balances) {
    captureShape(row, 'currency free used total');
    check(typeof row.currency === 'string' && /^[A-Z][A-Z0-9]{1,11}$/.test(row.currency), 'INVALID_WALLET');
    currencies.push(row.currency);
    const [free, used, total] = ['free', 'used', 'total'].map(key => decodeBinary64(row[key]).number);
    check(free >= 0 && used >= 0 && total >= 0, 'NEGATIVE_NATIVE_WALLET');
    // Wallet quantities use ordinary numeric equality, including signed zero.
    // Bit identity remains a separate native-replay check.
    check(used === 0 && free === total, 'RESIDUAL_OR_INCONSISTENT_WALLET');
    check(['BTC', 'USDT'].includes(row.currency) || total === 0, 'OTHER_ASSET_BALANCE_UNSUPPORTED');
    if (row.currency === 'USDT') check(total === decodeBinary64(value.cash).number, 'WALLET_QUERY_MISMATCH');
    if (row.currency === 'BTC') check(total === decodeBinary64(value.asset).number, 'WALLET_QUERY_MISMATCH');
  }
  check(same(currencies, [...new Set(currencies)].sort()), 'INVALID_WALLET');
  decodeBinary64(value.cash); decodeBinary64(value.asset);
  for (const [currency, query] of [['USDT', 'cash'], ['BTC', 'asset']]) check(currencies.includes(currency) || zero(value[query]), 'MISSING_WALLET_CURRENCY');
}
function frame(value) {
  captureShape(value, 'columns rows'); check(Array.isArray(value.columns) && value.columns.length <= 256 && new Set(value.columns).size === value.columns.length
    && value.columns.every(v => typeof v === 'string') && Array.isArray(value.rows) && value.rows.length <= 10000
    && value.rows.every(row => Array.isArray(row) && row.length === value.columns.length), 'INVALID_CAPTURE_DATAFRAME');
}
function order(value) {
  captureShape(value, ORDER_KEYS); if (value.id !== null) identifier(value.id); identifier(value.order_id);
  check(value.pair === 'BTC/USDT' && ['buy', 'sell'].includes(value.side) && typeof value.type === 'string' && typeof value.status === 'string'
    && typeof value.is_open === 'boolean' && (value.tag === null || typeof value.tag === 'string'), 'INVALID_CAPTURE_ORDER');
  for (const key of ['amount', 'filled', 'remaining', 'price', 'safe_price', 'cost']) decodeBinary64(value[key]);
  for (const key of ['average', 'fee_base']) if (value[key] !== null) decodeBinary64(value[key]);
  captureTime(value.created_at); if (value.filled_at !== null) captureTime(value.filled_at);
}
function trade(value) {
  captureShape(value, TRADE_KEYS); identifier(value.trade_id);
  check(value.pair === 'BTC/USDT' && typeof value.is_open === 'boolean' && typeof value.is_short === 'boolean' && typeof value.has_open_orders === 'boolean'
    && integer(value.entry_count) && integer(value.exit_count) && Array.isArray(value.orders) && value.orders.length <= 10000, 'INVALID_CAPTURE_TRADE');
  for (const key of ['leverage', 'amount', 'stake_amount', 'open_rate', 'fee_open', 'fee_close', 'realized_profit', 'funding_fees']) decodeBinary64(value[key]);
  for (const key of ['close_rate', 'fee_open_cost', 'fee_close_cost', 'close_profit_abs']) if (value[key] !== null) decodeBinary64(value[key]);
  captureTime(value.open_date); if (value.close_date !== null) captureTime(value.close_date);
  value.orders.forEach(order);
}

// This assessment independently constructs events from captured order completions.
// A COMPLETE observer record is never itself financial-model or oracle approval.
export function assessBaselineCapture(capture, manifest, attempt, request, dataBytes, effectiveConfigBytes) {
  return assessCapture(capture, manifest, attempt, request, dataBytes, effectiveConfigBytes);
}
function nativeProjection(value) {
  if (Array.isArray(value)) return value.map(nativeProjection);
  if (isObject(value)) return own(value, 'encoding') ? decodeBinary64(value).number : Object.fromEntries(Object.entries(value).map(([key, item]) => [key, nativeProjection(item)]));
  return value;
}
function assessCapture(capture, manifest, attempt, request, dataBytes, effectiveConfigBytes) {
  const report = missingAccounting('MISSING_CAPTURE'); if (capture === null) return report;
  const unsupported = [];
  try {
    captureShape(capture, 'schema capture_policy binding capture runtime scope window resolved opening completions closes pre_force_exit final trust');
    check(capture.schema === 'n170.freqtrade-baseline-capture.v1' && capture.capture_policy === 'freqtrade-2026.8-full-baseline-observer.v1', 'UNSUPPORTED_CAPTURE_POLICY');
    nativeTree(capture);
    captureShape(capture.trust, 'execution authenticity completeness fees observer');
    check(Object.values(capture.trust).every(v => typeof v === 'string' && v.length > 0), 'INVALID_CAPTURE_TRUST');
    const state = capture.capture;
    captureShape(state, 'status reason_codes hook_counts completion_count closed_trade_count terminal_order_count truncated');
    captureShape(state.hook_counts, 'baseline backtest opening pre_force_exit final');
    check(['COMPLETE', 'INCOMPLETE', 'FAILED'].includes(state.status) && typeof state.truncated === 'boolean'
      && Array.isArray(state.reason_codes) && state.reason_codes.every(v => typeof v === 'string' && /^[A-Z][A-Z0-9_]{0,127}$/.test(v)), 'INVALID_CAPTURE_STATE');
    check(Array.isArray(capture.completions) && capture.completions.length <= 10000 && state.completion_count === capture.completions.length
      && Array.isArray(capture.closes) && capture.closes.length <= 10000, 'CAPTURE_COUNT_MISMATCH');
    check(Object.values(state.hook_counts).every(v => integer(v, 0, 10000)) && integer(state.closed_trade_count) && integer(state.terminal_order_count), 'INVALID_CAPTURE_STATE');
    if (state.status !== 'COMPLETE' || state.truncated || !Object.values(state.hook_counts).every(v => v === 1)) {
      report.capture = { status: 'UNSUPPORTED', reason_codes: ['INCOMPLETE_BASELINE_CAPTURE'] }; report.reason_codes = ['INCOMPLETE_BASELINE_CAPTURE']; return report;
    }
    check(state.reason_codes.length === 0, 'CONTRADICTORY_CAPTURE_STATE');
    captureShape(capture.scope, 'pair timeframe trading_mode fee_model');
    check(same(capture.scope, { pair: 'BTC/USDT', timeframe: '5m', trading_mode: 'spot', fee_model: 'quote-filled-price-rate.v1' }), 'UNSUPPORTED_CAPTURE_SCOPE');
    const runtime = capture.runtime;
    captureShape(runtime, 'implementation python_version float_info numpy_version ccxt_version ccxt_precise_sha256 ccxt_precise_after_sha256');
    check(runtime.implementation === 'CPython' && runtime.python_version === '3.14.7' && runtime.numpy_version === '2.4.6' && runtime.ccxt_version === '4.5.76'
      && same(runtime.float_info, { radix: 2, mant_dig: 53, max_exp: 1024, min_exp: -1021, rounds: 1 })
      && runtime.ccxt_precise_sha256 === '445721221b65f37cc198adaeec26f68b214926e82ea2bfc0195a346ec94773ed'
      && runtime.ccxt_precise_after_sha256 === runtime.ccxt_precise_sha256, 'UNSUPPORTED_NATIVE_RUNTIME');
    const win = capture.window; captureShape(win, 'requested_timerange backtest_start backtest_end processed_bounds candle_count');
    const source = jsonBytes(dataBytes, 8 * MiB); check(win.requested_timerange === request.timerange && win.candle_count === source.length, 'CAPTURE_WINDOW_MISMATCH');
    const start = captureTime(win.backtest_start), end = captureTime(win.backtest_end); check(end > start, 'CAPTURE_WINDOW_MISMATCH');
    captureShape(win.processed_bounds, 'BTC/USDT'); const bound = win.processed_bounds['BTC/USDT']; captureShape(bound, 'first last count');
    const first = captureTime(bound.first), last = captureTime(bound.last);
    const firstIndex = source.findIndex(row => BigInt(row[0]) * 1000n === first), lastIndex = source.findIndex(row => BigInt(row[0]) * 1000n === last);
    check(firstIndex >= 0 && lastIndex >= firstIndex && bound.count === lastIndex - firstIndex + 1 && first <= start && start <= end && end <= last, 'CAPTURE_WINDOW_MISMATCH');
    captureShape(capture.resolved, 'config strategy_settings');
    captureShape(capture.resolved.strategy_settings, 'timeframe startup_candle_count minimal_roi stoploss can_short position_adjustment_enable order_types');
    const settings = capture.resolved.strategy_settings;
    if (settings.timeframe !== '5m' || settings.can_short !== false || settings.position_adjustment_enable !== false || settings.order_types?.entry !== 'market' || settings.order_types?.exit !== 'market') unsupported.push('UNSUPPORTED_STRATEGY_SETTINGS');
    check(isObject(capture.resolved.config), 'INVALID_RESOLVED_CONFIG');
    if (capture.resolved.config.trading_mode !== 'spot' || capture.resolved.config.stake_currency !== 'USDT' || nativeDecimal(capture.resolved.config.fee) !== '0.001') unsupported.push('UNSUPPORTED_RESOLVED_CONFIG');
    check(effectiveConfigBytes, 'MISSING_EFFECTIVE_CONFIGURATION');
    const effectiveConfig = jsonBytes(effectiveConfigBytes, 2 * MiB), resolvedConfig = nativeProjection(capture.resolved.config), stagedConfig = buildConfig(request);
    for (const key of ['trading_mode', 'stake_currency', 'stake_amount', 'dry_run', 'dry_run_wallet', 'fee', 'timeframe', 'tradable_balance_ratio',
      'dataformat_ohlcv', 'entry_pricing', 'exit_pricing', 'pairlists']) {
      check(same(resolvedConfig[key], stagedConfig[key]) && same(effectiveConfig[key], stagedConfig[key]), 'RESOLVED_CONFIGURATION_MISMATCH');
    }
    check(resolvedConfig.strategy === request.strategy && same(resolvedConfig.pairs, ['BTC/USDT']), 'RESOLVED_CONFIGURATION_MISMATCH');
    const epochRange = request.timerange.split('-').map(day => Date.parse(`${day.slice(0, 4)}-${day.slice(4, 6)}-${day.slice(6, 8)}T00:00:00Z`) / 1000).join('-');
    check(effectiveConfig.timerange === request.timerange && [request.timerange, epochRange].includes(resolvedConfig.timerange), 'RESOLVED_TIMERANGE_MISMATCH');
    if (own(effectiveConfig, 'strategy')) check(effectiveConfig.strategy === request.strategy, 'EFFECTIVE_CONFIGURATION_MISMATCH');
    if (own(effectiveConfig, 'pairs')) check(same(effectiveConfig.pairs, resolvedConfig.pairs), 'EFFECTIVE_CONFIGURATION_MISMATCH');
    for (const key of ['name', 'pair_whitelist', 'pair_blacklist', 'enable_ws']) check(same(resolvedConfig.exchange?.[key], stagedConfig.exchange[key])
      && same(effectiveConfig.exchange?.[key], stagedConfig.exchange[key]), 'RESOLVED_EXCHANGE_MISMATCH');
    for (const key of ['max_open_trades', 'minimum_trade_amount', 'targeted_trade_amount']) if (own(effectiveConfig, key)) check(same(resolvedConfig[key], effectiveConfig[key]), 'RESOLVED_CONFIGURATION_MISMATCH');
    for (const key of ['timeframe', 'startup_candle_count', 'minimal_roi', 'stoploss', 'can_short', 'position_adjustment_enable', 'order_types']) {
      if (own(resolvedConfig, key)) check(same(resolvedConfig[key], nativeProjection(settings[key])), 'RESOLVED_STRATEGY_MISMATCH');
    }
    for (const config of [resolvedConfig, effectiveConfig]) if (own(config, 'original_config')) {
      for (const key of Object.keys(stagedConfig)) check(same(config.original_config[key], stagedConfig[key]), 'ORIGINAL_CONFIGURATION_MISMATCH');
    }
    const opening = capture.opening; captureShape(opening, 'wallets starting_balance open_trades closed_trade_count total_closed_profit');
    const final = capture.final; captureShape(final, 'wallets open_trades closed_trades trade_rows native_final_balance native_total_closed_profit close_order engine_counters wallet_summary');
    const pre = capture.pre_force_exit; captureShape(pre, 'wallets open_trades terminal_candles');
    check(Array.isArray(pre.open_trades) && pre.open_trades.length <= 10000, 'INVALID_PRE_FORCE_STATE');
    check(pre.open_trades.length === 0 && zero(pre.wallets.asset), 'FORCED_LIQUIDATION_UNSUPPORTED');
    for (const value of [opening.wallets, final.wallets, pre.wallets]) wallet(value);
    check(nativeEqual(opening.starting_balance, resolvedConfig.dry_run_wallet), 'OPENING_CONFIGURATION_MISMATCH');
    check(Array.isArray(opening.open_trades) && opening.open_trades.length === 0 && opening.closed_trade_count === 0 && zero(opening.total_closed_profit)
      && zero(opening.wallets.asset) && nativeEqual(opening.starting_balance, opening.wallets.cash), 'UNSUPPORTED_OPENING_STATE');
    captureShape(pre.terminal_candles, 'BTC/USDT'); const terminal = pre.terminal_candles['BTC/USDT']; captureShape(terminal, 'ohlcv backtest_row');
    captureShape(terminal.ohlcv, 'date open high low close volume'); captureShape(terminal.backtest_row, 'date open high low close');
    check(captureTime(terminal.ohlcv.date) === last && captureTime(terminal.backtest_row.date) === last, 'TERMINAL_CANDLE_MISMATCH');
    for (const [i, key] of ['open', 'high', 'low', 'close', 'volume'].entries()) {
      check(numberHex(source[lastIndex][i + 1]) === decodeBinary64(terminal.ohlcv[key]).hex, 'TERMINAL_CANDLE_MISMATCH');
      if (key !== 'volume') check(nativeEqual(terminal.ohlcv[key], terminal.backtest_row[key]), 'TERMINAL_CANDLE_MISMATCH');
    }
    check(Array.isArray(final.open_trades) && Array.isArray(final.closed_trades) && final.closed_trades.length <= 5000 && Array.isArray(final.close_order), 'INVALID_FINAL_STATE');
    final.open_trades.forEach(trade); final.closed_trades.forEach(trade); frame(final.trade_rows); frame(final.wallet_summary);
    check(final.trade_rows.rows.length === final.closed_trades.length, 'TRADE_DATAFRAME_COUNT_MISMATCH');
    if (final.closed_trades.length) {
      const requiredColumns = ['pair', 'stake_amount', 'amount', 'open_date', 'close_date', 'open_rate', 'close_rate', 'fee_open', 'fee_close', 'profit_abs',
        'exit_reason', 'is_open', 'is_short', 'leverage', 'funding_fees', 'orders', 'open_timestamp', 'close_timestamp'];
      check(requiredColumns.every(key => final.trade_rows.columns.includes(key)), 'MISSING_TRADE_DATAFRAME_FIELDS');
      for (const [index, t] of final.closed_trades.entries()) {
        const row = Object.fromEntries(final.trade_rows.columns.map((key, i) => [key, final.trade_rows.rows[index][i]]));
        for (const key of ['pair', 'open_date', 'close_date', 'exit_reason', 'is_open', 'is_short']) check(row[key] === t[key], 'TRADE_DATAFRAME_IDENTITY_MISMATCH');
        for (const key of ['amount', 'open_rate', 'close_rate', 'fee_open', 'fee_close', 'leverage', 'funding_fees']) check(nativeEqual(row[key], t[key]), 'TRADE_DATAFRAME_IDENTITY_MISMATCH');
        // The pinned engine's trade serialization rounds only this displayed
        // stake cell. It is corroboration, never an input to the exact ledger.
        check(decodeBinary64(row.stake_amount).hex === roundBinary64ToDecimal8(decodeBinary64(t.stake_amount).hex).hex, 'TRADE_DATAFRAME_STAKE_MISMATCH');
        check(nativeEqual(row.profit_abs, t.close_profit_abs), 'TRADE_DATAFRAME_PROFIT_MISMATCH');
        check(row.open_timestamp === Number(captureTime(t.open_date) / 1000n) && row.close_timestamp === Number(captureTime(t.close_date) / 1000n), 'TRADE_DATAFRAME_TIME_MISMATCH');
        check(Array.isArray(row.orders) && row.orders.length === t.orders.length, 'TRADE_DATAFRAME_ORDERS_MISMATCH');
        for (const [orderIndex, summary] of row.orders.entries()) {
          captureShape(summary, 'amount cost ft_is_entry ft_order_side ft_order_tag order_filled_timestamp safe_price');
          const original = t.orders[orderIndex];
          check(summary.ft_is_entry === (original.side === 'buy') && summary.ft_order_side === original.side && summary.ft_order_tag === original.tag
            && summary.order_filled_timestamp === Number(captureTime(original.filled_at) / 1000n)
            && ['amount', 'cost', 'safe_price'].every(key => nativeEqual(summary[key], original[key])), 'TRADE_DATAFRAME_ORDERS_MISMATCH');
        }
      }
    }
    captureShape(final.engine_counters, COUNTER_KEYS); check(Object.values(final.engine_counters).every(v => integer(v)), 'INVALID_ENGINE_COUNTERS');
    if (Object.values(final.engine_counters).some(v => v !== 0)) unsupported.push('UNSUPPORTED_ORDER_COUNTERS');
    check(nativeEqual(final.wallets.cash, final.native_final_balance), 'NATIVE_CASH_IDENTITY_MISMATCH');
    check(state.closed_trade_count === final.closed_trades.length && state.closed_trade_count === capture.closes.length
      && same(final.close_order, final.closed_trades.map(t => t.trade_id)) && same(final.close_order, capture.closes.map(t => t.trade_id)), 'CLOSE_ORDER_MISMATCH');
    check(new Set(final.close_order.map(identifier)).size === final.close_order.length, 'DUPLICATE_TRADE');
    const terminalOrders = new Map(), completionIds = new Set(), trades = new Map(), internalOrderIds = new Set(), exchangeOrderIds = new Set(); let terminalCount = 0;
    for (const t of [...final.closed_trades, ...final.open_trades]) {
      const tid = identifier(t.trade_id); check(!trades.has(tid), 'DUPLICATE_TRADE'); trades.set(tid, t);
      for (const o of t.orders) {
        const exchangeId = identifier(o.order_id), oid = tid + '/' + exchangeId;
        check(!terminalOrders.has(oid) && !exchangeOrderIds.has(exchangeId), 'DUPLICATE_TERMINAL_ORDER'); exchangeOrderIds.add(exchangeId);
        if (o.id !== null) { const internalId = identifier(o.id); check(!internalOrderIds.has(internalId), 'DUPLICATE_TERMINAL_ORDER'); internalOrderIds.add(internalId); }
        terminalOrders.set(oid, o); terminalCount++;
      }
    }
    check(terminalCount === state.terminal_order_count && terminalCount === capture.completions.length, 'ORDER_BIJECTION_MISMATCH');
    const events = []; let previous = start; const active = new Set(); const perTrade = new Map();
    for (const [index, completion] of capture.completions.entries()) {
      captureShape(completion, 'sequence phase trade_id order trade_fee_rates trade_fee_costs trade_fee_currencies');
      check(completion.sequence === index + 1 && ['baseline', 'forced_liquidation'].includes(completion.phase), 'COMPLETION_SEQUENCE_MISMATCH');
      for (const key of ['trade_fee_rates', 'trade_fee_costs', 'trade_fee_currencies']) captureShape(completion[key], 'open close');
      const o = completion.order; order(o); const tid = identifier(completion.trade_id), oid = tid + '/' + identifier(o.order_id);
      check(!completionIds.has(oid) && terminalOrders.has(oid) && same(o, terminalOrders.get(oid)), 'ORDER_BIJECTION_MISMATCH'); completionIds.add(oid);
      const instant = captureTime(o.filled_at); check(instant >= previous && instant >= start && instant <= end && captureTime(o.created_at) <= instant, 'COMPLETION_CHRONOLOGY_MISMATCH'); previous = instant;
      if (completion.phase === 'forced_liquidation' || o.tag === 'force_exit' || trades.get(tid)?.exit_reason === 'force_exit') unsupported.push('FORCED_LIQUIDATION_UNSUPPORTED');
      if (o.type !== 'market' || o.status !== 'closed' || o.is_open || !zero(o.remaining) || !nativeEqual(o.amount, o.filled)) unsupported.push('PARTIAL_OR_UNSUPPORTED_ORDER');
      if (o.fee_base !== null && !zero(o.fee_base)) unsupported.push('BASE_CURRENCY_FEE_UNSUPPORTED');
      for (const key of ['open', 'close']) {
        if (nativeDecimal(completion.trade_fee_rates[key]) !== '0.001') unsupported.push('UNSUPPORTED_FEE_RATE');
        const currency = completion.trade_fee_currencies[key]; if (![null, '', 'USDT'].includes(currency)) unsupported.push('UNSUPPORTED_FEE_CURRENCY');
      }
      const q = exactDecimal(nativeDecimal(o.filled)), p = exactDecimal(nativeDecimal(o.safe_price));
      check(Number(q) > 0 && Number(p) > 0, 'INVALID_FILL_OPERANDS');
      if (o.average !== null) check(nativeEqual(o.average, o.safe_price), 'ORDER_PRICE_MISMATCH');
      const q8 = BigInt(q.replace('.', '') + '0'.repeat(8 - (q.split('.')[1]?.length || 0)));
      const p8 = BigInt(p.replace('.', '') + '0'.repeat(8 - (p.split('.')[1]?.length || 0)));
      const fee = (q8 * p8).toString().padStart(20, '0'); const feeDecimal = (fee.slice(0, -19) + '.' + fee.slice(-19)).replace(/0+$/, '').replace(/\.$/, '');
      events.push({ event_id: `fill-${index + 1}`, timestamp: o.filled_at, type: o.side === 'buy' ? 'BUY' : 'SELL', quantity: q, price: p, fee: feeDecimal,
        fee_currency: 'USDT', fee_model: { kind: 'modeled_fee', quantity: q, price: p, rate: '0.001', sources: [`capture:/completions/${index}/order/filled`, `capture:/completions/${index}/order/safe_price`, `capture:/completions/${index}/trade_fee_rates/${o.side === 'buy' ? 'open' : 'close'}`] } });
      const records = perTrade.get(tid) || []; records.push({ ...events.at(-1), phase: completion.phase }); perTrade.set(tid, records);
      if (o.side === 'buy') { if (active.size > 0) unsupported.push('OVERLAPPING_TRADES_UNSUPPORTED'); active.add(tid); }
      else { if (!active.has(tid)) unsupported.push('UNSUPPORTED_ENTRY_EXIT_ORDER'); active.delete(tid); }
    }
    if (pre.open_trades.length || final.open_trades.length || !zero(final.wallets.asset)) unsupported.push('OPEN_OR_FORCED_POSITION_UNSUPPORTED');
    if (!pre.open_trades.length && !final.open_trades.length) check(nativeEqual(pre.wallets.cash, final.wallets.cash), 'UNEXPLAINED_TERMINAL_CASH_CHANGE');
    if (!events.length || !final.closed_trades.length) unsupported.push('NO_COMPLETED_TRADES');
    const nativeTrades = []; let priorTotal = opening.total_closed_profit; let priorClose = start;
    for (const [index, t] of final.closed_trades.entries()) {
      const records = perTrade.get(identifier(t.trade_id)) || []; const close = capture.closes[index];
      captureShape(close, 'sequence trade_id close_profit_abs total_profit_before total_profit_after');
      check(close.sequence === index + 1 && close.trade_id === t.trade_id && nativeEqual(close.close_profit_abs, t.close_profit_abs)
        && nativeEqual(close.total_profit_before, priorTotal), 'NATIVE_CLOSE_SEQUENCE_MISMATCH');
      check(numberHex(decodeBinary64(close.total_profit_before).number + decodeBinary64(close.close_profit_abs).number) === decodeBinary64(close.total_profit_after).hex, 'NATIVE_CLOSE_ACCUMULATION_MISMATCH');
      priorTotal = close.total_profit_after; const instant = captureTime(t.close_date); check(instant >= priorClose && instant <= end, 'CLOSE_CHRONOLOGY_MISMATCH'); priorClose = instant;
      if (t.is_open || t.is_short || t.trading_mode !== 'spot' || nativeDecimal(t.leverage) !== '1' || t.has_open_orders || !zero(t.funding_fees)
        || t.entry_count !== 1 || t.exit_count !== 1 || records.length !== 2 || records[0]?.type !== 'BUY' || records[1]?.type !== 'SELL'
        || records[0]?.quantity !== records[1]?.quantity) { unsupported.push('UNSUPPORTED_TRADE_STRUCTURE'); continue; }
      check(nativeDecimal(t.open_rate) === records[0].price && nativeDecimal(t.close_rate) === records[1].price
        && nativeDecimal(t.amount) === records[1].quantity && t.open_date === records[0].timestamp && t.close_date === records[1].timestamp, 'TRADE_ORDER_IDENTITY_MISMATCH');
      if (nativeDecimal(t.fee_open) !== '0.001' || nativeDecimal(t.fee_close) !== '0.001') unsupported.push('UNSUPPORTED_FEE_RATE');
      nativeTrades.push({ trade_id: String(t.trade_id), entry_quantity: records[0].quantity, entry_price: records[0].price,
        exit_quantity: records[1].quantity, exit_price: records[1].price, fee_rate: '0.001', native_profit: t.close_profit_abs });
    }
    check(nativeEqual(priorTotal, final.native_total_closed_profit), 'NATIVE_TOTAL_PROFIT_MISMATCH');
    if (![...ASSESSABLE, 'INSUFFICIENT'].includes(attempt.outcome)) unsupported.push('UNSUCCESSFUL_ATTEMPT');
    report.capture = { status: unsupported.length ? 'UNSUPPORTED' : 'SUPPORTED', reason_codes: [...new Set(unsupported)] };
    report.reason_codes = [...report.capture.reason_codes, 'MISSING_NATIVE_METRICS'];
    if (unsupported.length) return report;
    const document = { schema: 'n170.accounting.events.v2', evidence_class: 'supplied_events', asset: 'BTC', cash_currency: 'USDT',
      opening: { timestamp: win.backtest_start, cash: exactDecimal(nativeDecimal(opening.starting_balance)) }, events,
      closing: { timestamp: win.backtest_end, mark_price: exactDecimal(nativeDecimal(terminal.ohlcv.close)), reported: {} } };
    report.events = document; report.exact_model = computeExactLedger(document);
    if (!report.exact_model.computed) { report.capture.status = 'UNSUPPORTED'; report.capture.reason_codes = report.exact_model.reason_codes; return report; }
    const runtimeBinding = { image_id: manifest.engine.image_id, image_reference: manifest.engine.reference,
      engine_revision: capture.binding.engine_revision, engine_source_sha256: capture.binding.engine_source_sha256,
      python: runtime.python_version, ccxt: runtime.ccxt_version, numpy: runtime.numpy_version, precise_sha256: runtime.ccxt_precise_sha256 };
    report.native_compatibility = replayNativeClosedTrades({ opening_cash: document.opening.cash, trades: nativeTrades,
      native_total_profit: final.native_total_closed_profit, native_cash: final.native_final_balance, runtime: runtimeBinding });
    for (const [key, value] of [['cash', final.native_final_balance], ['quantity', final.wallets.asset], ['net_pnl', final.native_total_closed_profit]]) {
      const comparison = compareNativeMetric(value, report.exact_model.computed[key]);
      report.native_metrics[key] = { status: comparison.exact_decimal_equal ? 'EXACT_MATCH' : 'EXACT_DIFFERENCE', ...comparison };
    }
    return report;
  } catch (error) {
    const code = /^[A-Z][A-Z0-9_]+$/.test(error?.message || '') ? error.message : 'INVALID_CAPTURE';
    const unsupportedCodes = ['UNSUPPORTED_NATIVE_SPELLING', 'NEGATIVE_NATIVE_WALLET', 'RESIDUAL_OR_INCONSISTENT_WALLET', 'OTHER_ASSET_BALANCE_UNSUPPORTED', 'FORCED_LIQUIDATION_UNSUPPORTED'];
    report.capture = { status: unsupportedCodes.includes(code) ? 'UNSUPPORTED' : 'INVALID', reason_codes: [code] }; report.reason_codes = [code]; return report;
  }
}

function sortedJson(value) {
  if (Array.isArray(value)) return '[' + value.map(sortedJson).join(',') + ']';
  if (isObject(value)) return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + sortedJson(value[key])).join(',') + '}';
  return JSON.stringify(value);
}
async function assessOracle(assessment, buffers, prefix) {
  const files = Object.fromEntries(ORACLE_FILES.filter(name => buffers.has(prefix + name)).map(name => [name, buffers.get(prefix + name)]));
  if (!Object.keys(files).length) return { status: 'NOT_RUN', reason_codes: ['ORACLE_NOT_SUPPLIED'] };
  const report = { status: 'INVALID', reason_codes: [], execution: 'supplied unsigned evidence; this browser did not execute Beancount' };
  try {
    const missing = ORACLE_FILES.filter(name => !own(files, name));
    if (missing.length) return { ...report, status: 'MISSING', reason_codes: ['INCOMPLETE_ORACLE_EVIDENCE'], missing };
    if (assessment.capture.status !== 'SUPPORTED' || !assessment.events) return { ...report, status: 'UNAVAILABLE', reason_codes: ['SUPPORTED_CAPTURE_REQUIRED'] };
    check(Object.values(files).every(raw => raw.length <= 2 * MiB), 'ORACLE_OUTPUT_LIMIT_EXCEEDED');
    check(assessment.capture.status === 'SUPPORTED' && assessment.events && assessment.exact_model?.computed, 'SUPPORTED_ACCOUNTING_INPUT_REQUIRED');
    const document = jsonBytes(files['events.json'], 2 * MiB);
    check(same(document, assessment.events), 'ORACLE_EVENT_BINDING_MISMATCH');
    check(equalBytes(files['ledger.beancount'], encoder.encode(generateOracleLedger(document))), 'ORACLE_LEDGER_MISMATCH');
    const source = jsonBytes(files['report.json'], 2 * MiB);
    shape(source, ['schema', 'numeric_policy', 'status', 'reason_codes', 'evidence_class', 'source_inventory', 'event_inventory', 'checks', 'computed',
      'event_checkpoints', 'source_authenticity', 'selected_source_completeness', 'oracle', 'limitations', 'scope']);
    check(source.schema === 'n170.accounting.reconciliation.v2' && same(source.computed, assessment.exact_model.computed)
      && same(source.event_checkpoints, assessment.exact_model.event_checkpoints), 'ORACLE_REPORT_MODEL_MISMATCH');
    check(source.numeric_policy === 'decimal80-operand8-modeledfee19-result19.v1' && source.status === 'NOT_ASSESSABLE'
      && source.evidence_class === 'supplied_events' && same(source.checks, assessment.exact_model.checks), 'ORACLE_REPORT_MODEL_MISMATCH');
    check(same(source.source_inventory, [{ role: 'supplied_event_document', size_bytes: files['events.json'].length, sha256: await digest(files['events.json']), binding: 'exact_supplied_bytes' }]), 'ORACLE_SOURCE_INVENTORY_MISMATCH');
    const eventInventory = await Promise.all(document.events.map(async (event, i) => ({ event_id: event.event_id, sequence: i + 1, sha256: await digest(encoder.encode(sortedJson(event) + '\n')) })));
    check(same(source.event_inventory, eventInventory), 'ORACLE_EVENT_INVENTORY_MISMATCH');
    const oracle = source.oracle;
    shape(oracle, ['engine', 'expected_revision', 'expected_installed_inventory_sha256', 'input_sha256', 'ledger_sha256', 'worker_sha256',
      'purpose', 'execution_trust', 'network_policy', 'output_policy', 'status', 'reason_codes', 'oracle.stdout.json', 'oracle.stderr.txt'], ['exit_code', 'observation', 'different_metrics']);
    check(oracle.engine === 'beancount' && oracle.expected_revision === ORACLE_REVISION && oracle.expected_installed_inventory_sha256 === ORACLE_INVENTORY_HASH, 'ORACLE_IDENTITY_MISMATCH');
    for (const [name, field] of [['events.json', 'input_sha256'], ['ledger.beancount', 'ledger_sha256'], ['oracle-worker.py', 'worker_sha256']]) {
      check(oracle[field] === await digest(files[name]), 'ORACLE_ARTIFACT_HASH_MISMATCH');
    }
    check(oracle.worker_sha256 === ORACLE_WORKER_HASH, 'ORACLE_WORKER_MISMATCH');
    for (const name of ['oracle.stdout.json', 'oracle.stderr.txt']) {
      const descriptor = oracle[name]; shape(descriptor, ['observed_bytes', 'sha256', 'retained_bytes', 'truncated']);
      check(integer(descriptor.observed_bytes) && integer(descriptor.retained_bytes) && typeof descriptor.truncated === 'boolean'
        && descriptor.retained_bytes === files[name].length && descriptor.retained_bytes === Math.min(descriptor.observed_bytes, 2 * MiB)
        && descriptor.truncated === (descriptor.observed_bytes > 2 * MiB) && hash(descriptor.sha256), 'ORACLE_OUTPUT_DESCRIPTOR_MISMATCH');
      if (descriptor.truncated) return { ...report, status: 'UNAVAILABLE', reason_codes: ['ORACLE_OUTPUT_TRUNCATED'] };
      check(descriptor.sha256 === await digest(files[name]), 'ORACLE_OUTPUT_HASH_MISMATCH');
    }
    check(['MATCHED', 'DISCREPANCIES_FOUND', 'UNAVAILABLE'].includes(oracle.status) && Array.isArray(oracle.reason_codes)
      && oracle.reason_codes.length <= 32 && oracle.reason_codes.every(v => string(v, 128)), 'INVALID_ORACLE_STATUS');
    if (oracle.status === 'UNAVAILABLE') return { ...report, status: 'UNAVAILABLE', reason_codes: ['SUPPLIED_ORACLE_UNAVAILABLE'] };
    const observation = jsonBytes(files['oracle.stdout.json'], 2 * MiB);
    check(same(observation, oracle.observation), 'ORACLE_OBSERVATION_MISMATCH');
    shape(observation, ['status', 'engine', 'version', 'declared_install_source', 'source_revision', 'installed_code_inventory',
      'installed_code_inventory_sha256', 'python', 'packages', 'validation_error_count', 'validation_error_types', 'computed', 'limits']);
    check(observation.status === 'EXECUTED' && observation.engine === 'beancount' && observation.version === '3.2.3'
      && observation.source_revision === ORACLE_REVISION && observation.declared_install_source?.url === `https://github.com/beancount/beancount/archive/${ORACLE_REVISION}.tar.gz`, 'ORACLE_IDENTITY_MISMATCH');
    check(typeof observation.python === 'string' && /^[0-9]+\.[0-9]+\.[0-9]+$/.test(observation.python)
      && Array.isArray(observation.packages) && observation.packages.length >= 1 && observation.packages.length <= 2000
      && Array.isArray(observation.limits) && observation.limits.length >= 1 && observation.limits.length <= 32
      && observation.limits.every(v => string(v, 1024)), 'INVALID_ORACLE_RUNTIME_METADATA');
    let packageName = '';
    for (const item of observation.packages) {
      shape(item, ['name', 'version']);
      check(string(item.name, 128) && string(item.version, 128) && item.name.toLowerCase() > packageName, 'INVALID_ORACLE_RUNTIME_METADATA'); packageName = item.name.toLowerCase();
    }
    check(observation.packages.some(item => item.name === 'beancount' && item.version === '3.2.3'), 'INVALID_ORACLE_RUNTIME_METADATA');
    const codeInventory = observation.installed_code_inventory;
    check(Array.isArray(codeInventory) && codeInventory.length >= 1 && codeInventory.length <= 2000, 'ORACLE_INVENTORY_MISMATCH');
    let previous = '';
    for (const entry of codeInventory) {
      shape(entry, ['path', 'size', 'sha256']);
      check(typeof entry.path === 'string' && /^beancount\/[A-Za-z0-9_/.-]+\.(?:py|so|pyd)$/.test(entry.path) && !entry.path.split('/').some(v => v === '.' || v === '..')
        && entry.path > previous && integer(entry.size, 0, 128 * MiB) && hash(entry.sha256), 'ORACLE_INVENTORY_MISMATCH'); previous = entry.path;
    }
    check(observation.installed_code_inventory_sha256 === ORACLE_INVENTORY_HASH
      && await digest(encoder.encode(sortedJson(codeInventory))) === ORACLE_INVENTORY_HASH, 'ORACLE_INVENTORY_MISMATCH');
    check(integer(observation.validation_error_count) && Array.isArray(observation.validation_error_types)
      && observation.validation_error_types.every(v => string(v, 128)) && integer(oracle.exit_code, 0, 1)
      && Boolean(observation.validation_error_count) === Boolean(observation.validation_error_types.length)
      && same(observation.validation_error_types, [...new Set(observation.validation_error_types)].sort()), 'INVALID_ORACLE_VALIDATION_RESULT');
    shape(observation.computed, METRICS);
    check(METRICS.every(key => exactDecimal(observation.computed[key], 'result') === observation.computed[key]), 'NONCANONICAL_ORACLE_METRIC');
    const differences = METRICS.filter(key => observation.computed[key] !== assessment.exact_model.computed[key]);
    check(same(oracle.different_metrics, differences), 'ORACLE_DIFFERENCE_REPORT_MISMATCH');
    const matched = !differences.length && observation.validation_error_count === 0 && oracle.exit_code === 0;
    check(oracle.status === (matched ? 'MATCHED' : 'DISCREPANCIES_FOUND'), 'ORACLE_STATUS_MISMATCH');
    return { ...report, status: matched ? 'SUPPLIED_MATCHED' : 'SUPPLIED_DISCREPANCIES', reason_codes: [matched ? 'SUPPLIED_ORACLE_MATCHES_EXACT_MODEL' : 'SUPPLIED_ORACLE_DIFFERENCE_OR_VALIDATION_ERROR'],
      different_metrics: differences, engine: 'beancount', version: '3.2.3', revision: ORACLE_REVISION, installed_inventory_sha256: ORACLE_INVENTORY_HASH };
  } catch (error) { report.reason_codes = [/^[A-Z][A-Z0-9_]+$/.test(error?.message || '') ? error.message : 'INVALID_ORACLE_EVIDENCE']; return report; }
}

/** Strict version routing only; v1 behavior and verifier source stay untouched. */
export async function verifyRunReviewPackage(text, options = {}) {
  let schema;
  try { schema = strictJson(text, RUN_REVIEW_MAX_BYTES, true)?.schema; } catch { return verifyRunReviewV1(text, options); }
  return schema === RUN_REVIEW_V2_SCHEMA ? verifyRunReviewV2(text, options) : verifyRunReviewV1(text, options);
}

async function validateManifest(manifest, buffers, outerInventory) {
  shape(manifest, ['schema', 'run_id', 'execution_root', 'state', 'started_at', 'finished_at', 'engine', 'request', 'inputs', 'artifacts', 'attempts', 'summary', 'trust']);
  check(manifest.schema === 'n170.freqtrade-run.v2' && manifest.state === 'FINALIZED', 'INCOMPLETE_MANIFEST');
  check(typeof manifest.run_id === 'string' && /^[a-f0-9]{32}$/.test(manifest.run_id)
    && string(manifest.started_at, 128) && string(manifest.finished_at, 128) && same(manifest.trust, TRUST), 'INVALID_MANIFEST_METADATA');
  check(string(manifest.execution_root, 4096) && manifest.execution_root.startsWith('/')
    && !/[,\r\n\x00]/.test(manifest.execution_root) && !manifest.execution_root.split('/').some(p => p === '.' || p === '..'), 'INVALID_EXECUTION_ROOT');
  const engine = manifest.engine;
  shape(engine, ['version', 'revision', 'image_id', 'reference'], ['os', 'architecture', 'docker_version']);
  check(engine.version === '2026.8' && engine.revision === REVISION && typeof engine.image_id === 'string' && /^sha256:[a-f0-9]{64}$/.test(engine.image_id)
    && typeof engine.reference === 'string' && /^(?:[A-Za-z0-9./_-]+@)?sha256:[a-f0-9]{64}$/.test(engine.reference), 'ENGINE_MISMATCH');
  if (own(engine, 'os')) check(engine.os === 'linux' && string(engine.architecture, 64) && isObject(engine.docker_version), 'ENGINE_MISMATCH');
  validateRequest(manifest.request);
  inventory(manifest.artifacts); inventory(manifest.inputs);
  check(same(manifest.artifacts, outerInventory), 'ARTIFACT_MISMATCH');
  check(same(manifest.inputs, outerInventory.filter(item => /^attempts\/[0-9]{3}\/input\/.+/.test(item.path))), 'INPUT_INVENTORY_MISMATCH');
  check(Array.isArray(manifest.attempts) && manifest.attempts.length === manifest.request.strategies.length, 'INCOMPLETE_ATTEMPTS');
  const allowedPaths = new Set(); const missing = []; const accounting = [];
  const accountingMissing = (attempt, code) => ({ id: attempt.id, ...missingAccounting(code), detector_status: attempt.outcome });
  for (const [index, attempt] of manifest.attempts.entries()) {
    shape(attempt, ['id', 'strategy', 'state', 'outcome', 'reason_codes', 'argv', 'environment', 'started_at', 'finished_at', 'exit_code', 'artifacts', 'capture'], ['container_name', 'cleanup_confirmed']);
    const id = String(index).padStart(3, '0'); const prefix = `attempts/${id}/`; const input = prefix + 'input/';
    if (attempt.capture !== null) captureDescriptor(attempt.capture);
    check(attempt.id === id && attempt.strategy === manifest.request.strategies[index] && attempt.state === 'FINALIZED' && OUTCOMES.includes(attempt.outcome), 'INCOMPLETE_ATTEMPTS');
    check(Array.isArray(attempt.reason_codes) && attempt.reason_codes.length >= 1 && attempt.reason_codes.length <= 16
      && attempt.reason_codes.every(v => typeof v === 'string' && /^[A-Z][A-Z0-9_]{0,95}$/.test(v)) && new Set(attempt.reason_codes).size === attempt.reason_codes.length);
    check(Array.isArray(attempt.argv) && attempt.argv.length <= 128 && attempt.argv.every(v => string(v, 8192)) && isObject(attempt.environment));
    check((attempt.started_at === null || string(attempt.started_at, 128)) && string(attempt.finished_at, 128)
      && (attempt.exit_code === null || integer(attempt.exit_code, -2147483648, 2147483647)));
    if (own(attempt, 'cleanup_confirmed')) check(attempt.cleanup_confirmed === null || typeof attempt.cleanup_confirmed === 'boolean');
    inventory(attempt.artifacts); check(same(attempt.artifacts, outerInventory.filter(i => i.path.startsWith(prefix))), 'ATTEMPT_INVENTORY_MISMATCH');
    const required = ['config.json', 'engine_worker.py', 'engine_worker_v1.py', 'accounting_collector.py', 'data/BTC_USDT-5m.json', `strategies/${attempt.strategy}.py`];
    for (const path of [...required.map(v => input + v), input + 'request.json', prefix + 'stdout.log', prefix + 'stderr.log', ...OUTPUTS.map(v => prefix + 'output/' + v), ...ORACLE_FILES.map(v => prefix + 'accounting/' + v)]) allowedPaths.add(path);
    const requestRaw = buffers.get(input + 'request.json');
    if (!requestRaw) {
      check(attempt.outcome === 'SKIPPED' && !attempt.argv.length && attempt.exit_code === null && attempt.started_at === null
        && attempt.artifacts.every(item => item.path.startsWith(input)) && Object.keys(attempt.environment).length === 0, 'MISSING_INPUT');
      // A staging failure can retain a partial input directory before a request
      // exists. Keep that skipped attempt and report each absent prerequisite.
      if (buffers.has(input + 'config.json')) check(equalBytes(buffers.get(input + 'config.json'), configBytes(manifest.request)), 'CONFIGURATION_MISMATCH');
      if (buffers.has(input + 'data/BTC_USDT-5m.json')) validateCandles(buffers.get(input + 'data/BTC_USDT-5m.json'));
      for (const path of [input + 'engine_worker.py', input + 'engine_worker_v1.py', input + 'accounting_collector.py', input + `strategies/${attempt.strategy}.py`]) {
        if (buffers.has(path)) check(buffers.get(path).length <= 256 * 1024, 'FILE_LIMIT_EXCEEDED');
      }
      missing.push(...[input + 'request.json', ...required.map(name => input + name)].filter(path => !buffers.has(path))); accounting.push(accountingMissing(attempt, 'MISSING_CAPTURE')); continue;
    }
    const expected = manifest.inputs.filter(i => i.path.startsWith(input) && i.path !== input + 'request.json').map(i => ({ ...i, path: i.path.slice(input.length) }));
    check(expected.length === 6 && same(expected.map(i => i.path).sort(), [...required].sort()), 'MISSING_REQUIRED_INPUT');
    const request = jsonBytes(requestRaw, 4 * MiB); validateRequest(request, true);
    const declared = { ...manifest.request, strategy: attempt.strategy, input_inventory: expected, schema: 'n170.freqtrade-request.v2', run_id: manifest.run_id, attempt_id: attempt.id }; delete declared.strategies;
    check(same(request, declared), 'INPUT_INVENTORY_MISMATCH');
    const config = buffers.get(input + 'config.json'); jsonBytes(config, 4 * MiB);
    check(equalBytes(config, configBytes(request)), 'CONFIGURATION_MISMATCH');
    check(['engine_worker.py', 'engine_worker_v1.py', 'accounting_collector.py', `strategies/${attempt.strategy}.py`]
      .every(path => buffers.get(input + path).length <= 256 * 1024), 'FILE_LIMIT_EXCEEDED');
    validateCandles(buffers.get(input + 'data/BTC_USDT-5m.json'));
    const container = 'n170-' + manifest.run_id + '-' + id;
    if (attempt.argv.length) {
      const root = manifest.execution_root.replace(/\/+$/, '');
      check(same(attempt.argv, invocation(attempt.argv[0], engine.image_id, root + '/' + input.slice(0, -1), container)), 'INVOCATION_MISMATCH');
      check(buffers.has(prefix + 'stdout.log') && buffers.has(prefix + 'stderr.log'), 'MISSING_EXECUTION_LOG');
      check(attempt.started_at !== null && attempt.container_name === container, 'MISSING_EXECUTION_RECEIPT');
    }
    const retained = Object.fromEntries([...buffers].filter(([path]) => path.startsWith(prefix + 'output/')).map(([path, raw]) => [path.slice((prefix + 'output/').length), raw]));
    let transport = null; let transportInvalid = false;
    try { transport = outputTransport(buffers.get(prefix + 'stdout.log')); } catch { transportInvalid = true; }
    if (transportInvalid) check(['INVALID_OUTPUT', 'FAILED', 'TIMED_OUT', 'CANCELLED'].includes(attempt.outcome) && !Object.keys(retained).length, 'OUTPUT_TRANSPORT_MISMATCH');
    else if (!['TIMED_OUT', 'CANCELLED'].includes(attempt.outcome) || Object.keys(retained).length) {
      check(same(Object.keys(transport || {}).sort(), Object.keys(retained).sort())
        && Object.entries(transport || {}).every(([name, raw]) => equalBytes(raw, retained[name])), 'OUTPUT_TRANSPORT_MISMATCH');
    }
    let worker = null; let workerInvalid = false;
    if (retained['worker-result.json']) { try { worker = jsonBytes(retained['worker-result.json'], 2 * MiB); } catch { workerInvalid = true; } }
    if (workerInvalid) check(['INVALID_OUTPUT', 'FAILED', 'TIMED_OUT', 'CANCELLED'].includes(attempt.outcome), 'INVALID_WORKER_RECEIPT');
    for (const name of ['effective-config.json', 'market-metadata.json']) if (retained[name]) {
      try { jsonBytes(retained[name], 2 * MiB); } catch { check(['INVALID_OUTPUT', 'FAILED', 'TIMED_OUT', 'CANCELLED'].includes(attempt.outcome), 'INVALID_ARTIFACT_JSON'); }
    }
    if (worker !== null) {
      await workerRelationships(worker, attempt, request, requestRaw, expected, retained);
      const capture = await captureBinding(worker, attempt, request, requestRaw, expected, retained);
      accounting.push({ id: attempt.id, detector_status: attempt.outcome, ...assessCapture(capture, manifest, attempt, request, buffers.get(input + 'data/BTC_USDT-5m.json'), retained['effective-config.json']) });
    } else {
      check(attempt.capture === null, 'CAPTURE_WITHOUT_WORKER');
      accounting.push(accountingMissing(attempt, 'MISSING_CAPTURE'));
    }
    accounting.at(-1).oracle = await assessOracle(accounting.at(-1), buffers, prefix + 'accounting/');
    if ([...ASSESSABLE, 'INSUFFICIENT', 'MISSING_OUTPUT', 'INVALID_OUTPUT', 'INPUT_CHANGED'].includes(attempt.outcome)) {
      const computed = workerInvalid ? 'INVALID_OUTPUT' : worker === null ? (transportInvalid ? 'INVALID_OUTPUT' : 'MISSING_OUTPUT')
        : await classifyWorker(worker, retained['lookahead.csv'], attempt.strategy, request, expected, requestRaw);
      check(attempt.exit_code === 0 && computed === attempt.outcome, 'OUTCOME_MISMATCH');
    }
    if (ASSESSABLE.includes(attempt.outcome)) {
      check(attempt.argv.length > 0 && attempt.cleanup_confirmed === null && same(attempt.environment, { ...environment(request.timeout_seconds), observed: worker.environment }), 'INVALID_ENVIRONMENT_RECEIPT');
      check(retained['effective-config.json'] && retained['market-metadata.json'] && worker.effective_config_sha256
        && worker.offline_adapter?.market_metadata_sha256, 'MISSING_OUTPUT');
      check(worker.offline_adapter.scope === 'original synthetic BTC/USDT spot market metadata' && worker.offline_adapter.detector_modified === false, 'UNSUPPORTED_METHOD');
    }
    if (attempt.outcome === 'SKIPPED') check(!attempt.argv.length && attempt.exit_code === null, 'OUTCOME_MISMATCH');
    if (attempt.outcome === 'FAILED') check(attempt.exit_code !== 0 || worker?.outcome === 'FAILED'
      || attempt.reason_codes.some(code => ['RUNNER_ERROR', 'PROCESS_ERROR', 'OUTPUT_LIMIT'].includes(code)), 'OUTCOME_MISMATCH');
    if (['TIMED_OUT', 'CANCELLED'].includes(attempt.outcome)) check(attempt.argv.length > 0
      && attempt.reason_codes.some(code => code === attempt.outcome || (attempt.outcome === 'CANCELLED' && code === 'RUN_CANCELLED')), 'OUTCOME_MISMATCH');
  }
  check(outerInventory.every(i => allowedPaths.has(i.path)), 'UNSUPPORTED_ARTIFACT');
  if (engine.image_id === 'sha256:' + '0'.repeat(64)) missing.push('pinned_engine_image_identity');
  const summary = summarize(manifest.attempts); check(same(manifest.summary, summary), 'SUMMARY_MISMATCH');
  return { summary, missing, accounting };
}

/** Independently verify exact supplied bytes; validity never authenticates a run. */
export async function verifyRunReviewV2(text, { manifestSha256 } = {}) {
  const report = { schema: 'n170.run-review-verification.v2', integrity: 'INVALID', status: 'NOT_ASSESSABLE',
    manifest_sha256: null, manifest_pin: manifestSha256 === undefined ? 'not_supplied' : 'mismatched_or_invalid',
    summary: null, attempts: [], artifacts: [], reproducibility: { status: 'NOT_REPRODUCIBLE', missing: ['VALID_RUN_REVIEW_PACKAGE'] },
    trust: { ...REPORT_TRUST }, reason_codes: ['INVALID_OR_INCOMPLETE_RUN_BUNDLE'] };
  try {
    const envelope = strictJson(text, RUN_REVIEW_MAX_BYTES, true);
    shape(envelope, ['schema', 'manifest', 'artifacts']); check(envelope.schema === RUN_REVIEW_V2_SCHEMA, 'UNSUPPORTED_SCHEMA');
    check(Array.isArray(envelope.artifacts) && envelope.artifacts.length <= 128, 'INVALID_INVENTORY');
    const descriptors = [envelope.manifest, ...envelope.artifacts];
    let total = 0; const buffers = new Map(); const outerInventory = [];
    for (const [index, item] of descriptors.entries()) {
      shape(item, ['path', 'size', 'sha256', 'base64']); safePath(item.path);
      const limit = index === 0 ? 4 * MiB : 16 * MiB;
      check(integer(item.size, 0, limit) && hash(item.sha256), 'INVALID_INVENTORY');
      if (index === 0) check(item.path === 'manifest.json', 'INVALID_INVENTORY');
      else check(item.path.toLowerCase() !== 'manifest.json', 'INVALID_INVENTORY');
      total += item.size; check(total <= 64 * MiB, 'TOTAL_LIMIT_EXCEEDED');
      const raw = unbase64(item.base64, limit);
      check(raw.length === item.size && await digest(raw) === item.sha256, 'ARTIFACT_MISMATCH');
      check(!buffers.has(item.path), 'INVALID_INVENTORY'); buffers.set(item.path, raw);
      if (index > 0) outerInventory.push({ path: item.path, size: raw.length, sha256: item.sha256 });
    }
    inventory(outerInventory);
    check(!outerInventory.some(i => i.path.toLowerCase().startsWith('manifest.json/')), 'INVALID_PATH');
    report.manifest_sha256 = await digest(buffers.get('manifest.json'));
    if (manifestSha256 !== undefined) {
      check(hash(manifestSha256) && manifestSha256 === report.manifest_sha256, 'MANIFEST_PIN_MISMATCH'); report.manifest_pin = 'matched';
    }
    const manifest = jsonBytes(buffers.get('manifest.json'), 4 * MiB); buffers.delete('manifest.json');
    const { summary, missing, accounting } = await validateManifest(manifest, buffers, outerInventory);
    report.accounting = { status: 'NOT_ASSESSABLE', attempts: accounting };
    report.integrity = 'VALID'; report.status = summary.status; report.summary = summary;
    report.attempts = manifest.attempts.map(a => ({ id: a.id, strategy: a.strategy, state: a.state, outcome: a.outcome, reason_codes: [...a.reason_codes], exit_code: a.exit_code }));
    report.artifacts = outerInventory;
    report.reproducibility = { status: missing.length ? 'NOT_REPRODUCIBLE' : 'READY_TO_RERUN', missing };
    report.reason_codes = ['PACKAGE_BYTES_AND_RECEIPT_CONSISTENT', ...(summary.status === 'NOT_ASSESSABLE' ? ['UNASSESSABLE_ATTEMPTS'] : []), ...(missing.length ? ['MISSING_REPRODUCTION_PREREQUISITES'] : [])];
  } catch (error) {
    // Only fixed machine codes escape; supplied text and parser exception text
    // can contain private input, so never expose arbitrary exception messages.
    const code = error instanceof Error && /^[A-Z][A-Z0-9_]{1,80}$/.test(error.message) ? error.message : 'INVALID_OR_INCOMPLETE_RUN_BUNDLE';
    report.reason_codes = [code];
  }
  return report;
}
