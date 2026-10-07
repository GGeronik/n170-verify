// Original Apache-2.0 independent recipient verifier. This module processes data
// only: no execution, imports of supplied code, network, extraction, or storage.
export const RUN_REVIEW_MAX_BYTES = 96 * 1024 * 1024;
export const RUN_REVIEW_SCHEMA = 'n170.run-review.v1';
const MiB = 1024 * 1024;
const REVISION = '9f10e357a93c1dcf10c2a2b367659214d89c073e';
const SOURCE_HASH = 'a96f980268301b69f8fb6e423d27606ede3f174449f63ff672aebb48f97ac6de';
const ASSESSABLE = ['NO_FINDINGS_REPORTED', 'FINDINGS_REPORTED'];
const OUTCOMES = [...ASSESSABLE, 'INSUFFICIENT', 'FAILED', 'TIMED_OUT', 'CANCELLED', 'SKIPPED', 'MISSING_OUTPUT', 'INVALID_OUTPUT', 'INPUT_CHANGED'];
const OUTPUTS = ['effective-config.json', 'lookahead.csv', 'market-metadata.json', 'worker-result.json'];
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
  shape(request, [...(attempt ? ['strategy', 'input_inventory'] : ['strategies']), 'timeout_seconds', 'minimum_trade_amount',
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
  if (!isObject(worker) || worker.schema !== 'n170.freqtrade-worker.v1' || worker.strategy !== strategy) return 'INVALID_OUTPUT';
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
  for (const [key, wanted] of Object.entries({ schema: 'n170.freqtrade-worker.v1', strategy: attempt.strategy,
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
  const prefix = encoder.encode('N170_RESULT_BUNDLE_V1:');
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
  check(encoded.length <= 4 * MiB, 'OUTPUT_TRANSPORT_MISMATCH');
  const bundle = jsonBytes(unbase64(encoded, 4 * MiB), 4 * MiB);
  shape(bundle, ['worker-result.json'], OUTPUTS.filter(name => name !== 'worker-result.json'));
  return Object.fromEntries(Object.entries(bundle).map(([name, value]) => [name, unbase64(value, 2 * MiB)]));
}
function summarize(attempts) {
  const counts = Object.fromEntries([...OUTCOMES].sort().map(outcome => [outcome, attempts.filter(a => a.outcome === outcome).length]));
  const completed = attempts.length > 0 && attempts.every(a => ASSESSABLE.includes(a.outcome));
  return { status: completed ? (counts.FINDINGS_REPORTED ? 'FINDINGS_REPORTED' : 'NO_FINDINGS_REPORTED') : 'NOT_ASSESSABLE',
    selected_count: attempts.length, assessed_count: counts.NO_FINDINGS_REPORTED + counts.FINDINGS_REPORTED,
    findings_count: counts.FINDINGS_REPORTED, outcome_counts: counts };
}

async function validateManifest(manifest, buffers, outerInventory) {
  shape(manifest, ['schema', 'run_id', 'execution_root', 'state', 'started_at', 'finished_at', 'engine', 'request', 'inputs', 'artifacts', 'attempts', 'summary', 'trust']);
  check(manifest.schema === 'n170.freqtrade-run.v1' && manifest.state === 'FINALIZED', 'INCOMPLETE_MANIFEST');
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
  const allowedPaths = new Set(); const missing = [];
  for (const [index, attempt] of manifest.attempts.entries()) {
    shape(attempt, ['id', 'strategy', 'state', 'outcome', 'reason_codes', 'argv', 'environment', 'started_at', 'finished_at', 'exit_code', 'artifacts'], ['container_name', 'cleanup_confirmed']);
    const id = String(index).padStart(3, '0'); const prefix = `attempts/${id}/`; const input = prefix + 'input/';
    check(attempt.id === id && attempt.strategy === manifest.request.strategies[index] && attempt.state === 'FINALIZED' && OUTCOMES.includes(attempt.outcome), 'INCOMPLETE_ATTEMPTS');
    check(Array.isArray(attempt.reason_codes) && attempt.reason_codes.length >= 1 && attempt.reason_codes.length <= 16
      && attempt.reason_codes.every(v => typeof v === 'string' && /^[A-Z][A-Z0-9_]{0,95}$/.test(v)) && new Set(attempt.reason_codes).size === attempt.reason_codes.length);
    check(Array.isArray(attempt.argv) && attempt.argv.length <= 128 && attempt.argv.every(v => string(v, 8192)) && isObject(attempt.environment));
    check((attempt.started_at === null || string(attempt.started_at, 128)) && string(attempt.finished_at, 128)
      && (attempt.exit_code === null || integer(attempt.exit_code, -2147483648, 2147483647)));
    if (own(attempt, 'cleanup_confirmed')) check(attempt.cleanup_confirmed === null || typeof attempt.cleanup_confirmed === 'boolean');
    inventory(attempt.artifacts); check(same(attempt.artifacts, outerInventory.filter(i => i.path.startsWith(prefix))), 'ATTEMPT_INVENTORY_MISMATCH');
    const required = ['config.json', 'engine_worker.py', 'data/BTC_USDT-5m.json', `strategies/${attempt.strategy}.py`];
    for (const path of [...required.map(v => input + v), input + 'request.json', prefix + 'stdout.log', prefix + 'stderr.log', ...OUTPUTS.map(v => prefix + 'output/' + v)]) allowedPaths.add(path);
    const requestRaw = buffers.get(input + 'request.json');
    if (!requestRaw) {
      check(attempt.outcome === 'SKIPPED' && !attempt.argv.length && attempt.exit_code === null && attempt.started_at === null
        && attempt.artifacts.every(item => item.path.startsWith(input)) && Object.keys(attempt.environment).length === 0, 'MISSING_INPUT');
      // A staging failure can retain a partial input directory before a request
      // exists. Keep that skipped attempt and report each absent prerequisite.
      if (buffers.has(input + 'config.json')) check(equalBytes(buffers.get(input + 'config.json'), configBytes(manifest.request)), 'CONFIGURATION_MISMATCH');
      if (buffers.has(input + 'data/BTC_USDT-5m.json')) validateCandles(buffers.get(input + 'data/BTC_USDT-5m.json'));
      for (const path of [input + 'engine_worker.py', input + `strategies/${attempt.strategy}.py`]) {
        if (buffers.has(path)) check(buffers.get(path).length <= 256 * 1024, 'FILE_LIMIT_EXCEEDED');
      }
      missing.push(...[input + 'request.json', ...required.map(name => input + name)].filter(path => !buffers.has(path))); continue;
    }
    const expected = manifest.inputs.filter(i => i.path.startsWith(input) && i.path !== input + 'request.json').map(i => ({ ...i, path: i.path.slice(input.length) }));
    check(expected.length === 4 && same(expected.map(i => i.path).sort(), [...required].sort()), 'MISSING_REQUIRED_INPUT');
    const request = jsonBytes(requestRaw, 4 * MiB); validateRequest(request, true);
    const declared = { ...manifest.request, strategy: attempt.strategy, input_inventory: expected }; delete declared.strategies;
    check(same(request, declared), 'INPUT_INVENTORY_MISMATCH');
    const config = buffers.get(input + 'config.json'); jsonBytes(config, 4 * MiB);
    check(equalBytes(config, configBytes(request)), 'CONFIGURATION_MISMATCH');
    check(buffers.get(input + 'engine_worker.py').length <= 256 * 1024 && buffers.get(input + `strategies/${attempt.strategy}.py`).length <= 256 * 1024, 'FILE_LIMIT_EXCEEDED');
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
    if (worker !== null) await workerRelationships(worker, attempt, request, requestRaw, expected, retained);
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
  return { summary, missing };
}

/** Independently verify exact supplied bytes; validity never authenticates a run. */
export async function verifyRunReview(text, { manifestSha256 } = {}) {
  const report = { schema: 'n170.run-review-verification.v1', integrity: 'INVALID', status: 'NOT_ASSESSABLE',
    manifest_sha256: null, manifest_pin: manifestSha256 === undefined ? 'not_supplied' : 'mismatched_or_invalid',
    summary: null, attempts: [], artifacts: [], reproducibility: { status: 'NOT_REPRODUCIBLE', missing: ['VALID_RUN_REVIEW_PACKAGE'] },
    trust: { ...REPORT_TRUST }, reason_codes: ['INVALID_OR_INCOMPLETE_RUN_BUNDLE'] };
  try {
    const envelope = strictJson(text, RUN_REVIEW_MAX_BYTES, true);
    shape(envelope, ['schema', 'manifest', 'artifacts']); check(envelope.schema === RUN_REVIEW_SCHEMA, 'UNSUPPORTED_SCHEMA');
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
    const { summary, missing } = await validateManifest(manifest, buffers, outerInventory);
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
