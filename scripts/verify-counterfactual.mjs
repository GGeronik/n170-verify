#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { TextDecoder } from 'node:util';

export const COUNTERFACTUAL_VERSION = 'n170.verify.counterfactual-attribution.v1';
export const COUNTERFACTUAL_INPUT_SCHEMA = 'n170.verify.counterfactual-input.v1';
export const LEAN_MANIFEST_SCHEMA = 'n170.verify.lean-replay-manifest.v1';

const USAGE =
  'Usage: node scripts/verify-counterfactual.mjs INPUT.json\nOffline 4-book counterfactual attribution, LEAN replay manifest, and behavioral pattern verifier.\n';
const MAX_INPUT_BYTES = 16000000;
const FREQUENCIES = new Set([1, 4, 12, 52, 252, 365, 366]);
const SAFE_INTEGER = 9007199254740991;
const BOOK_NAMES = Object.freeze(['ACTUAL', 'MIRROR_SHADOW', 'CLEAN_SHADOW', 'FIXED_BENCHMARK']);
const PROHIBITED_KEYS = new Set([
  'ticker',
  'tickers',
  'symbol',
  'symbols',
  'isin',
  'cusip',
  'positions',
  'holdings',
  'nav_amount',
  'dollar_value',
  'cash_balance',
  'account_id',
  'account_number',
  'strategy_code',
  'algorithm_source',
  'factor_weights',
  'prompts',
]);

export function fsum(values) {
  const partials = [];
  for (let x of values) {
    if (!Number.isFinite(x)) return NaN;
    let used = 0;
    for (let y of partials) {
      if (Math.abs(x) < Math.abs(y)) [x, y] = [y, x];
      const high = x + y;
      if (!Number.isFinite(high)) return NaN;
      const low = y - (high - x);
      if (low !== 0) partials[used++] = low;
      x = high;
    }
    partials.length = used;
    if (x !== 0) partials.push(x);
  }
  let remaining = partials.length;
  if (remaining === 0) return 0;
  let high = partials[--remaining];
  let low = 0;
  while (remaining > 0) {
    const x = high;
    const y = partials[--remaining];
    high = x + y;
    low = y - (high - x);
    if (low !== 0) break;
  }
  if (
    remaining > 0 &&
    ((low < 0 && partials[remaining - 1] < 0) ||
      (low > 0 && partials[remaining - 1] > 0))
  ) {
    const twiceLow = low * 2;
    const rounded = high + twiceLow;
    if (rounded - high === twiceLow) high = rounded;
  }
  return high;
}

function sha256Hex(input) {
  return createHash('sha256').update(input).digest('hex');
}

function sha256Bytes(input) {
  return createHash('sha256').update(input).digest();
}

function deepFreeze(obj) {
  if (obj === null || typeof obj !== 'object' || Object.isFrozen(obj)) {
    return obj;
  }
  Object.freeze(obj);
  for (const value of Object.values(obj)) {
    deepFreeze(value);
  }
  return obj;
}

function finite(value) {
  if (!Number.isFinite(value)) {
    throw new RangeError('non-finite intermediate');
  }
  return value === 0 ? 0 : value;
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isStrictInt(value) {
  return typeof value === 'number' && Number.isInteger(value);
}

function isRealNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function isHex64(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function isEngineDigest(value) {
  return typeof value === 'string' && value.startsWith('sha256:') && isHex64(value.slice(7));
}

function isIsoDate(value) {
  if (typeof value !== 'string' || value.length !== 10) return false;
  if (value[4] !== '-' || value[7] !== '-') return false;
  const yyyy = value.slice(0, 4);
  const mm = value.slice(5, 7);
  const dd = value.slice(8, 10);
  if (!/^\d{4}$/.test(yyyy) || !/^\d{2}$/.test(mm) || !/^\d{2}$/.test(dd)) return false;
  const month = Number(mm);
  const day = Number(dd);
  return month >= 1 && month <= 12 && day >= 1 && day <= 31;
}

function findProhibitedKey(obj) {
  if (isPlainObject(obj)) {
    for (const [key, value] of Object.entries(obj)) {
      if (PROHIBITED_KEYS.has(key.toLowerCase())) {
        return key.toLowerCase();
      }
      const nested = findProhibitedKey(value);
      if (nested !== null) return nested;
    }
  } else if (Array.isArray(obj)) {
    for (const item of obj) {
      const nested = findProhibitedKey(item);
      if (nested !== null) return nested;
    }
  }
  return null;
}

export function computeMerkleRoot(hexLeaves) {
  let level = hexLeaves.map((leaf) =>
    sha256Bytes(Buffer.concat([Buffer.from([0x00]), Buffer.from(leaf, 'hex')])),
  );
  while (level.length > 1) {
    const nextLevel = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        nextLevel.push(
          sha256Bytes(Buffer.concat([Buffer.from([0x01]), level[i], level[i + 1]])),
        );
      } else {
        nextLevel.push(level[i]);
      }
    }
    level = nextLevel;
  }
  return level[0].toString('hex');
}

function computePatternProfileInternal(returnsE8, benchmarkE8, q) {
  const r = returnsE8.map((x) => finite(x / 100000000));
  const T = r.length;
  let win_intervals = 0;
  let loss_intervals = 0;
  let flat_intervals = 0;
  const pos = [];
  const neg_abs = [];
  for (const x of returnsE8) {
    if (x > 0) {
      win_intervals += 1;
      pos.push(finite(x / 100000000));
    } else if (x < 0) {
      loss_intervals += 1;
      neg_abs.push(finite(-x / 100000000));
    } else {
      flat_intervals += 1;
    }
  }
  const win_rate = finite(win_intervals / T);
  const sum_pos = finite(fsum(pos));
  const sum_neg_abs = finite(fsum(neg_abs));
  const gain_to_pain_ratio = sum_neg_abs > 0 ? finite(sum_pos / sum_neg_abs) : null;
  const mean_win = pos.length > 0 ? finite(sum_pos / pos.length) : null;
  const mean_loss_abs = neg_abs.length > 0 ? finite(sum_neg_abs / neg_abs.length) : null;
  const payoff_asymmetry =
    mean_win !== null && mean_loss_abs !== null && mean_loss_abs > 0
      ? finite(mean_win / mean_loss_abs)
      : null;

  let wealth = 1.0;
  let peak = 1.0;
  const dd_series = [];
  for (const rt of r) {
    wealth = finite(wealth * finite(1.0 + rt));
    if (wealth > peak) {
      peak = wealth;
    }
    const dd = finite(finite(peak - wealth) / peak);
    dd_series.push(dd);
  }

  const cumulative_return = finite(wealth - 1.0);
  const cagr = finite(finite(wealth ** finite(q / T)) - 1.0);
  let max_drawdown = 0;
  for (const d of dd_series) {
    if (d > max_drawdown) max_drawdown = d;
  }
  const ulcer_index = finite(
    Math.sqrt(finite(fsum(dd_series.map((d) => finite(d * d))) / T)),
  );

  let max_dd_duration = 0;
  let cur_dur = 0;
  for (const d of dd_series) {
    if (d > 0) {
      cur_dur += 1;
      if (cur_dur > max_dd_duration) {
        max_dd_duration = cur_dur;
      }
    } else {
      cur_dur = 0;
    }
  }

  let max_drawdown_recovery_intervals = null;
  let max_drawdown_recovered = false;
  if (max_drawdown === 0) {
    max_drawdown_recovery_intervals = 0;
    max_drawdown_recovered = true;
  } else {
    const trough_idx = dd_series.findIndex((d) => d === max_drawdown);
    let recovery_idx = -1;
    for (let j = trough_idx + 1; j < T; j += 1) {
      if (dd_series[j] === 0.0) {
        recovery_idx = j;
        break;
      }
    }
    if (recovery_idx !== -1) {
      max_drawdown_recovery_intervals = recovery_idx - trough_idx;
      max_drawdown_recovered = true;
    } else {
      max_drawdown_recovery_intervals = null;
      max_drawdown_recovered = false;
    }
  }

  const in_dd_r = [];
  const hw_r = [];
  for (let t = 1; t < T; t += 1) {
    if (dd_series[t - 1] > 0) {
      in_dd_r.push(r[t]);
    } else if (dd_series[t - 1] === 0) {
      hw_r.push(r[t]);
    }
  }
  const post_drawdown_rms_vol =
    in_dd_r.length >= 2
      ? finite(Math.sqrt(finite(fsum(in_dd_r.map((x) => finite(x * x))) / in_dd_r.length)))
      : null;
  const high_water_rms_vol =
    hw_r.length >= 2
      ? finite(Math.sqrt(finite(fsum(hw_r.map((x) => finite(x * x))) / hw_r.length)))
      : null;
  const post_drawdown_vol_scaling_ratio =
    post_drawdown_rms_vol !== null && high_water_rms_vol !== null && high_water_rms_vol > 0
      ? finite(post_drawdown_rms_vol / high_water_rms_vol)
      : null;

  let post_drawdown_behavior_code;
  if (post_drawdown_vol_scaling_ratio === null) {
    post_drawdown_behavior_code = 'INSUFFICIENT_REGIME_OBSERVATIONS';
  } else if (post_drawdown_vol_scaling_ratio < 0.95) {
    post_drawdown_behavior_code = 'DISCIPLINED_RISK_SCALING';
  } else if (post_drawdown_vol_scaling_ratio <= 1.15) {
    post_drawdown_behavior_code = 'NEUTRAL_RISK_SCALING';
  } else {
    post_drawdown_behavior_code = 'ELEVATED_POST_DRAWDOWN_RISK';
  }

  let upside_capture = null;
  let downside_capture = null;
  let capture_asymmetry = null;
  if (benchmarkE8 !== null && benchmarkE8 !== undefined) {
    const b = benchmarkE8.map((x) => finite(x / 100000000));
    const up_idx = [];
    const down_idx = [];
    for (let t = 0; t < T; t += 1) {
      if (benchmarkE8[t] > 0) up_idx.push(t);
      else if (benchmarkE8[t] < 0) down_idx.push(t);
    }
    if (up_idx.length > 0) {
      const up_book = finite(fsum(up_idx.map((t) => r[t])) / up_idx.length);
      const up_bench = finite(fsum(up_idx.map((t) => b[t])) / up_idx.length);
      if (up_bench > 0) {
        upside_capture = finite(up_book / up_bench);
      }
    }
    if (down_idx.length > 0) {
      const down_book = finite(fsum(down_idx.map((t) => r[t])) / down_idx.length);
      const down_bench = finite(fsum(down_idx.map((t) => b[t])) / down_idx.length);
      if (down_bench < 0) {
        downside_capture = finite(down_book / down_bench);
      }
    }
    if (upside_capture !== null && downside_capture !== null) {
      capture_asymmetry = finite(upside_capture - downside_capture);
    }
  }

  return {
    T,
    win_intervals,
    loss_intervals,
    flat_intervals,
    win_rate,
    gain_to_pain_ratio,
    mean_win,
    mean_loss_abs,
    payoff_asymmetry,
    cumulative_return,
    cagr,
    max_drawdown,
    ulcer_index,
    max_drawdown_duration_intervals: max_dd_duration,
    max_drawdown_recovery_intervals,
    max_drawdown_recovered,
    post_drawdown_rms_vol,
    high_water_rms_vol,
    post_drawdown_vol_scaling_ratio,
    post_drawdown_behavior_code,
    upside_capture,
    downside_capture,
    capture_asymmetry,
  };
}

export function verifyCounterfactualAttribution(fixtureInput, options = {}) {
  let fixture = fixtureInput;
  let fixture_sha256 =
    typeof options === 'string'
      ? options
      : isPlainObject(options) && typeof options.fixtureSha256 === 'string'
        ? options.fixtureSha256
        : null;

  if (typeof fixtureInput === 'string') {
    if (fixture_sha256 === null) {
      fixture_sha256 = sha256Hex(fixtureInput);
    }
    try {
      fixture = JSON.parse(fixtureInput);
    } catch {
      return deepFreeze({
        schema: COUNTERFACTUAL_VERSION,
        fixture: null,
        fixture_sha256,
        status: 'CF_INVALID_INPUT',
        reason_code: 'INVALID_JSON',
        T: null,
        periods_per_year: null,
        calendar_sha256: null,
        books: null,
        attribution: null,
        decision_chain_summary: null,
        lean_replay_verification: null,
      });
    }
  }

  const fixtureDict = isPlainObject(fixture) ? fixture : {};
  const rawBooks = fixtureDict.books;
  const rawActual = isPlainObject(rawBooks) ? rawBooks.ACTUAL : null;
  const rawQ = fixtureDict.periods_per_year;

  const result = {
    schema: COUNTERFACTUAL_VERSION,
    fixture: typeof fixtureDict.id === 'string' ? fixtureDict.id : null,
    fixture_sha256,
    status: 'CF_INVALID_INPUT',
    reason_code: 'INVALID_INPUT',
    T: Array.isArray(rawActual) ? rawActual.length : null,
    periods_per_year: isStrictInt(rawQ) && FREQUENCIES.has(rawQ) ? rawQ : null,
    calendar_sha256: null,
    books: null,
    attribution: null,
    decision_chain_summary: null,
    lean_replay_verification: null,
  };

  // 1. Prohibited Disclosure Field Check (First!)
  const prohibited = findProhibitedKey(fixture);
  if (prohibited !== null) {
    result.status = 'CF_PROHIBITED_DISCLOSURE_FIELD';
    result.reason_code = `PROHIBITED_FIELD:${prohibited}`;
    return deepFreeze(result);
  }

  // 2. Schema & Frequency Validation
  if (!isPlainObject(fixture) || fixture.schema !== COUNTERFACTUAL_INPUT_SCHEMA) {
    result.status = 'CF_INVALID_INPUT';
    result.reason_code = 'INVALID_SCHEMA';
    return deepFreeze(result);
  }

  const q = fixture.periods_per_year;
  if (!isStrictInt(q) || !FREQUENCIES.has(q)) {
    result.status = 'CF_INVALID_INPUT';
    result.reason_code = 'INVALID_FREQUENCY';
    return deepFreeze(result);
  }

  const booksIn = fixture.books;
  if (!isPlainObject(booksIn)) {
    result.status = 'CF_INVALID_INPUT';
    result.reason_code = 'INVALID_BOOK_SET';
    return deepFreeze(result);
  }

  const bookKeys = Object.keys(booksIn);
  const keySet = new Set(bookKeys);
  const validSingle =
    (keySet.size === 1 && keySet.has('ACTUAL')) ||
    (keySet.size === 2 && keySet.has('ACTUAL') && keySet.has('FIXED_BENCHMARK'));
  const validFour =
    keySet.size === BOOK_NAMES.length && BOOK_NAMES.every((name) => keySet.has(name));
  if (!validSingle && !validFour) {
    result.status = 'CF_INVALID_INPUT';
    result.reason_code = 'INVALID_BOOK_SET';
    return deepFreeze(result);
  }

  const actual = booksIn.ACTUAL;
  if (!Array.isArray(actual) || actual.length < 4) {
    result.status = 'CF_INVALID_INPUT';
    result.reason_code = 'SAMPLE_TOO_SHORT';
    return deepFreeze(result);
  }

  for (const bname of BOOK_NAMES) {
    if (Object.hasOwn(booksIn, bname) && !Array.isArray(booksIn[bname])) {
      result.status = 'CF_INVALID_INPUT';
      result.reason_code = 'INVALID_BOOK_SET';
      return deepFreeze(result);
    }
  }

  const T = actual.length;
  result.T = T;

  // 3. Calendar & Return Series Validation
  for (let t = 0; t < T; t += 1) {
    const item = actual[t];
    if (!isPlainObject(item)) {
      result.status = 'CF_INVALID_INPUT';
      result.reason_code = 'INVALID_INTERVAL_OBJECT';
      return deepFreeze(result);
    }
    const { start, end } = item;
    if (!isIsoDate(start) || !isIsoDate(end) || !(start < end)) {
      result.status = 'CF_CALENDAR_MISMATCH';
      result.reason_code = 'NON_CHRONOLOGICAL_INTERVALS';
      return deepFreeze(result);
    }
    if (t > 0 && actual[t - 1].end > start) {
      result.status = 'CF_CALENDAR_MISMATCH';
      result.reason_code = 'NON_CHRONOLOGICAL_INTERVALS';
      return deepFreeze(result);
    }
  }

  for (const bname of BOOK_NAMES) {
    if (!Object.hasOwn(booksIn, bname)) continue;
    const series = booksIn[bname];
    if (series.length !== T) {
      result.status = 'CF_CALENDAR_MISMATCH';
      result.reason_code = 'BOOK_CALENDAR_MISMATCH';
      return deepFreeze(result);
    }
    for (let t = 0; t < T; t += 1) {
      const entry = series[t];
      if (!isPlainObject(entry)) {
        result.status = 'CF_INVALID_INPUT';
        result.reason_code = 'INVALID_INTERVAL_OBJECT';
        return deepFreeze(result);
      }
      if (entry.start !== actual[t].start || entry.end !== actual[t].end) {
        result.status = 'CF_CALENDAR_MISMATCH';
        result.reason_code = 'BOOK_CALENDAR_MISMATCH';
        return deepFreeze(result);
      }
    }
  }

  for (const bname of BOOK_NAMES) {
    if (!Object.hasOwn(booksIn, bname)) continue;
    for (const entry of booksIn[bname]) {
      const x = entry.return_e8;
      if (!isStrictInt(x) || Math.abs(x) > SAFE_INTEGER || x <= -100000000) {
        result.status = 'CF_INVALID_INPUT';
        result.reason_code = 'INVALID_RETURN_E8';
        return deepFreeze(result);
      }
    }
  }

  const calendarPairs = actual.map((item) => [item.start, item.end]);
  const calendar_sha256 = sha256Hex(JSON.stringify(calendarPairs));
  result.calendar_sha256 = calendar_sha256;

  try {
    // 4. Decision Log Verification (Optional)
    let decision_chain_summary = null;
    const decisionLog = fixture.decision_log;
    if (decisionLog !== undefined && decisionLog !== null) {
      if (!isPlainObject(decisionLog)) {
        result.status = 'CF_DECISION_CHAIN_BROKEN';
        result.reason_code = 'INVALID_DECISION_LOG';
        return deepFreeze(result);
      }
      const { intervals, head_chain_sha256: headChain } = decisionLog;
      if (!Array.isArray(intervals) || intervals.length !== T || !isHex64(headChain)) {
        result.status = 'CF_DECISION_CHAIN_BROKEN';
        result.reason_code = 'INVALID_DECISION_LOG';
        return deepFreeze(result);
      }

      for (let t = 0; t < T; t += 1) {
        const d = intervals[t];
        if (!isPlainObject(d)) {
          result.status = 'CF_DECISION_CHAIN_BROKEN';
          result.reason_code = `CHAIN_HASH_MISMATCH_AT_${t}`;
          return deepFreeze(result);
        }
        if (d.start !== actual[t].start || d.end !== actual[t].end) {
          result.status = 'CF_CALENDAR_MISMATCH';
          result.reason_code = 'BOOK_CALENDAR_MISMATCH';
          return deepFreeze(result);
        }
        const acc = d.accepted_count;
        const mod = d.modified_count;
        const rej = d.rejected_count;
        if (
          ![acc, mod, rej].every(
            (c) => isStrictInt(c) && c >= 0 && c <= SAFE_INTEGER,
          )
        ) {
          result.status = 'CF_DECISION_CHAIN_BROKEN';
          result.reason_code = `INVALID_DECISION_COUNTS_AT_${t}`;
          return deepFreeze(result);
        }
        const dsetSha = d.decision_set_sha256;
        const chainSha = d.chain_sha256;
        if (!isHex64(dsetSha) || !isHex64(chainSha)) {
          result.status = 'CF_DECISION_CHAIN_BROKEN';
          result.reason_code = `CHAIN_HASH_MISMATCH_AT_${t}`;
          return deepFreeze(result);
        }
        const prevChain = t === 0 ? '0'.repeat(64) : intervals[t - 1].chain_sha256;
        const preimage = `${prevChain}:${d.start}:${d.end}:${acc}:${mod}:${rej}:${dsetSha}`;
        const expectedChain = sha256Hex(preimage);
        if (chainSha !== expectedChain) {
          result.status = 'CF_DECISION_CHAIN_BROKEN';
          result.reason_code = `CHAIN_HASH_MISMATCH_AT_${t}`;
          return deepFreeze(result);
        }
      }

      if (headChain !== intervals[T - 1].chain_sha256) {
        result.status = 'CF_DECISION_CHAIN_BROKEN';
        result.reason_code = 'HEAD_CHAIN_HASH_MISMATCH';
        return deepFreeze(result);
      }

      const merkle_root_sha256 = computeMerkleRoot(
        intervals.map((d) => d.decision_set_sha256),
      );
      let total_accepted = 0;
      let total_modified = 0;
      let total_rejected = 0;
      for (const d of intervals) {
        total_accepted += d.accepted_count;
        total_modified += d.modified_count;
        total_rejected += d.rejected_count;
      }
      const total_proposals = total_accepted + total_modified + total_rejected;
      const acceptance_rate =
        total_proposals > 0 ? finite(total_accepted / total_proposals) : null;
      const modification_rate =
        total_proposals > 0 ? finite(total_modified / total_proposals) : null;
      const rejection_rate =
        total_proposals > 0 ? finite(total_rejected / total_proposals) : null;

      decision_chain_summary = {
        verified: true,
        intervals: T,
        total_proposals,
        total_accepted,
        total_modified,
        total_rejected,
        acceptance_rate,
        modification_rate,
        rejection_rate,
        head_chain_sha256: headChain,
        merkle_root_sha256,
      };
    }

    // 5. QuantConnect LEAN Replay Manifest Verification (Optional)
    let lean_replay_verification = null;
    const lm = fixture.lean_manifest;
    if (lm !== undefined && lm !== null) {
      if (!isPlainObject(lm) || lm.schema !== LEAN_MANIFEST_SCHEMA) {
        result.status = 'CF_LEAN_MANIFEST_INVALID';
        result.reason_code = 'LEAN_SCHEMA_INVALID';
        return deepFreeze(result);
      }
      const targetBook = lm.target_book;
      if (
        (targetBook !== 'CLEAN_SHADOW' && targetBook !== 'MIRROR_SHADOW') ||
        !Object.hasOwn(booksIn, targetBook)
      ) {
        result.status = 'CF_LEAN_MANIFEST_INVALID';
        result.reason_code = 'LEAN_TARGET_BOOK_INVALID';
        return deepFreeze(result);
      }
      const engineImageDigest = lm.engine_image_digest;
      if (!isEngineDigest(engineImageDigest)) {
        result.status = 'CF_LEAN_MANIFEST_INVALID';
        result.reason_code = 'LEAN_ENGINE_DIGEST_INVALID';
        return deepFreeze(result);
      }
      if (lm.calendar_sha256 !== calendar_sha256) {
        result.status = 'CF_LEAN_MANIFEST_INVALID';
        result.reason_code = 'LEAN_CALENDAR_HASH_MISMATCH';
        return deepFreeze(result);
      }
      const costPolicyBps = lm.cost_policy_bps;
      if (!isRealNumber(costPolicyBps) || costPolicyBps < 0 || costPolicyBps > 1000) {
        result.status = 'CF_LEAN_MANIFEST_INVALID';
        result.reason_code = 'LEAN_COST_POLICY_INVALID';
        return deepFreeze(result);
      }
      const inputMerkle = lm.input_commitments_merkle_root;
      if (!isHex64(inputMerkle)) {
        result.status = 'CF_LEAN_MANIFEST_INVALID';
        result.reason_code = 'LEAN_MERKLE_ROOT_MISMATCH';
        return deepFreeze(result);
      }
      if (
        decision_chain_summary !== null &&
        inputMerkle !== decision_chain_summary.merkle_root_sha256
      ) {
        result.status = 'CF_LEAN_MANIFEST_INVALID';
        result.reason_code = 'LEAN_MERKLE_ROOT_MISMATCH';
        return deepFreeze(result);
      }
      const targetReturnsE8 = booksIn[targetBook].map((item) => item.return_e8);
      const expectedOutputSha256 = sha256Hex(JSON.stringify(targetReturnsE8));
      if (lm.output_returns_sha256 !== expectedOutputSha256) {
        result.status = 'CF_LEAN_MANIFEST_INVALID';
        result.reason_code = 'LEAN_OUTPUT_HASH_MISMATCH';
        return deepFreeze(result);
      }
      const canonicalManifest = {
        calendar_sha256: lm.calendar_sha256,
        cost_policy_bps: lm.cost_policy_bps,
        engine_image_digest: lm.engine_image_digest,
        input_commitments_merkle_root: lm.input_commitments_merkle_root,
        output_returns_sha256: lm.output_returns_sha256,
        schema: LEAN_MANIFEST_SCHEMA,
        target_book: lm.target_book,
      };
      const expectedManifestSha256 = sha256Hex(JSON.stringify(canonicalManifest));
      if (lm.manifest_sha256 !== expectedManifestSha256) {
        result.status = 'CF_LEAN_MANIFEST_INVALID';
        result.reason_code = 'LEAN_MANIFEST_HASH_MISMATCH';
        return deepFreeze(result);
      }
      lean_replay_verification = {
        verified: true,
        ...canonicalManifest,
        manifest_sha256: expectedManifestSha256,
      };
    }

    // 6. Pattern Profile per Book
    const benchmarkE8 = Object.hasOwn(booksIn, 'FIXED_BENCHMARK')
      ? booksIn.FIXED_BENCHMARK.map((item) => item.return_e8)
      : null;
    const booksOut = {};
    for (const bname of BOOK_NAMES) {
      if (Object.hasOwn(booksIn, bname)) {
        const bE8 = booksIn[bname].map((item) => item.return_e8);
        booksOut[bname] = computePatternProfileInternal(bE8, benchmarkE8, q);
      }
    }

    // 7. Four-Book Counterfactual Attribution
    let attribution = null;
    if (validFour) {
      const actualE8 = booksIn.ACTUAL.map((item) => item.return_e8);
      const mirrorE8 = booksIn.MIRROR_SHADOW.map((item) => item.return_e8);
      const cleanE8 = booksIn.CLEAN_SHADOW.map((item) => item.return_e8);
      const benchE8 = booksIn.FIXED_BENCHMARK.map((item) => item.return_e8);

      const rActual = actualE8.map((x) => finite(x / 100000000));
      const rMirror = mirrorE8.map((x) => finite(x / 100000000));
      const rClean = cleanE8.map((x) => finite(x / 100000000));
      const rBench = benchE8.map((x) => finite(x / 100000000));

      const C_A = booksOut.ACTUAL.cumulative_return;
      const C_M = booksOut.MIRROR_SHADOW.cumulative_return;
      const C_C = booksOut.CLEAN_SHADOW.cumulative_return;
      const C_B = booksOut.FIXED_BENCHMARK.cumulative_return;

      const W_A = finite(1.0 + C_A);
      const W_M = finite(1.0 + C_M);
      const W_C = finite(1.0 + C_C);
      const W_B = finite(1.0 + C_B);

      const systematic_process_edge_cumulative = finite(C_C - C_B);
      const legacy_transition_drag_cumulative = finite(C_M - C_C);
      const discretionary_execution_alpha_cumulative = finite(C_A - C_M);
      const total_outperformance_vs_benchmark = finite(C_A - C_B);

      const systematic_process_edge_mean = finite(
        fsum(rClean.map((rc, t) => finite(rc - rBench[t]))) / T,
      );
      const legacy_transition_drag_mean = finite(
        fsum(rMirror.map((rm, t) => finite(rm - rClean[t]))) / T,
      );
      const discretionary_execution_alpha_mean = finite(
        fsum(rActual.map((ra, t) => finite(ra - rMirror[t]))) / T,
      );
      const total_outperformance_mean = finite(
        fsum(rActual.map((ra, t) => finite(ra - rBench[t]))) / T,
      );

      const systematic_process_geometric_factor = finite(finite(W_C / W_B) - 1.0);
      const legacy_transition_geometric_factor = finite(finite(W_M / W_C) - 1.0);
      const discretionary_alpha_geometric_factor = finite(finite(W_A / W_M) - 1.0);
      const total_outperformance_geometric_factor = finite(finite(W_A / W_B) - 1.0);

      let sysWins = 0;
      let discWins = 0;
      for (let t = 0; t < T; t += 1) {
        if (cleanE8[t] > benchE8[t]) sysWins += 1;
        if (actualE8[t] > mirrorE8[t]) discWins += 1;
      }
      const systematic_hit_rate = finite(sysWins / T);
      const discretionary_override_hit_rate = finite(discWins / T);

      attribution = {
        systematic_process_edge_cumulative,
        legacy_transition_drag_cumulative,
        discretionary_execution_alpha_cumulative,
        total_outperformance_vs_benchmark,
        systematic_process_edge_mean,
        legacy_transition_drag_mean,
        discretionary_execution_alpha_mean,
        total_outperformance_mean,
        systematic_process_geometric_factor,
        legacy_transition_geometric_factor,
        discretionary_alpha_geometric_factor,
        total_outperformance_geometric_factor,
        systematic_hit_rate,
        discretionary_override_hit_rate,
      };
    }

    result.status = 'OK';
    result.reason_code = null;
    result.books = booksOut;
    result.attribution = attribution;
    result.decision_chain_summary = decision_chain_summary;
    result.lean_replay_verification = lean_replay_verification;
    return deepFreeze(result);
  } catch {
    result.status = 'CF_INVALID_INPUT';
    result.reason_code = 'NON_FINITE_ARITHMETIC';
    return deepFreeze(result);
  }
}

export function runCli(args) {
  const cliError = (reasonCode) => ({
    exitCode: 3,
    output:
      JSON.stringify(
        {
          schema: COUNTERFACTUAL_VERSION,
          fixture: null,
          fixture_sha256: null,
          status: 'CF_INVALID_INPUT',
          reason_code: reasonCode,
          T: null,
          periods_per_year: null,
          calendar_sha256: null,
          books: null,
          attribution: null,
          decision_chain_summary: null,
          lean_replay_verification: null,
        },
        null,
        2,
      ) + '\n',
  });

  if (!Array.isArray(args)) {
    return cliError('CLI_USAGE_ERROR');
  }
  if (args.length === 1 && args[0] === '--help') {
    return { exitCode: 0, output: USAGE };
  }
  if (args.length !== 1 || typeof args[0] !== 'string' || args[0].startsWith('--')) {
    return cliError('CLI_USAGE_ERROR');
  }

  let rawBytes;
  let text;
  try {
    rawBytes = readFileSync(args[0]);
    if (rawBytes.length > MAX_INPUT_BYTES) {
      return cliError('UNREADABLE_INPUT');
    }
    text = new TextDecoder('utf-8', { fatal: true }).decode(rawBytes);
  } catch {
    return cliError('UNREADABLE_INPUT');
  }

  const fixtureSha256 = sha256Hex(rawBytes);
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return cliError('INVALID_JSON');
  }

  const result = verifyCounterfactualAttribution(parsed, { fixtureSha256 });
  return {
    exitCode: result.status === 'OK' ? 0 : 1,
    output: JSON.stringify(result, null, 2) + '\n',
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const response = runCli(process.argv.slice(2));
  process.stdout.write(response.output);
  process.exitCode = response.exitCode;
}
