#!/usr/bin/env python3
"""Independent binary64 oracle for counterfactual attribution and pattern profiles.

Python 3.10+, standard library only (argparse, hashlib, json, math, sys).
Evaluates four-book counterfactual attribution (ACTUAL, MIRROR_SHADOW,
CLEAN_SHADOW, FIXED_BENCHMARK), single-book return pattern profiles,
append-only decision log hash chains and Merkle roots, and QuantConnect LEAN
replay manifests under strict zero-disclosure guardrails.
"""

import argparse
import hashlib
import json
import math
import sys

VERSION = "n170.verify.counterfactual-attribution.v1"
INPUT_SCHEMA = "n170.verify.counterfactual-input.v1"
LEAN_SCHEMA = "n170.verify.lean-replay-manifest.v1"
FREQUENCIES = (1, 4, 12, 52, 252, 365, 366)
SAFE_INTEGER = 9007199254740991
BOOK_NAMES = ("ACTUAL", "MIRROR_SHADOW", "CLEAN_SHADOW", "FIXED_BENCHMARK")
PROHIBITED_KEYS = frozenset({
    "ticker",
    "tickers",
    "symbol",
    "symbols",
    "isin",
    "cusip",
    "positions",
    "holdings",
    "nav_amount",
    "dollar_value",
    "cash_balance",
    "account_id",
    "account_number",
    "strategy_code",
    "algorithm_source",
    "factor_weights",
    "prompts",
})


def finite(value):
    """Check each floating intermediate before using it in another operation."""
    if not math.isfinite(value):
        raise ArithmeticError("non-finite intermediate")
    return value


def real(value):
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def is_hex64(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def is_engine_digest(value):
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and is_hex64(value[7:])
    )


def is_iso_date(value):
    if not isinstance(value, str) or len(value) != 10:
        return False
    if value[4] != "-" or value[7] != "-":
        return False
    yyyy, mm, dd = value[:4], value[5:7], value[8:10]
    if not (yyyy.isdigit() and mm.isdigit() and dd.isdigit()):
        return False
    month = int(mm)
    day = int(dd)
    return 1 <= month <= 12 and 1 <= day <= 31


def find_prohibited_key(obj):
    """Recursively inspect every dict key at every nesting depth."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, str) and key.lower() in PROHIBITED_KEYS:
                return key.lower()
            nested = find_prohibited_key(value)
            if nested is not None:
                return nested
    elif isinstance(obj, list):
        for item in obj:
            nested = find_prohibited_key(item)
            if nested is not None:
                return nested
    return None


def compute_merkle_root(hex_leaves):
    """Compute binary Merkle root over 32-byte decision_set_sha256 leaves."""
    level = [
        hashlib.sha256(b"\x00" + bytes.fromhex(leaf)).digest()
        for leaf in hex_leaves
    ]
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                combined = hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest()
                next_level.append(combined)
            else:
                next_level.append(level[i])
        level = next_level
    return level[0].hex()


def compute_pattern_profile(returns_e8, benchmark_e8, q):
    """Compute return pattern profile for a single book."""
    r = [finite(x / 100000000) for x in returns_e8]
    T = len(r)
    win_intervals = sum(1 for x in returns_e8 if x > 0)
    loss_intervals = sum(1 for x in returns_e8 if x < 0)
    flat_intervals = sum(1 for x in returns_e8 if x == 0)
    win_rate = finite(win_intervals / T)

    pos = [finite(x / 100000000) for x in returns_e8 if x > 0]
    neg_abs = [finite(-x / 100000000) for x in returns_e8 if x < 0]
    sum_pos = finite(math.fsum(pos))
    sum_neg_abs = finite(math.fsum(neg_abs))
    gain_to_pain_ratio = finite(sum_pos / sum_neg_abs) if sum_neg_abs > 0 else None
    mean_win = finite(sum_pos / len(pos)) if len(pos) > 0 else None
    mean_loss_abs = finite(sum_neg_abs / len(neg_abs)) if len(neg_abs) > 0 else None
    payoff_asymmetry = (
        finite(mean_win / mean_loss_abs)
        if (mean_win is not None and mean_loss_abs is not None and mean_loss_abs > 0)
        else None
    )

    wealth = 1.0
    peak = 1.0
    dd_series = []
    for rt in r:
        wealth = finite(wealth * finite(1.0 + rt))
        if wealth > peak:
            peak = wealth
        dd = finite(finite(peak - wealth) / peak)
        dd_series.append(dd)

    cumulative_return = finite(wealth - 1.0)
    cagr = finite(finite(wealth ** finite(q / T)) - 1.0)
    max_drawdown = max(dd_series)
    ulcer_index = finite(
        math.sqrt(finite(math.fsum([finite(d * d) for d in dd_series]) / T))
    )

    max_dd_duration = 0
    cur_dur = 0
    for d in dd_series:
        if d > 0:
            cur_dur += 1
            if cur_dur > max_dd_duration:
                max_dd_duration = cur_dur
        else:
            cur_dur = 0

    if max_drawdown == 0:
        max_drawdown_recovery_intervals = 0
        max_drawdown_recovered = True
    else:
        trough_idx = next(i for i, d in enumerate(dd_series) if d == max_drawdown)
        recovery_idx = next(
            (j for j in range(trough_idx + 1, T) if dd_series[j] == 0.0),
            None,
        )
        if recovery_idx is not None:
            max_drawdown_recovery_intervals = recovery_idx - trough_idx
            max_drawdown_recovered = True
        else:
            max_drawdown_recovery_intervals = None
            max_drawdown_recovered = False

    in_dd_r = [r[t] for t in range(1, T) if dd_series[t - 1] > 0]
    hw_r = [r[t] for t in range(1, T) if dd_series[t - 1] == 0]
    post_drawdown_rms_vol = (
        finite(math.sqrt(finite(math.fsum([finite(x * x) for x in in_dd_r]) / len(in_dd_r))))
        if len(in_dd_r) >= 2
        else None
    )
    high_water_rms_vol = (
        finite(math.sqrt(finite(math.fsum([finite(x * x) for x in hw_r]) / len(hw_r))))
        if len(hw_r) >= 2
        else None
    )
    post_drawdown_vol_scaling_ratio = (
        finite(post_drawdown_rms_vol / high_water_rms_vol)
        if (
            post_drawdown_rms_vol is not None
            and high_water_rms_vol is not None
            and high_water_rms_vol > 0
        )
        else None
    )
    if post_drawdown_vol_scaling_ratio is None:
        post_drawdown_behavior_code = "INSUFFICIENT_REGIME_OBSERVATIONS"
    elif post_drawdown_vol_scaling_ratio < 0.95:
        post_drawdown_behavior_code = "DISCIPLINED_RISK_SCALING"
    elif post_drawdown_vol_scaling_ratio <= 1.15:
        post_drawdown_behavior_code = "NEUTRAL_RISK_SCALING"
    else:
        post_drawdown_behavior_code = "ELEVATED_POST_DRAWDOWN_RISK"

    upside_capture = None
    downside_capture = None
    capture_asymmetry = None
    if benchmark_e8 is not None:
        b = [finite(x / 100000000) for x in benchmark_e8]
        up_idx = [t for t in range(T) if benchmark_e8[t] > 0]
        down_idx = [t for t in range(T) if benchmark_e8[t] < 0]
        if len(up_idx) > 0:
            up_book = finite(math.fsum([r[t] for t in up_idx]) / len(up_idx))
            up_bench = finite(math.fsum([b[t] for t in up_idx]) / len(up_idx))
            if up_bench > 0:
                upside_capture = finite(up_book / up_bench)
        if len(down_idx) > 0:
            down_book = finite(math.fsum([r[t] for t in down_idx]) / len(down_idx))
            down_bench = finite(math.fsum([b[t] for t in down_idx]) / len(down_idx))
            if down_bench < 0:
                downside_capture = finite(down_book / down_bench)
        if upside_capture is not None and downside_capture is not None:
            capture_asymmetry = finite(upside_capture - downside_capture)

    return {
        "T": T,
        "win_intervals": win_intervals,
        "loss_intervals": loss_intervals,
        "flat_intervals": flat_intervals,
        "win_rate": win_rate,
        "gain_to_pain_ratio": gain_to_pain_ratio,
        "mean_win": mean_win,
        "mean_loss_abs": mean_loss_abs,
        "payoff_asymmetry": payoff_asymmetry,
        "cumulative_return": cumulative_return,
        "cagr": cagr,
        "max_drawdown": max_drawdown,
        "ulcer_index": ulcer_index,
        "max_drawdown_duration_intervals": max_dd_duration,
        "max_drawdown_recovery_intervals": max_drawdown_recovery_intervals,
        "max_drawdown_recovered": max_drawdown_recovered,
        "post_drawdown_rms_vol": post_drawdown_rms_vol,
        "high_water_rms_vol": high_water_rms_vol,
        "post_drawdown_vol_scaling_ratio": post_drawdown_vol_scaling_ratio,
        "post_drawdown_behavior_code": post_drawdown_behavior_code,
        "upside_capture": upside_capture,
        "downside_capture": downside_capture,
        "capture_asymmetry": capture_asymmetry,
    }


def compute(fixture, fixture_sha256=None):
    """Validate and evaluate a counterfactual attribution fixture."""
    fixture_dict = fixture if isinstance(fixture, dict) else {}
    raw_books = fixture_dict.get("books")
    raw_actual = raw_books.get("ACTUAL") if isinstance(raw_books, dict) else None
    raw_q = fixture_dict.get("periods_per_year")

    result = {
        "schema": VERSION,
        "fixture": fixture_dict.get("id") if isinstance(fixture_dict.get("id"), str) else None,
        "fixture_sha256": fixture_sha256,
        "status": "CF_INVALID_INPUT",
        "reason_code": "INVALID_INPUT",
        "T": len(raw_actual) if isinstance(raw_actual, list) else None,
        "periods_per_year": raw_q if (type(raw_q) is int and raw_q in FREQUENCIES) else None,
        "calendar_sha256": None,
        "books": None,
        "attribution": None,
        "decision_chain_summary": None,
        "lean_replay_verification": None,
    }

    # 1. Prohibited Disclosure Field Check (First!)
    prohibited = find_prohibited_key(fixture)
    if prohibited is not None:
        result["status"] = "CF_PROHIBITED_DISCLOSURE_FIELD"
        result["reason_code"] = f"PROHIBITED_FIELD:{prohibited}"
        return result

    # 2. Schema & Frequency Validation
    if not isinstance(fixture, dict) or fixture.get("schema") != INPUT_SCHEMA:
        result["status"] = "CF_INVALID_INPUT"
        result["reason_code"] = "INVALID_SCHEMA"
        return result

    q = fixture.get("periods_per_year")
    if type(q) is not int or q not in FREQUENCIES:
        result["status"] = "CF_INVALID_INPUT"
        result["reason_code"] = "INVALID_FREQUENCY"
        return result

    books_in = fixture.get("books")
    if not isinstance(books_in, dict):
        result["status"] = "CF_INVALID_INPUT"
        result["reason_code"] = "INVALID_BOOK_SET"
        return result

    book_keys = set(books_in.keys())
    valid_single = book_keys in ({"ACTUAL"}, {"ACTUAL", "FIXED_BENCHMARK"})
    valid_four = book_keys == set(BOOK_NAMES)
    if not (valid_single or valid_four):
        result["status"] = "CF_INVALID_INPUT"
        result["reason_code"] = "INVALID_BOOK_SET"
        return result

    actual = books_in.get("ACTUAL")
    if not isinstance(actual, list) or len(actual) < 4:
        result["status"] = "CF_INVALID_INPUT"
        result["reason_code"] = "SAMPLE_TOO_SHORT"
        return result

    for bname in BOOK_NAMES:
        if bname in books_in and not isinstance(books_in[bname], list):
            result["status"] = "CF_INVALID_INPUT"
            result["reason_code"] = "INVALID_BOOK_SET"
            return result

    T = len(actual)
    result["T"] = T

    # 3. Calendar & Return Series Validation
    for t, item in enumerate(actual):
        if not isinstance(item, dict):
            result["status"] = "CF_INVALID_INPUT"
            result["reason_code"] = "INVALID_INTERVAL_OBJECT"
            return result
        start = item.get("start")
        end = item.get("end")
        if not is_iso_date(start) or not is_iso_date(end) or not (start < end):
            result["status"] = "CF_CALENDAR_MISMATCH"
            result["reason_code"] = "NON_CHRONOLOGICAL_INTERVALS"
            return result
        if t > 0 and actual[t - 1]["end"] > start:
            result["status"] = "CF_CALENDAR_MISMATCH"
            result["reason_code"] = "NON_CHRONOLOGICAL_INTERVALS"
            return result

    for bname in BOOK_NAMES:
        if bname not in books_in:
            continue
        series = books_in[bname]
        if len(series) != T:
            result["status"] = "CF_CALENDAR_MISMATCH"
            result["reason_code"] = "BOOK_CALENDAR_MISMATCH"
            return result
        for t in range(T):
            entry = series[t]
            if not isinstance(entry, dict):
                result["status"] = "CF_INVALID_INPUT"
                result["reason_code"] = "INVALID_INTERVAL_OBJECT"
                return result
            if (
                entry.get("start") != actual[t]["start"]
                or entry.get("end") != actual[t]["end"]
            ):
                result["status"] = "CF_CALENDAR_MISMATCH"
                result["reason_code"] = "BOOK_CALENDAR_MISMATCH"
                return result

    for bname in BOOK_NAMES:
        if bname not in books_in:
            continue
        for entry in books_in[bname]:
            x = entry.get("return_e8")
            if type(x) is not int or abs(x) > SAFE_INTEGER or x <= -100000000:
                result["status"] = "CF_INVALID_INPUT"
                result["reason_code"] = "INVALID_RETURN_E8"
                return result

    calendar_pairs = [[item["start"], item["end"]] for item in actual]
    calendar_sha256 = hashlib.sha256(
        json.dumps(calendar_pairs, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    result["calendar_sha256"] = calendar_sha256

    try:
        # 4. Decision Log Verification (Optional)
        decision_chain_summary = None
        decision_log = fixture.get("decision_log")
        if decision_log is not None:
            if not isinstance(decision_log, dict):
                result["status"] = "CF_DECISION_CHAIN_BROKEN"
                result["reason_code"] = "INVALID_DECISION_LOG"
                return result
            intervals = decision_log.get("intervals")
            head_chain = decision_log.get("head_chain_sha256")
            if (
                not isinstance(intervals, list)
                or len(intervals) != T
                or not is_hex64(head_chain)
            ):
                result["status"] = "CF_DECISION_CHAIN_BROKEN"
                result["reason_code"] = "INVALID_DECISION_LOG"
                return result

            for t in range(T):
                d = intervals[t]
                if not isinstance(d, dict):
                    result["status"] = "CF_DECISION_CHAIN_BROKEN"
                    result["reason_code"] = f"CHAIN_HASH_MISMATCH_AT_{t}"
                    return result
                if (
                    d.get("start") != actual[t]["start"]
                    or d.get("end") != actual[t]["end"]
                ):
                    result["status"] = "CF_CALENDAR_MISMATCH"
                    result["reason_code"] = "BOOK_CALENDAR_MISMATCH"
                    return result
                acc = d.get("accepted_count")
                mod = d.get("modified_count")
                rej = d.get("rejected_count")
                if any(
                    type(c) is not int or c < 0 or c > SAFE_INTEGER
                    for c in (acc, mod, rej)
                ):
                    result["status"] = "CF_DECISION_CHAIN_BROKEN"
                    result["reason_code"] = f"INVALID_DECISION_COUNTS_AT_{t}"
                    return result
                dset_sha = d.get("decision_set_sha256")
                chain_sha = d.get("chain_sha256")
                if not is_hex64(dset_sha) or not is_hex64(chain_sha):
                    result["status"] = "CF_DECISION_CHAIN_BROKEN"
                    result["reason_code"] = f"CHAIN_HASH_MISMATCH_AT_{t}"
                    return result
                prev_chain = "0" * 64 if t == 0 else intervals[t - 1]["chain_sha256"]
                preimage = (
                    f"{prev_chain}:{d['start']}:{d['end']}:"
                    f"{acc}:{mod}:{rej}:{dset_sha}"
                )
                expected_chain = hashlib.sha256(preimage.encode("utf-8")).hexdigest()
                if chain_sha != expected_chain:
                    result["status"] = "CF_DECISION_CHAIN_BROKEN"
                    result["reason_code"] = f"CHAIN_HASH_MISMATCH_AT_{t}"
                    return result

            if head_chain != intervals[-1]["chain_sha256"]:
                result["status"] = "CF_DECISION_CHAIN_BROKEN"
                result["reason_code"] = "HEAD_CHAIN_HASH_MISMATCH"
                return result

            merkle_root_sha256 = compute_merkle_root(
                [d["decision_set_sha256"] for d in intervals]
            )
            total_accepted = sum(d["accepted_count"] for d in intervals)
            total_modified = sum(d["modified_count"] for d in intervals)
            total_rejected = sum(d["rejected_count"] for d in intervals)
            total_proposals = total_accepted + total_modified + total_rejected
            acceptance_rate = (
                finite(total_accepted / total_proposals)
                if total_proposals > 0
                else None
            )
            modification_rate = (
                finite(total_modified / total_proposals)
                if total_proposals > 0
                else None
            )
            rejection_rate = (
                finite(total_rejected / total_proposals)
                if total_proposals > 0
                else None
            )
            decision_chain_summary = {
                "verified": True,
                "intervals": T,
                "total_proposals": total_proposals,
                "total_accepted": total_accepted,
                "total_modified": total_modified,
                "total_rejected": total_rejected,
                "acceptance_rate": acceptance_rate,
                "modification_rate": modification_rate,
                "rejection_rate": rejection_rate,
                "head_chain_sha256": head_chain,
                "merkle_root_sha256": merkle_root_sha256,
            }

        # 5. QuantConnect LEAN Replay Manifest Verification (Optional)
        lean_replay_verification = None
        lm = fixture.get("lean_manifest")
        if lm is not None:
            if not isinstance(lm, dict) or lm.get("schema") != LEAN_SCHEMA:
                result["status"] = "CF_LEAN_MANIFEST_INVALID"
                result["reason_code"] = "LEAN_SCHEMA_INVALID"
                return result
            target_book = lm.get("target_book")
            if (
                target_book not in ("CLEAN_SHADOW", "MIRROR_SHADOW")
                or target_book not in books_in
            ):
                result["status"] = "CF_LEAN_MANIFEST_INVALID"
                result["reason_code"] = "LEAN_TARGET_BOOK_INVALID"
                return result
            engine_image_digest = lm.get("engine_image_digest")
            if not is_engine_digest(engine_image_digest):
                result["status"] = "CF_LEAN_MANIFEST_INVALID"
                result["reason_code"] = "LEAN_ENGINE_DIGEST_INVALID"
                return result
            if lm.get("calendar_sha256") != calendar_sha256:
                result["status"] = "CF_LEAN_MANIFEST_INVALID"
                result["reason_code"] = "LEAN_CALENDAR_HASH_MISMATCH"
                return result
            cost_policy_bps = lm.get("cost_policy_bps")
            if not real(cost_policy_bps) or cost_policy_bps < 0 or cost_policy_bps > 1000:
                result["status"] = "CF_LEAN_MANIFEST_INVALID"
                result["reason_code"] = "LEAN_COST_POLICY_INVALID"
                return result
            input_merkle = lm.get("input_commitments_merkle_root")
            if not is_hex64(input_merkle):
                result["status"] = "CF_LEAN_MANIFEST_INVALID"
                result["reason_code"] = "LEAN_MERKLE_ROOT_MISMATCH"
                return result
            if (
                decision_chain_summary is not None
                and input_merkle != decision_chain_summary["merkle_root_sha256"]
            ):
                result["status"] = "CF_LEAN_MANIFEST_INVALID"
                result["reason_code"] = "LEAN_MERKLE_ROOT_MISMATCH"
                return result
            target_returns_e8 = [item["return_e8"] for item in books_in[target_book]]
            expected_output_sha256 = hashlib.sha256(
                json.dumps(target_returns_e8, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            if lm.get("output_returns_sha256") != expected_output_sha256:
                result["status"] = "CF_LEAN_MANIFEST_INVALID"
                result["reason_code"] = "LEAN_OUTPUT_HASH_MISMATCH"
                return result
            canonical_manifest = {
                "calendar_sha256": lm["calendar_sha256"],
                "cost_policy_bps": lm["cost_policy_bps"],
                "engine_image_digest": lm["engine_image_digest"],
                "input_commitments_merkle_root": lm["input_commitments_merkle_root"],
                "output_returns_sha256": lm["output_returns_sha256"],
                "schema": LEAN_SCHEMA,
                "target_book": lm["target_book"],
            }
            expected_manifest_sha256 = hashlib.sha256(
                json.dumps(
                    canonical_manifest, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            ).hexdigest()
            if lm.get("manifest_sha256") != expected_manifest_sha256:
                result["status"] = "CF_LEAN_MANIFEST_INVALID"
                result["reason_code"] = "LEAN_MANIFEST_HASH_MISMATCH"
                return result
            lean_replay_verification = {
                "verified": True,
                **canonical_manifest,
                "manifest_sha256": expected_manifest_sha256,
            }

        # 6. Pattern Profile per Book
        benchmark_e8 = (
            [item["return_e8"] for item in books_in["FIXED_BENCHMARK"]]
            if "FIXED_BENCHMARK" in books_in
            else None
        )
        books_out = {}
        for bname in BOOK_NAMES:
            if bname in books_in:
                b_e8 = [item["return_e8"] for item in books_in[bname]]
                books_out[bname] = compute_pattern_profile(b_e8, benchmark_e8, q)

        # 7. Four-Book Counterfactual Attribution
        attribution = None
        if valid_four:
            actual_e8 = [item["return_e8"] for item in books_in["ACTUAL"]]
            mirror_e8 = [item["return_e8"] for item in books_in["MIRROR_SHADOW"]]
            clean_e8 = [item["return_e8"] for item in books_in["CLEAN_SHADOW"]]
            bench_e8 = [item["return_e8"] for item in books_in["FIXED_BENCHMARK"]]

            r_actual = [finite(x / 100000000) for x in actual_e8]
            r_mirror = [finite(x / 100000000) for x in mirror_e8]
            r_clean = [finite(x / 100000000) for x in clean_e8]
            r_bench = [finite(x / 100000000) for x in bench_e8]

            C_A = books_out["ACTUAL"]["cumulative_return"]
            C_M = books_out["MIRROR_SHADOW"]["cumulative_return"]
            C_C = books_out["CLEAN_SHADOW"]["cumulative_return"]
            C_B = books_out["FIXED_BENCHMARK"]["cumulative_return"]

            W_A = finite(1.0 + C_A)
            W_M = finite(1.0 + C_M)
            W_C = finite(1.0 + C_C)
            W_B = finite(1.0 + C_B)

            systematic_process_edge_cumulative = finite(C_C - C_B)
            legacy_transition_drag_cumulative = finite(C_M - C_C)
            discretionary_execution_alpha_cumulative = finite(C_A - C_M)
            total_outperformance_vs_benchmark = finite(C_A - C_B)

            systematic_process_edge_mean = finite(
                math.fsum([finite(r_clean[t] - r_bench[t]) for t in range(T)]) / T
            )
            legacy_transition_drag_mean = finite(
                math.fsum([finite(r_mirror[t] - r_clean[t]) for t in range(T)]) / T
            )
            discretionary_execution_alpha_mean = finite(
                math.fsum([finite(r_actual[t] - r_mirror[t]) for t in range(T)]) / T
            )
            total_outperformance_mean = finite(
                math.fsum([finite(r_actual[t] - r_bench[t]) for t in range(T)]) / T
            )

            systematic_process_geometric_factor = finite(finite(W_C / W_B) - 1.0)
            legacy_transition_geometric_factor = finite(finite(W_M / W_C) - 1.0)
            discretionary_alpha_geometric_factor = finite(finite(W_A / W_M) - 1.0)
            total_outperformance_geometric_factor = finite(finite(W_A / W_B) - 1.0)

            systematic_hit_rate = finite(
                sum(1 for t in range(T) if clean_e8[t] > bench_e8[t]) / T
            )
            discretionary_override_hit_rate = finite(
                sum(1 for t in range(T) if actual_e8[t] > mirror_e8[t]) / T
            )

            attribution = {
                "systematic_process_edge_cumulative": systematic_process_edge_cumulative,
                "legacy_transition_drag_cumulative": legacy_transition_drag_cumulative,
                "discretionary_execution_alpha_cumulative": discretionary_execution_alpha_cumulative,
                "total_outperformance_vs_benchmark": total_outperformance_vs_benchmark,
                "systematic_process_edge_mean": systematic_process_edge_mean,
                "legacy_transition_drag_mean": legacy_transition_drag_mean,
                "discretionary_execution_alpha_mean": discretionary_execution_alpha_mean,
                "total_outperformance_mean": total_outperformance_mean,
                "systematic_process_geometric_factor": systematic_process_geometric_factor,
                "legacy_transition_geometric_factor": legacy_transition_geometric_factor,
                "discretionary_alpha_geometric_factor": discretionary_alpha_geometric_factor,
                "total_outperformance_geometric_factor": total_outperformance_geometric_factor,
                "systematic_hit_rate": systematic_hit_rate,
                "discretionary_override_hit_rate": discretionary_override_hit_rate,
            }

        result["status"] = "OK"
        result["reason_code"] = None
        result["books"] = books_out
        result["attribution"] = attribution
        result["decision_chain_summary"] = decision_chain_summary
        result["lean_replay_verification"] = lean_replay_verification
        return result
    except (ArithmeticError, ValueError, TypeError, OverflowError):
        result["status"] = "CF_INVALID_INPUT"
        result["reason_code"] = "NON_FINITE_ARITHMETIC"
        return result


def sanity():
    """Run deterministic self-checks on math.fsum, Merkle roots, and guardrails."""
    sum_vectors = (
        ([0.1] * 10, 1.0),
        ([1e100, 1.0, -1e100, 1e-100, 1e50, -1.0, -1e50], 1e-100),
        ([9007199254740992, 1.0, -9007199254740992], 1.0),
        ([], 0.0),
    )
    sums = [
        {
            "terms": terms,
            "expected": expected,
            "actual": math.fsum(terms),
            "exact_match": math.fsum(terms) == expected,
        }
        for terms, expected in sum_vectors
    ]

    leaf0 = hashlib.sha256(b"leaf-0").hexdigest()
    leaf1 = hashlib.sha256(b"leaf-1").hexdigest()
    leaf2 = hashlib.sha256(b"leaf-2").hexdigest()
    n0 = hashlib.sha256(b"\x00" + bytes.fromhex(leaf0)).digest()
    n1 = hashlib.sha256(b"\x00" + bytes.fromhex(leaf1)).digest()
    n2 = hashlib.sha256(b"\x00" + bytes.fromhex(leaf2)).digest()
    n01 = hashlib.sha256(b"\x01" + n0 + n1).digest()
    expected_root_3 = hashlib.sha256(b"\x01" + n01 + n2).hexdigest()
    actual_root_3 = compute_merkle_root([leaf0, leaf1, leaf2])
    merkle_ok = actual_root_3 == expected_root_3

    prohibited_probe = compute(
        {
            "schema": INPUT_SCHEMA,
            "id": "SANITY_PROHIBITED",
            "periods_per_year": 252,
            "books": {"ACTUAL": []},
            "meta": {"nested": {"tickers": ["SYNTH"]}},
        }
    )
    prohibited_ok = (
        prohibited_probe["status"] == "CF_PROHIBITED_DISCLOSURE_FIELD"
        and prohibited_probe["reason_code"] == "PROHIBITED_FIELD:tickers"
    )

    ok = all(row["exact_match"] for row in sums) and merkle_ok and prohibited_ok
    return {
        "pass": ok,
        "schema": VERSION,
        "fsum_vectors": sums,
        "merkle_odd_promotion_ok": merkle_ok,
        "prohibited_field_guard_ok": prohibited_ok,
    }


def emit(value):
    print(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    compute_parser = commands.add_parser("compute")
    compute_parser.add_argument("input")
    commands.add_parser("sanity")
    args = parser.parse_args()
    if args.command == "compute":
        try:
            with open(args.input, "rb") as source:
                raw = source.read()
            fixture = json.loads(raw)
        except (OSError, ValueError):
            print("Unreadable input", file=sys.stderr)
            return 1
        emit(compute(fixture, hashlib.sha256(raw).hexdigest()))
    else:
        report = sanity()
        emit(report)
        return 0 if report["pass"] else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
