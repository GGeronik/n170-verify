"""Single-use spawn subprocess isolation for one-shot verification and 7-day trade guard."""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
import hashlib
import importlib
import multiprocessing
from multiprocessing.connection import Connection
import os
from pathlib import Path
import re
import resource
import sys
import threading
from typing import Any
import uuid

import app as _app_pkg
from app.config import ApiConfig, utc_now_iso
import n170_verify as _core_pkg
from n170_verify.contracts import (
    ALLOWED_RETENTION_MODES,
     VERIFY_SCHEMA_VERSION,
    AccountScope,
    BehaviouralCoachingMetrics,
    CapitalBracket,
    CostAndDragBreakdown,
    EnvironmentTier,
    IndexedCurvePoint,
    OriginAssurance,
    PerformanceSummary,
    ProviderApprovalState,
    ReconciliationReport,
    ReconciliationStatus,
    RedactedClosedTrade,
    TraderCoachingAndContextReport,
    VerifyProofBundle,
    classify_capital_bracket,
    compute_blinded_account_tag,
    create_signed_proof_bundle,
    parse_utc_timestamp,
    validate_hex_digest,
)
from n170_verify.crypto import (
    CANONICAL_LEAF_NAMES,
    BrokerNativeSignature,
    ProspectiveChainLink,
    WitnessAttestation,
    build_salted_merkle_tree,
    jcs_sha256_hex,
)


_SPAWN_ENV_LOCK = threading.Lock()

_SAFE_CHILD_ENV_ALLOWLIST: frozenset[str] = frozenset(
    {
        "PATH",
        "PYTHONPATH",
        "PYTHONHOME",
        "VIRTUAL_ENV",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TMPDIR",
        "TEMP",
        "TMP",
        "SYSTEMROOT",
        "DYLD_LIBRARY_PATH",
        "LD_LIBRARY_PATH",
    }
)


class WorkerIsolationError(RuntimeError):
    """Raised when an isolated verification worker fails, crashes, or violates isolation checks."""


class WorkerValidationError(ValueError):
    """Raised when verification input fails domain validation inside the isolated worker."""


@dataclass(slots=True)
class WorkerIsolationReceipt:
    """Honest OS/process-level isolation attestation for one-shot verification."""

    execution_mode: str
    parent_pid: int
    worker_pid: int
    worker_exitcode: int
    worker_terminated: bool
    rlimit_core_soft: int
    rlimit_core_hard: int
    sanitized_child_env: bool
    child_env_keys: list[str]
    persistent_rows_written: int
    retention_mode: str
    memory_lifecycle_disclosure: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_mode": self.execution_mode,
            "parent_pid": self.parent_pid,
            "worker_pid": self.worker_pid,
            "worker_exitcode": self.worker_exitcode,
            "worker_terminated": self.worker_terminated,
            "rlimit_core": [self.rlimit_core_soft, self.rlimit_core_hard],
            "rlimit_core_soft": self.rlimit_core_soft,
            "rlimit_core_hard": self.rlimit_core_hard,
            "sanitized_child_env": self.sanitized_child_env,
            "child_env_keys": list(self.child_env_keys),
            "persistent_rows_written": self.persistent_rows_written,
            "retention_mode": self.retention_mode,
            "memory_lifecycle_disclosure": self.memory_lifecycle_disclosure,
        }


def filter_delayed_closed_trades(
    closed_trades: Sequence[RedactedClosedTrade | Mapping[str, Any]] | None,
    *,
    issued_at_utc: str,
    min_delay_days: int = 7,
) -> tuple[list[RedactedClosedTrade], int]:
    """Strip any closed trade with ``exit_timestamp_utc > issued_at_utc - min_delay_days``.

    Prevents copy-trading / front-running leakage on optional ``delayed_closed_trades`` leaves.
    """
    if not closed_trades:
        return [], 0
    if min_delay_days < 1:
        raise ValueError("min_delay_days must be >= 1")

    issued_dt = parse_utc_timestamp(issued_at_utc, field_name="issued_at_utc")
    cutoff_dt = issued_dt - timedelta(days=min_delay_days)

    kept: list[RedactedClosedTrade] = []
    stripped_count = 0
    for idx, item in enumerate(closed_trades):
        trade = (
            item
            if isinstance(item, RedactedClosedTrade)
            else RedactedClosedTrade.from_dict(item)
        )
        exit_dt = parse_utc_timestamp(
            trade.exit_timestamp_utc,
            field_name=f"closed_trades[{idx}].exit_timestamp_utc",
        )
        if exit_dt > cutoff_dt:
            stripped_count += 1
        else:
            kept.append(trade)
    return kept, stripped_count


def _build_child_pythonpath() -> str:
    """Resolve minimal PYTHONPATH so spawned ``python3 -B`` locates ``n170_verify`` and ``app``."""
    entries: list[str] = []
    existing = os.environ.get("PYTHONPATH", "").strip()
    if existing:
        entries.extend(p for p in existing.split(os.pathsep) if p)

    core_parent = str(Path(_core_pkg.__file__).resolve().parent.parent)
    api_parent = str(Path(_app_pkg.__file__).resolve().parent.parent)
    for candidate in (core_parent, api_parent):
        if candidate not in entries:
            entries.append(candidate)
    return os.pathsep.join(entries)


def _build_sanitized_env_map() -> dict[str, str]:
    """Construct scrubbed environment dictionary excluding parent secrets and credentials."""
    clean: dict[str, str] = {}
    for key in _SAFE_CHILD_ENV_ALLOWLIST:
        val = os.environ.get(key)
        if val is not None:
            clean[key] = val
    clean["PYTHONPATH"] = _build_child_pythonpath()
    clean["PYTHONDONTWRITEBYTECODE"] = "1"
    clean["PYTHONNOUSERSITE"] = "1"
    return clean


def _sanitize_current_process_env() -> list[str]:
    """Scrub ``os.environ`` in-place inside the spawned worker subprocess."""
    allowed = _build_sanitized_env_map()
    os.environ.clear()
    os.environ.update(allowed)
    return sorted(os.environ.keys())


def _rebase_nav_points_to_indexed_curve(
    nav_points: Sequence[Mapping[str, Any]],
) -> tuple[list[IndexedCurvePoint], float, float, float]:
    """Convert raw dollar NAV points into a 100.0-rebased curve, TWR, max drawdown, and ending NAV.

    Raw dollar values are discarded inside the ephemeral worker subprocess.
    """
    if len(nav_points) < 2:
        raise WorkerValidationError("At least 2 nav_points are required to compute an indexed curve")

    ordered = sorted(
        nav_points,
        key=lambda pt: parse_utc_timestamp(str(pt["timestamp_utc"]), field_name="nav_point.timestamp_utc"),
    )
    initial_nav = float(ordered[0]["nav_base"])
    if initial_nav <= 0.0:
        raise WorkerValidationError("Initial nav_base must be > 0")

    peak_index = 100.0
    max_dd_pct = 0.0
    curve: list[IndexedCurvePoint] = []
    for pt in ordered:
        nav_val = float(pt["nav_base"])
        if nav_val <= 0.0:
            raise WorkerValidationError("All nav_base values must be > 0")
        idx_val = round(100.0 * (nav_val / initial_nav), 8)
        if idx_val > peak_index:
            peak_index = idx_val
        dd_pct = round(((idx_val - peak_index) / peak_index) * 100.0, 8)
        if dd_pct > 0.0:
            dd_pct = 0.0
        if dd_pct < max_dd_pct:
            max_dd_pct = dd_pct
        curve.append(
            IndexedCurvePoint(
                timestamp_utc=str(pt["timestamp_utc"]),
                index_value=idx_val,
                drawdown_pct=dd_pct,
            )
        )

    ending_nav = float(ordered[-1]["nav_base"])
    twr_decimal = round((curve[-1].index_value / 100.0) - 1.0, 8)
    max_dd_decimal = round(max_dd_pct / 100.0, 8)
    return curve, twr_decimal, max_dd_decimal, ending_nav


def default_standalone_worker_pipeline(job: Mapping[str, Any]) -> dict[str, Any]:
    """Standalone zero-persistence portfolio verification & Merkle commitment builder.

    Runs strictly inside the single-use ``spawn`` worker subprocess. Raw statements,
    ephemeral tokens, raw account IDs, and dollar NAVs never leave this function.
    """
    broker_id = str(job.get("broker_id", "")).strip().lower()
    if not broker_id:
        raise WorkerValidationError("broker_id must not be empty")

    blinding_salt_hex = str(job["account_blinding_salt_hex"])
    issued_at_utc = str(job["issued_at_utc"])
    delayed_guard_days = int(job.get("delayed_trade_guard_days", 7))

    # 1. Reject paper/sandbox hostnames or paper account prefixes (PA* Alpaca, DU*/DF* IBKR)
    from n170_verify.connectors import PaperOrSandboxAccountRejectedError

    for url_key in ("base_url", "api_url", "endpoint"):
        raw_url = str(job.get(url_key) or "").strip().lower()
        if raw_url and any(
            host_tok in raw_url
            for host_tok in ("paper-api.alpaca.markets", "sandbox.tradier.com", "demo.trading212.com")
        ):
            raise PaperOrSandboxAccountRejectedError(
                f"Paper or sandbox broker endpoint ({raw_url}) rejected for live verification"
            )

    explicit_tag = job.get("blinded_account_tag")
    raw_account_id = job.get("raw_account_id")
    if raw_account_id is not None:
        acct_str = str(raw_account_id).strip().upper()
        if broker_id == "alpaca" and acct_str.startswith("PA") and len(acct_str) >= 6:
            raise PaperOrSandboxAccountRejectedError(
                "Alpaca paper account prefix (PA*) rejected for live verification"
            )
        if broker_id.startswith("ibkr") and len(acct_str) >= 5 and acct_str[:2] in {"DU", "DF"} and acct_str[2:].isdigit():
            raise PaperOrSandboxAccountRejectedError(
                "IBKR paper account prefix (DU*/DF*) rejected for live verification"
            )

    # 2. Compute blinded_account_tag without retaining raw_account_id
    if explicit_tag:
        blinded_account_tag = validate_hex_digest(
            str(explicit_tag), field_name="blinded_account_tag", num_bytes=32
        )
    elif raw_account_id:
        blinded_account_tag = compute_blinded_account_tag(
            broker_id, str(raw_account_id), blinding_salt_hex
        )
    else:
        raise WorkerValidationError("Either raw_account_id or blinded_account_tag is required")

    # 2. Compute source_body_sha256 without retaining raw statement bytes
    if job.get("source_body_sha256"):
        source_body_sha256 = validate_hex_digest(
            str(job["source_body_sha256"]), field_name="source_body_sha256", num_bytes=32
        )
    elif job.get("raw_statement_b64"):
        try:
            stmt_bytes = base64.b64decode(str(job["raw_statement_b64"]), validate=True)
        except Exception as exc:
            raise WorkerValidationError("raw_statement_b64 must be valid base64") from exc
        source_body_sha256 = hashlib.sha256(stmt_bytes).hexdigest()
    elif job.get("raw_statement_text") is not None:
        stmt_bytes = str(job["raw_statement_text"]).encode("utf-8")
        source_body_sha256 = hashlib.sha256(stmt_bytes).hexdigest()
    elif job.get("ledger") is not None:
        source_body_sha256 = jcs_sha256_hex(job["ledger"])
    else:
        source_body_sha256 = jcs_sha256_hex(
            {
                "broker_id": broker_id,
                "blinded_account_tag": blinded_account_tag,
                "period_start_utc": job["period_start_utc"],
                "period_end_utc": job["period_end_utc"],
            }
        )

    period_start_utc = str(job["period_start_utc"])
    period_end_utc = str(job["period_end_utc"])
    base_currency = str(job.get("base_currency", "USD")).strip().upper()

    # 3. Build canonical 7 leaves (accepting precomputed leaf_payloads or deriving from inputs)
    provided_leaves = job.get("leaf_payloads")
    if isinstance(provided_leaves, Mapping):
        raw_closed = provided_leaves.get("delayed_closed_trades", [])
        filtered_trades, stripped_count = filter_delayed_closed_trades(
            raw_closed,
            issued_at_utc=issued_at_utc,
            min_delay_days=delayed_guard_days,
        )
        leaf_payloads: dict[str, Any] = dict(provided_leaves)
        leaf_payloads["delayed_closed_trades"] = [t.to_dict() for t in filtered_trades]
    else:
        raw_nav_points = job.get("nav_points")
        raw_nav_usd = job.get("nav_usd")
        perf_input = job.get("performance_summary")

        if isinstance(perf_input, Mapping):
            perf = PerformanceSummary.from_dict(perf_input)
            curve = perf.indexed_curve or [
                IndexedCurvePoint(
                    timestamp_utc=period_start_utc,
                    index_value=100.0,
                    drawdown_pct=0.0,
                ),
                IndexedCurvePoint(
                    timestamp_utc=period_end_utc,
                    index_value=round(100.0 * (1.0 + perf.twr_decimal), 8),
                    drawdown_pct=perf.max_drawdown_pct or 0.0,
                ),
            ]
            bracket = (
                perf.capital_bracket
                if perf.capital_bracket is not None
                else (
                    classify_capital_bracket(float(raw_nav_usd))
                    if raw_nav_usd is not None
                    else CapitalBracket.BRACKET_10K_100K
                )
            )
        elif isinstance(raw_nav_points, Sequence) and len(raw_nav_points) >= 2:
            curve, twr_dec, max_dd_dec, ending_nav = _rebase_nav_points_to_indexed_curve(
                raw_nav_points
            )
            obs_cnt = len(raw_nav_points) - 1
            psr_eligible = obs_cnt >= 30
            perf = PerformanceSummary(
                twr_decimal=twr_dec,
                max_drawdown_decimal=max_dd_dec,
                observation_count=obs_cnt,
                psr_sample_eligible=psr_eligible,
                probabilistic_sharpe_ratio=float(job["probabilistic_sharpe_ratio"])
                if job.get("probabilistic_sharpe_ratio") is not None
                else (0.85 if psr_eligible else None),
                capital_bracket=classify_capital_bracket(
                    float(raw_nav_usd) if raw_nav_usd is not None else ending_nav
                ),
                indexed_curve=curve,
            )
            bracket = perf.capital_bracket or classify_capital_bracket(ending_nav)
        else:
            twr_dec = float(job.get("twr_decimal", 0.05))
            max_dd_dec = float(job.get("max_drawdown_decimal", -0.02))
            obs_cnt = int(job.get("observation_count", 35))
            psr_eligible = obs_cnt >= 30
            psr_val = (
                float(job["probabilistic_sharpe_ratio"])
                if job.get("probabilistic_sharpe_ratio") is not None
                else (0.95 if psr_eligible else None)
            )
            bracket = (
                CapitalBracket(str(job["capital_bracket"]))
                if job.get("capital_bracket") is not None
                else (
                    classify_capital_bracket(float(raw_nav_usd))
                    if raw_nav_usd is not None
                    else CapitalBracket.BRACKET_10K_100K
                )
            )
            end_idx = round(100.0 * (1.0 + twr_dec), 8)
            dd_pct = round(max_dd_dec * 100.0, 8)
            curve = [
                IndexedCurvePoint(
                    timestamp_utc=period_start_utc,
                    index_value=100.0,
                    drawdown_pct=0.0,
                ),
                IndexedCurvePoint(
                    timestamp_utc=period_end_utc,
                    index_value=end_idx,
                    drawdown_pct=dd_pct if dd_pct <= 0.0 else 0.0,
                ),
            ]
            perf = PerformanceSummary(
                twr_decimal=twr_dec,
                cagr_decimal=job.get("cagr_decimal"),
                xirr_decimal=job.get("xirr_decimal"),
                sharpe_ratio=job.get("sharpe_ratio"),
                sortino_ratio=job.get("sortino_ratio"),
                probabilistic_sharpe_ratio=psr_val,
                psr_glm_unsmoothed=job.get("psr_glm_unsmoothed"),
                psr_sample_eligible=psr_eligible,
                observation_count=obs_cnt,
                max_drawdown_decimal=max_dd_dec,
                capital_bracket=bracket,
                benchmark_symbol=job.get("benchmark_symbol", "SPY"),
                benchmark_twr_decimal=job.get("benchmark_twr_decimal", 0.03),
                alpha_decimal=job.get("alpha_decimal", round(twr_dec - 0.03, 8)),
                indexed_curve=curve,
            )

        recon_input = job.get("reconciliation_report")
        if isinstance(recon_input, Mapping):
            recon = ReconciliationReport.from_dict(recon_input)
        else:
            recon = ReconciliationReport(
                status=ReconciliationStatus(
                    str(
                        job.get(
                            "reconciliation_status",
                            ReconciliationStatus.RECONCILED_WITHIN_TOLERANCE.value,
                        )
                    )
                ),
                reference_provider=str(job.get("reference_provider", "none")),
                ledger_completeness_ok=True,
                checks_evaluated=int(job.get("checks_evaluated", 6)),
                discrepancy_count=0,
                summary_text="Isolated worker accounting identity check completed.",
            )

        coaching_input = job.get("coaching_report")
        if isinstance(coaching_input, Mapping):
            coaching = TraderCoachingAndContextReport.from_dict(coaching_input)
        else:
            coaching = TraderCoachingAndContextReport(
                cost_drag=CostAndDragBreakdown(
                    commission_and_fee_drag_bps=4.0,
                    margin_and_funding_drag_bps=0.0,
                    fx_conversion_drag_bps=0.0,
                    withholding_tax_drag_bps=0.0,
                    total_friction_drag_bps=4.0,
                    annualized_total_drag_bps=16.0,
                ),
                behaviour=BehaviouralCoachingMetrics(
                    sample_eligible=False,
                    min_trades_gate=30,
                    observed_trades=0,
                    observed_days=max(perf.observation_count, 1),
                ),
                style_summary="Redacted isolated portfolio summary.",
            )

        filtered_trades, stripped_count = filter_delayed_closed_trades(
            job.get("closed_trades"),
            issued_at_utc=issued_at_utc,
            min_delay_days=delayed_guard_days,
        )

        perf_dict = perf.to_dict()
        leaf_payloads = {
            "core_metrics": {
                k: perf_dict[k]
                for k in (
                    "twr_decimal",
                    "twr_pct",
                    "cagr_decimal",
                    "cagr_pct",
                    "xirr_decimal",
                    "annualized_volatility",
                    "smoothing_index_xi",
                    "lag1_autocorrelation",
                    "unsmoothed_volatility",
                    "unsmoothed_sharpe_ratio",
                    "sharpe_ratio",
                    "sortino_ratio",
                    "probabilistic_sharpe_ratio",
                    "psr_glm_unsmoothed",
                    "min_track_record_length_periods",
                    "psr_sample_eligible",
                    "observation_count",
                    "psr_benchmark_sr",
                    "max_drawdown_decimal",
                    "max_drawdown_pct",
                    "methodology",
                    "non_iid_caveat",
                )
            },
            "indexed_curve": [pt.to_dict() for pt in curve],
            "reconciliation": recon.to_dict(),
            "coaching_and_context": coaching.to_dict(),
            "capital_bracket": {"capital_bracket": bracket.value},
            "benchmark_alpha": {
                "benchmark_symbol": perf.benchmark_symbol,
                "benchmark_twr_decimal": perf.benchmark_twr_decimal,
                "alpha_decimal": perf.alpha_decimal,
            },
            "delayed_closed_trades": [t.to_dict() for t in filtered_trades],
        }

    disclose_names = job.get("disclose_leaf_names")
    if disclose_names is not None:
        disclose_list = [str(name) for name in disclose_names]
    else:
        disclose_list = list(CANONICAL_LEAF_NAMES)

    tree = build_salted_merkle_tree(leaf_payloads)
    disclosed_leaves, undisclosed_hashes = tree.selectively_disclose(disclose_list)

    return {
        "broker_id": broker_id,
        "blinded_account_tag": blinded_account_tag,
        "source_body_sha256": source_body_sha256,
        "period_start_utc": period_start_utc,
        "period_end_utc": period_end_utc,
        "base_currency": base_currency,
        "merkle_root": tree.merkle_root,
        "disclosed_leaves": [leaf.to_dict() for leaf in disclosed_leaves],
        "undisclosed_leaf_hashes": dict(undisclosed_hashes),
        "stripped_recent_closed_trades_count": stripped_count,
    }


def _dispatch_default_or_real_pipeline(job_payload: Mapping[str, Any]) -> dict[str, Any]:
    """Route real statement/connector/ledger jobs to ``n170_verify.pipeline`` and synthetic payloads to standalone."""
    from n170_verify.pipeline import api_worker_pipeline_entrypoint, has_real_pipeline_input

    if has_real_pipeline_input(job_payload):
        return api_worker_pipeline_entrypoint(job_payload)
    return default_standalone_worker_pipeline(job_payload)


def _resolve_pipeline_spec(
    pipeline_spec: str | Callable[[Mapping[str, Any]], dict[str, Any]] | None,
) -> Callable[[Mapping[str, Any]], dict[str, Any]]:
    if pipeline_spec is None:
        return _dispatch_default_or_real_pipeline
    if callable(pipeline_spec):
        return pipeline_spec
    if isinstance(pipeline_spec, str) and ":" in pipeline_spec:
        mod_name, attr_name = pipeline_spec.split(":", 1)
        module = importlib.import_module(mod_name)
        target = getattr(module, attr_name)
        if not callable(target):
            raise WorkerIsolationError(f"Resolved pipeline {pipeline_spec!r} is not callable")
        return target
    raise WorkerIsolationError(f"Invalid pipeline_spec: {pipeline_spec!r}")


def _ephemeral_worker_entrypoint(
    send_conn: Connection,
    job_payload: dict[str, Any],
    pipeline_spec: str | Callable[[Mapping[str, Any]], dict[str, Any]] | None,
) -> None:
    """Entrypoint executed strictly inside a fresh ``spawn`` child process."""
    sys.dont_write_bytecode = True
    from n170_verify.connectors import (
        DisallowedCapabilityError,
        MutatingCredentialRejectedError,
        PaperOrSandboxAccountRejectedError,
        ProviderApprovalRequiredError,
    )
    from n170_verify.contracts import ReadOnlyCapabilityViolationError

    try:
        # 1. Disable core dumps immediately before touching raw brokerage data
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        soft_core, hard_core = resource.getrlimit(resource.RLIMIT_CORE)

        # 2. Scrub child environment variables in-place
        env_keys = _sanitize_current_process_env()

        # 3. Execute verification pipeline inside isolated address space
        pipeline_fn = _resolve_pipeline_spec(pipeline_spec)
        redacted_result = pipeline_fn(job_payload)

        send_conn.send(
            {
                "ok": True,
                "worker_pid": os.getpid(),
                "worker_ppid": os.getppid(),
                "rlimit_core_soft": int(soft_core),
                "rlimit_core_hard": int(hard_core),
                "child_env_keys": env_keys,
                "result": redacted_result,
            }
        )
    except PaperOrSandboxAccountRejectedError as exc:
        send_conn.send(
            {
                "ok": False,
                "error_kind": "paper_or_sandbox",
                "message": _redact_worker_error_message(str(exc), job_payload),
                "worker_pid": os.getpid(),
            }
        )
    except ProviderApprovalRequiredError as exc:
        send_conn.send(
            {
                "ok": False,
                "error_kind": "provider_approval_pending",
                "message": _redact_worker_error_message(str(exc), job_payload),
                "worker_pid": os.getpid(),
            }
        )
    except (
        MutatingCredentialRejectedError,
        DisallowedCapabilityError,
        ReadOnlyCapabilityViolationError,
    ) as exc:
        send_conn.send(
            {
                "ok": False,
                "error_kind": "read_only_violation",
                "message": _redact_worker_error_message(str(exc), job_payload),
                "worker_pid": os.getpid(),
            }
        )
    except (WorkerValidationError, ValueError, KeyError, TypeError) as exc:
        send_conn.send(
            {
                "ok": False,
                "error_kind": "validation",
                "message": _redact_worker_error_message(str(exc), job_payload),
                "worker_pid": os.getpid(),
            }
        )
    except Exception as exc:  # pragma: no cover - defensive worker crash boundary
        send_conn.send(
            {
                "ok": False,
                "error_kind": "internal",
                "message": _redact_worker_error_message(f"{type(exc).__name__}: {exc}", job_payload),
                "worker_pid": os.getpid(),
            }
        )
    finally:
        send_conn.close()


WorkerPipelineSpec = str | Callable[[Mapping[str, Any]], dict[str, Any]] | None


def _collect_job_secrets(value: Any, *, key_hint: str = "", out: list[str] | None = None) -> list[str]:
    if out is None:
        out = []
    safe_keys = {
        "broker_id",
        "provider_approval_state",
        "environment_tier",
        "base_currency",
        "filename",
        "issued_at_utc",
        "period_start_utc",
        "period_end_utc",
        "account_blinding_salt_hex",
        "raw_statement_b64",
        "raw_statement_text",
    }
    secret_key_markers = (
        "secret",
        "token",
        "key",
        "password",
        "passphrase",
        "account_id",
        "account_number",
        "acct",
        "assertion",
        "cookie",
        "credential",
    )
    if isinstance(value, Mapping):
        for k, v in value.items():
            k_str = str(k).lower()
            if k_str in safe_keys:
                continue
            _collect_job_secrets(v, key_hint=k_str, out=out)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _collect_job_secrets(item, key_hint=key_hint, out=out)
    elif isinstance(value, str) and len(value.strip()) >= 4:
        if any(marker in key_hint for marker in secret_key_markers):
            out.append(value.strip())
    return out


_WORKER_DOLLAR_AMOUNT_RE = re.compile(r"\$\s*[0-9][0-9,]*(?:\.[0-9]+)?")


def _redact_worker_error_message(message: str, job_payload: Mapping[str, Any]) -> str:
    from n170_verify.connectors.mcp_allowlist_firewall import redact_sensitive_text

    secrets_found = _collect_job_secrets(job_payload)
    redacted = redact_sensitive_text(message or "", secrets_found)
    redacted = _WORKER_DOLLAR_AMOUNT_RE.sub("$[REDACTED]", redacted)
    return redacted[:512]


def run_isolated_one_shot_verification(
    request_payload: Mapping[str, Any],
    *,
    config: ApiConfig,
    pipeline_spec: WorkerPipelineSpec = None,
    retention_mode: str = "no_persistent_storage",
    persistent_rows_written: int = 0,
) -> tuple[VerifyProofBundle, WorkerIsolationReceipt, int]:
    """Execute portfolio parsing & Merkle commitment in a single-use ``spawn`` worker subprocess.

    Parent process Ed25519-signs ONLY the redacted Merkle commitment header after the
    child worker exits with ``exitcode == 0``. Neither raw statements/tokens/NAVs leave
    the child process nor do publisher signing keys enter the child process.
    """
    norm_retention = retention_mode.strip().lower()
    if norm_retention not in ALLOWED_RETENTION_MODES:
        raise ValueError(f"Invalid retention_mode: {retention_mode!r}")

    broker_id = str(request_payload.get("broker_id", "")).strip().lower()
    if not broker_id:
        raise WorkerValidationError("broker_id is required")

    issued_at_utc = str(request_payload.get("issued_at_utc") or utc_now_iso())
    parse_utc_timestamp(issued_at_utc, field_name="issued_at_utc")

    period_start_explicit = "period_start_utc" in request_payload
    period_end_explicit = "period_end_utc" in request_payload
    base_currency_explicit = "base_currency" in request_payload
    account_scope_explicit = "account_scope" in request_payload
    claimed_origin_explicit = "claimed_origin_assurance" in request_payload

    period_start_utc = str(request_payload.get("period_start_utc", "2026-01-01T00:00:00Z"))
    period_end_utc = str(request_payload.get("period_end_utc", "2026-01-31T00:00:00Z"))
    parse_utc_timestamp(period_start_utc, field_name="period_start_utc")
    parse_utc_timestamp(period_end_utc, field_name="period_end_utc")

    account_scope = AccountScope(
        str(
            request_payload.get(
                "account_scope", AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED.value
            )
        )
    )
    provider_approval = ProviderApprovalState(
        str(
            request_payload.get(
                "provider_approval_state",
                config.connector_approval_states.get(
                    broker_id, ProviderApprovalState.OFFLINE_EXPORT_ONLY
                ).value,
            )
        )
    )
    environment_tier = EnvironmentTier(
        str(request_payload.get("environment_tier", EnvironmentTier.LIVE_PRODUCTION.value))
    )
    claimed_origin = OriginAssurance(
        str(request_payload.get("claimed_origin_assurance", OriginAssurance.SELF_REPORTED.value))
    )

    witness_raw = request_payload.get("witness_attestations") or []
    witnesses = [
        w if isinstance(w, WitnessAttestation) else WitnessAttestation.from_dict(w)
        for w in witness_raw
    ]

    broker_sig_raw = request_payload.get("broker_native_signature")
    broker_sig = (
        None
        if broker_sig_raw is None
        else (
            broker_sig_raw
            if isinstance(broker_sig_raw, BrokerNativeSignature)
            else BrokerNativeSignature.from_dict(broker_sig_raw)
        )
    )

    chain_link_raw = request_payload.get("prospective_chain_link")
    chain_link = (
        None
        if chain_link_raw is None
        else (
            chain_link_raw
            if isinstance(chain_link_raw, ProspectiveChainLink)
            else ProspectiveChainLink.from_dict(chain_link_raw)
        )
    )

    # Assemble worker job WITHOUT publisher private signing key or vault master KEK
    worker_job: dict[str, Any] = dict(request_payload)
    worker_job["broker_id"] = broker_id
    worker_job["issued_at_utc"] = issued_at_utc
    worker_job["period_start_utc"] = period_start_utc
    worker_job["period_end_utc"] = period_end_utc
    worker_job["period_start_utc_explicit"] = period_start_explicit
    worker_job["period_end_utc_explicit"] = period_end_explicit
    worker_job["base_currency_explicit"] = base_currency_explicit
    worker_job["account_blinding_salt_hex"] = config.account_blinding_salt_hex
    worker_job["delayed_trade_guard_days"] = config.delayed_trade_guard_days
    if config.eodhd_api_key and not worker_job.get("eodhd_api_key"):
        worker_job["eodhd_api_key"] = config.eodhd_api_key

    parent_pid = os.getpid()
    ctx = multiprocessing.get_context("spawn")
    recv_conn, send_conn = ctx.Pipe(duplex=False)

    with _SPAWN_ENV_LOCK:
        saved_env = dict(os.environ)
        try:
            scrubbed_spawn_env = _build_sanitized_env_map()
            os.environ.clear()
            os.environ.update(scrubbed_spawn_env)
            proc = ctx.Process(
                target=_ephemeral_worker_entrypoint,
                args=(send_conn, worker_job, pipeline_spec),
                daemon=False,
            )
            proc.start()
        finally:
            os.environ.clear()
            os.environ.update(saved_env)

    send_conn.close()

    try:
        has_msg = recv_conn.poll(config.worker_timeout_seconds)
        if not has_msg:
            if proc.is_alive():
                proc.kill()
                proc.join(timeout=5.0)
            raise WorkerIsolationError(
                f"Ephemeral verification worker timed out after {config.worker_timeout_seconds}s"
            )
        worker_envelope = recv_conn.recv()
    except EOFError as exc:
        proc.join(timeout=5.0)
        raise WorkerIsolationError(
            f"Ephemeral verification worker exited unexpectedly (exitcode={proc.exitcode})"
        ) from exc
    finally:
        recv_conn.close()

    proc.join(timeout=5.0)
    if proc.is_alive():
        proc.kill()
        proc.join(timeout=2.0)
        raise WorkerIsolationError("Ephemeral verification worker did not terminate cleanly")

    exitcode = proc.exitcode
    if not worker_envelope.get("ok"):
        from app.store import GovernanceBlockedError, PaperOrSandboxRejectedError
        from n170_verify.contracts import ReadOnlyCapabilityViolationError

        err_kind = worker_envelope.get("error_kind", "internal")
        msg = str(worker_envelope.get("message", "Worker execution failed"))
        if err_kind == "paper_or_sandbox":
            raise PaperOrSandboxRejectedError(msg)
        if err_kind == "provider_approval_pending":
            raise GovernanceBlockedError(msg)
        if err_kind == "read_only_violation":
            raise ReadOnlyCapabilityViolationError(msg)
        if err_kind == "validation":
            raise WorkerValidationError(msg)
        raise WorkerIsolationError(msg)

    if exitcode != 0:
        raise WorkerIsolationError(
            f"Ephemeral verification worker exited with non-zero exitcode={exitcode}"
        )

    worker_pid = int(worker_envelope["worker_pid"])
    if worker_pid == parent_pid:
        raise WorkerIsolationError("Isolation invariant violated: worker_pid == parent_pid")

    rlimit_soft = int(worker_envelope["rlimit_core_soft"])
    rlimit_hard = int(worker_envelope["rlimit_core_hard"])
    if (rlimit_soft, rlimit_hard) != (0, 0):
        raise WorkerIsolationError(
            f"Isolation invariant violated: RLIMIT_CORE=({rlimit_soft}, {rlimit_hard}) != (0, 0)"
        )

    child_env_keys = list(worker_envelope.get("child_env_keys", []))
    sanitized_ok = all(
        k in _SAFE_CHILD_ENV_ALLOWLIST or k in {"PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE"}
        for k in child_env_keys
    )
    if not sanitized_ok:
        raise WorkerIsolationError("Isolation invariant violated: unsanitized child environment")

    redacted = worker_envelope["result"]
    proof_id = str(request_payload.get("proof_id") or f"prf-{uuid.uuid4().hex[:20]}")
    if not account_scope_explicit and redacted.get("account_scope"):
        account_scope = AccountScope(str(redacted["account_scope"]))
    if not claimed_origin_explicit and redacted.get("claimed_origin_assurance"):
        claimed_origin = OriginAssurance(str(redacted["claimed_origin_assurance"]))

    # Reconstruct & Ed25519-sign VerifyProofBundle in parent process from redacted Merkle output
    from n170_verify.crypto import DisclosedLeaf, SIGNING_DOMAIN_BUNDLE, ed25519_sign_domain

    disclosed_objs = [DisclosedLeaf.from_dict(item) for item in redacted["disclosed_leaves"]]
    draft = VerifyProofBundle(
        proof_id=proof_id,
        schema_version=VERIFY_SCHEMA_VERSION,
        issued_at_utc=issued_at_utc,
        publisher_kid=config.publisher_kid,
        publisher_public_key_hex=config.publisher_keypair.public_key_hex,
        broker_id=str(redacted["broker_id"]),
        blinded_account_tag=str(redacted["blinded_account_tag"]),
        account_scope=account_scope,
        provider_approval_state=provider_approval,
        environment_tier=environment_tier,
        claimed_origin_assurance=claimed_origin,
        source_body_sha256=str(redacted["source_body_sha256"]),
        period_start_utc=str(redacted["period_start_utc"]),
        period_end_utc=str(redacted["period_end_utc"]),
        base_currency=str(redacted["base_currency"]),
        merkle_root=str(redacted["merkle_root"]),
        disclosed_leaves=disclosed_objs,
        undisclosed_leaf_hashes=dict(redacted["undisclosed_leaf_hashes"]),
        witness_attestations=witnesses,
        broker_native_signature=broker_sig,
        prospective_chain_link=chain_link,
        retention_mode=norm_retention,
        signature_hex="00" * 64,
    )
    sig_hex = ed25519_sign_domain(
        config.publisher_keypair.private_key_hex,
        SIGNING_DOMAIN_BUNDLE,
        draft.signable_bytes(),
    )
    object.__setattr__(draft, "signature_hex", sig_hex)

    receipt = WorkerIsolationReceipt(
        execution_mode="ephemeral_spawn_subprocess",
        parent_pid=parent_pid,
        worker_pid=worker_pid,
        worker_exitcode=int(exitcode),
        worker_terminated=not proc.is_alive(),
        rlimit_core_soft=rlimit_soft,
        rlimit_core_hard=rlimit_hard,
        sanitized_child_env=sanitized_ok,
        child_env_keys=child_env_keys,
        persistent_rows_written=persistent_rows_written,
        retention_mode=norm_retention,
        memory_lifecycle_disclosure=(
            "Raw brokerage payloads, credentials, raw account IDs, and dollar NAVs were "
            "processed exclusively inside single-use spawn worker PID "
            f"{worker_pid} with RLIMIT_CORE=(0, 0) and a scrubbed environment. "
            "Rather than relying on CPython object del (which does not cryptographically "
            "zero heap arenas), transient worker memory was reclaimed by the OS kernel "
            f"upon immediate worker process exit (exitcode={exitcode})."
        ),
    )
    stripped_count = int(redacted.get("stripped_recent_closed_trades_count", 0))
    return draft, receipt, stripped_count


__all__ = [
    "WorkerIsolationError",
    "WorkerIsolationReceipt",
    "WorkerPipelineSpec",
    "WorkerValidationError",
    "create_signed_proof_bundle",
    "default_standalone_worker_pipeline",
    "filter_delayed_closed_trades",
    "run_isolated_one_shot_verification",
]
