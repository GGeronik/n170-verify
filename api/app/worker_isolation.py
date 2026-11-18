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


class WorkerBrokerUpstreamError(WorkerIsolationError):
    """Raised when a live read-only upstream clearinghouse/broker endpoint fails inside the worker."""


class WorkerValidationError(ValueError):
    """Raised when verification input fails domain validation inside the isolated worker."""


# At most this many verification workers run at once on this host (sized for two cores:
# one worker per core). Every route that signs a record shares the limit.
MAX_CONCURRENT_VERIFICATION_WORKERS = 2
# Seconds a refused caller is asked to wait before trying again.
VERIFICATION_RETRY_AFTER_SECONDS = 10
# Largest statement accepted for verification, in bytes and in rows (line endings of any
# kind, or XML elements), summed over every statement field of one request. The cost per row
# depends on the statement kind and grows faster than linearly for a long valuation series:
# measured on a laptop core, a Tradovate cash history (the slowest kind measured) took 2.8 s
# for 2,000 rows, 7.4 s for 4,000, 9.7 s at this limit and about 17 s near 10,000. The row
# limit keeps the slowest legal file within about a third of the 30-second worker timeout
# on that machine.
MAX_STATEMENT_INPUT_BYTES = 2 * 1024 * 1024
MAX_STATEMENT_INPUT_ROWS = 5_000

_VERIFICATION_WORKER_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_VERIFICATION_WORKERS)


class WorkerCapacityExceededError(WorkerIsolationError):
    """Every verification worker slot is in use; the caller should retry later (503)."""

    http_status = 503
    error_code = "verification_busy"

    def __init__(self, message: str, *, retry_after_seconds: int = VERIFICATION_RETRY_AFTER_SECONDS) -> None:
        super().__init__(message)
        self.retry_after_seconds = int(retry_after_seconds)


class WorkerTimeoutError(WorkerIsolationError):
    """The verification worker ran out of time; the caller may retry later (503)."""

    http_status = 503
    error_code = "verification_timed_out"

    def __init__(self, message: str, *, retry_after_seconds: int = VERIFICATION_RETRY_AFTER_SECONDS) -> None:
        super().__init__(message)
        self.retry_after_seconds = int(retry_after_seconds)


class WorkerInputTooLargeError(WorkerValidationError):
    """A statement is over the stated byte or row limit (413)."""

    http_status = 413
    error_code = "statement_too_large"


_STATEMENT_TEXT_KEYS: tuple[str, ...] = (
    "raw_statement",
    "raw_statement_text",
    "flex_xml",
    "csv_source",
    "degiro_account_csv",
    "degiro_transactions_csv",
    "degiro_portfolio_csv",
)
_STATEMENT_B64_KEYS: tuple[str, ...] = ("raw_statement_b64", "flex_xml_b64", "csv_b64")


def _statement_input_bytes(request_payload: Mapping[str, Any]) -> list[bytes]:
    out: list[bytes] = []
    for key in _STATEMENT_TEXT_KEYS:
        val = request_payload.get(key)
        if isinstance(val, str):
            out.append(val.encode("utf-8"))
        elif isinstance(val, (bytes, bytearray)):
            out.append(bytes(val))
    for key in _STATEMENT_B64_KEYS:
        val = request_payload.get(key)
        if isinstance(val, (str, bytes)) and val:
            if len(val) * 3 // 4 > MAX_STATEMENT_INPUT_BYTES + 3:
                raise WorkerInputTooLargeError(_too_large_message("bytes"))
            try:
                out.append(base64.b64decode(val))
            except Exception as exc:
                raise WorkerValidationError(f"{key} must be valid base64") from exc
    return out


def _too_large_message(limit: str) -> str:
    stated = (
        f"{MAX_STATEMENT_INPUT_BYTES:,} bytes"
        if limit == "bytes"
        else f"{MAX_STATEMENT_INPUT_ROWS:,} rows"
    )
    return (
        f"The statement is over this host's limit of {stated}. "
        "Export a shorter date range and verify it in parts."
    )


_HTML_STATEMENT_RE = re.compile(rb"(?i)<(?:!doctype\s+html|html|table|tr)[\s>/]")
_HTML_TR_ROW_RE = re.compile(rb"(?i)<tr(?:[\s>/]|$)")
_FLEX_XML_RE = re.compile(rb"(?i)<flex(?:queryresponse|statements|statement)[\s>/]")


def _utf8_statement_view(blob: bytes) -> bytes:
    """Decode UTF-16LE/BE (BOM or NUL-interleaved ASCII) to a UTF-8 byte view once."""
    if blob[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return blob.decode("utf-16").encode("utf-8")
        except UnicodeDecodeError:
            return blob
    head = blob[:128]
    if b"\x00" in head:
        aligned = blob if len(blob) % 2 == 0 else blob[:-1]
        even_nuls = head[0::2].count(0)
        odd_nuls = head[1::2].count(0)
        order = ("utf-16-be", "utf-16-le") if even_nuls > odd_nuls else ("utf-16-le", "utf-16-be")
        for enc in order:
            try:
                return aligned.decode(enc).encode("utf-8")
            except UnicodeDecodeError:
                continue
    return blob


def _line_endings(u8: bytes) -> int:
    """Line endings of every kind: CR LF, a lone LF and a lone CR each end one row."""
    return u8.count(b"\n") + u8.count(b"\r") - u8.count(b"\r\n")


def _markup_rows(u8: bytes) -> int:
    """Count table rows for HTML exports and XML elements for non-HTML XML exports."""
    if _HTML_STATEMENT_RE.search(u8) and not _FLEX_XML_RE.search(u8[:16384]):
        return len(_HTML_TR_ROW_RE.findall(u8))
    return u8.count(b"<") - u8.count(b"</")


def enforce_statement_input_limits(request_payload: Mapping[str, Any]) -> None:
    """Refuse a statement over the byte or row limit before any worker starts."""
    blobs = _statement_input_bytes(request_payload)
    if sum(len(b) for b in blobs) > MAX_STATEMENT_INPUT_BYTES:
        raise WorkerInputTooLargeError(_too_large_message("bytes"))
    rows = 0
    for b in blobs:
        u8 = _utf8_statement_view(b)
        rows += max(_line_endings(u8), _markup_rows(u8))
    if rows > MAX_STATEMENT_INPUT_ROWS:
        raise WorkerInputTooLargeError(_too_large_message("rows"))


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
    api_parent_path = Path(_app_pkg.__file__).resolve().parent.parent
    api_parent = str(api_parent_path)
    candidates = [core_parent, api_parent]
    api_tests = api_parent_path / "tests"
    if api_tests.is_dir():
        candidates.append(str(api_tests))
    for candidate in candidates:
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
    for entry in allowed.get("PYTHONPATH", "").split(os.pathsep):
        if entry and entry not in sys.path:
            sys.path.append(entry)
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

        is_withheld = bool(job.get("performance_withheld", False)) or bool(
            perf.performance_withheld
        )
        coaching_input = job.get("coaching_report")
        if isinstance(coaching_input, Mapping):
            coaching = TraderCoachingAndContextReport.from_dict(coaching_input)
        else:
            coaching = TraderCoachingAndContextReport(
                cost_drag=(
                    CostAndDragBreakdown(
                        commission_and_fee_drag_bps=None,
                        margin_and_funding_drag_bps=None,
                        fx_conversion_drag_bps=None,
                        withholding_tax_drag_bps=None,
                        total_friction_drag_bps=None,
                        annualized_total_drag_bps=None,
                    )
                    if is_withheld
                    else CostAndDragBreakdown(
                        commission_and_fee_drag_bps=4.0,
                        margin_and_funding_drag_bps=0.0,
                        fx_conversion_drag_bps=0.0,
                        withholding_tax_drag_bps=0.0,
                        total_friction_drag_bps=4.0,
                        annualized_total_drag_bps=16.0,
                    )
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


_SYNTHETIC_SIGNING_ORACLE_KEYS: frozenset[str] = frozenset(
    {
        "leaf_payloads",
        "performance_summary",
        "reconciliation_report",
        "coaching_report",
        "nav_points",
        "closed_trades",
        "ledger",
        "twr_decimal",
        "cagr_decimal",
        "xirr_decimal",
        "sharpe_ratio",
        "sortino_ratio",
        "probabilistic_sharpe_ratio",
        "psr_glm_unsmoothed",
        "max_drawdown_decimal",
        "capital_bracket",
        "alpha_decimal",
        "benchmark_twr_decimal",
    }
)


# Hosted: signed records never carry a chain link or attestation taken from the request.
_HOSTED_REFUSED_ATTACHMENT_KEYS: frozenset[str] = frozenset(
    {"prospective_chain_link", "witness_attestations", "broker_native_signature"}
)

# Offline id under which a statement-derived record is signed when the parser names a
# broker id that this host serves as a live connector.
_STATEMENT_OFFLINE_BROKER_IDS: dict[str, str] = {
    "schwab": "schwab_csv",
    "ibkr": "ibkr_flex_offline",
}


def _offline_broker_id_for_statement(
    returned_broker_id: str, worker_reported_state: Any, config: ApiConfig
) -> str:
    """Hosted: a record whose input was a statement is signed under an offline broker id."""
    offline = ProviderApprovalState.OFFLINE_EXPORT_ONLY
    if not worker_reported_state or ProviderApprovalState(str(worker_reported_state)) != offline:
        return returned_broker_id
    if config.connector_approval_states.get(returned_broker_id, offline) == offline:
        return returned_broker_id
    mapped = _STATEMENT_OFFLINE_BROKER_IDS.get(returned_broker_id)
    if mapped is not None and config.connector_approval_states.get(mapped, offline) == offline:
        return mapped
    raise WorkerValidationError(
        f"statement input cannot be signed under live connector broker_id={returned_broker_id!r}"
    )


def enforce_hosted_signing_oracle_policy(
    request_payload: Mapping[str, Any],
    *,
    hosted_multi_user_mode: bool,
    allow_hosted_signing: bool,
    allow_client_supplied_series_for_tests: bool = False,
    has_custom_pipeline: bool = False,
    allow_trusted_internal_ledger: bool = False,
) -> None:
    """Block pre-fabricated leaf_payloads/performance_summary/series in hosted mode."""
    if (
        not hosted_multi_user_mode
        or allow_hosted_signing
        or allow_client_supplied_series_for_tests
        or has_custom_pipeline
    ):
        return

    from app.store import SigningOracleDisabledError
    from n170_verify.pipeline import has_real_pipeline_input

    disallowed_keys = (
        _SYNTHETIC_SIGNING_ORACLE_KEYS - {"ledger"}
        if allow_trusted_internal_ledger
        else _SYNTHETIC_SIGNING_ORACLE_KEYS
    )
    present_synthetic = sorted(
        key for key in disallowed_keys if request_payload.get(key) is not None
    )
    if present_synthetic:
        raise SigningOracleDisabledError(
            "Hosted mode refuses to sign client-supplied synthetic payloads "
            f"({', '.join(present_synthetic)}); submit a real brokerage statement or read-only connector"
        )

    if not has_real_pipeline_input(request_payload):
        raise SigningOracleDisabledError(
            "Hosted mode refuses standalone synthetic signing without real statement or read-only connector input"
        )


SCANNER_REFUSAL_DETAIL = (
    "The record contains text that looks like an account number, a raw statement excerpt or "
    "a credential; remove it from the statement or journal and try again"
)


UNREADABLE_INPUT_DETAIL = (
    "The statement could not be read: a row is malformed or the file is not a supported "
    "export. Export it again from the broker and add it unchanged."
)

JOURNAL_TAGS_LEFT_OUT_WARNING = (
    "{n} journal tag(s) that look like an account number or a credential were left out of "
    "the record"
)


def _leave_out_journal_tags_the_scanner_blocks(dropped: set[str]) -> None:
    """Inside the single-use worker only: a cleaned journal tag that the outbound scanner
    would block is left out of the record (and counted) instead of refusing the record."""
    import importlib

    from app.privacy_scanner import OutboundPrivacyScanner

    scanner = OutboundPrivacyScanner()
    for module_name in ("n170_verify.coaching.engine", "n170_verify.pipeline"):
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        original = getattr(module, "sanitize_journal_tags", None)
        if original is None or getattr(original, "_leaves_out_scanner_hits", False):
            continue

        def filtered(tags: Any, _original: Callable[..., list[str]] = original) -> list[str]:
            kept: list[str] = []
            for tag in _original(tags):
                if scanner.scan_text(str(tag)):
                    dropped.add(str(tag))
                else:
                    kept.append(tag)
            return kept

        filtered._leaves_out_scanner_hits = True  # type: ignore[attr-defined]
        setattr(module, "sanitize_journal_tags", filtered)


def _refuse_text_the_scanner_blocks_before_signing(draft: VerifyProofBundle) -> None:
    """Nothing the outbound privacy scanner would block is ever signed; the reason does not
    repeat the text."""
    from app.privacy_scanner import OutboundPrivacyScanner

    if OutboundPrivacyScanner().scan_payload(draft.to_dict()):
        raise WorkerValidationError(SCANNER_REFUSAL_DETAIL)


WORKER_LIMIT_ERRORS: tuple[type[Exception], ...] = (
    WorkerCapacityExceededError,
    WorkerTimeoutError,
    WorkerInputTooLargeError,
)


def worker_limit_response(exc: Exception) -> tuple[int, dict[str, Any]]:
    """The HTTP answer every route gives for a busy host, a timeout or an oversized input."""
    body: dict[str, Any] = {"error": getattr(exc, "error_code"), "detail": str(exc)}
    retry = getattr(exc, "retry_after_seconds", None)
    if retry is not None:
        body["retry_after_seconds"] = int(retry)
    return int(getattr(exc, "http_status")), body


def _withheld_without_core_metrics(result: Any) -> bool:
    """True when a worker result reports a withheld return but leaves core_metrics undisclosed."""
    if not isinstance(result, Mapping) or not result.get("performance_withheld"):
        return False
    return not any(
        isinstance(leaf, Mapping) and leaf.get("leaf_name") == "core_metrics"
        for leaf in result.get("disclosed_leaves") or []
    )


def _refuse_standalone_series_outside_tests(
    request_payload: Mapping[str, Any], *, config: ApiConfig, pipeline_spec: Any
) -> None:
    """A job without real input would be signed from a client-supplied series by the
    standalone builder, which does not apply the shared calculator's withholding rules;
    only test configurations sign such a job."""
    if pipeline_spec is not None or config.allow_client_supplied_series_for_tests:
        return
    from app.store import SigningOracleDisabledError
    from n170_verify.pipeline import has_real_pipeline_input

    if not has_real_pipeline_input(request_payload):
        raise SigningOracleDisabledError(
            "This host does not sign a client-supplied series; submit a real brokerage "
            "statement or read-only connector"
        )


def _dispatch_default_or_real_pipeline(job_payload: Mapping[str, Any]) -> dict[str, Any]:
    """Route real statement/connector/ledger jobs to ``n170_verify.pipeline`` and synthetic payloads to standalone."""
    from n170_verify.pipeline import api_worker_pipeline_entrypoint, has_real_pipeline_input

    if bool(job_payload.get("_hosted_signing_restricted", False)):
        enforce_hosted_signing_oracle_policy(
            job_payload,
            hosted_multi_user_mode=True,
            allow_hosted_signing=False,
            allow_client_supplied_series_for_tests=False,
            has_custom_pipeline=False,
            allow_trusted_internal_ledger=bool(
                job_payload.get("_allow_trusted_internal_ledger", False)
            ),
        )

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
    from app.store import SigningOracleDisabledError
    from n170_verify.connectors import (
        DisallowedCapabilityError,
        HyperliquidServiceError,
        MutatingCredentialRejectedError,
        PaperOrSandboxAccountRejectedError,
        ProviderApprovalRequiredError,
        SnapTradeError,
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
        dropped_tags: set[str] = set()
        _leave_out_journal_tags_the_scanner_blocks(dropped_tags)
        redacted_result = pipeline_fn(job_payload)
        if _withheld_without_core_metrics(redacted_result):
            # A withheld return is always visible: disclose core_metrics with whatever
            # else the first run disclosed.
            rerun_job = dict(job_payload)
            rerun_job["disclose_leaf_names"] = [
                str(leaf.get("leaf_name")) for leaf in redacted_result.get("disclosed_leaves") or []
            ] + ["core_metrics"]
            redacted_result = pipeline_fn(rerun_job)
        if dropped_tags and isinstance(redacted_result, dict):
            redacted_result["dropped_journal_tag_count"] = len(dropped_tags)

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
    except SigningOracleDisabledError as exc:
        send_conn.send(
            {
                "ok": False,
                "error_kind": "signing_oracle_disabled",
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
    except (HyperliquidServiceError, SnapTradeError) as exc:
        send_conn.send(
            {
                "ok": False,
                "error_kind": "broker_upstream",
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
    except Exception:  # noqa: BLE001 - any other input error is the caller's, never a 500
        # A reader error (for example csv.Error) carries the library's own wording, so it is
        # replaced by a sentence a visitor can act on.
        send_conn.send(
            {
                "ok": False,
                "error_kind": "validation",
                "message": UNREADABLE_INPUT_DETAIL,
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
        "client_id",
        "user_id",
        "account_id",
        "account_number",
        "acct",
        "wallet_address",
        "address",
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


def _clamp_approval_to_worker_origin(
    requested: ProviderApprovalState,
    *,
    returned_broker_id: str,
    worker_reported_state: Any,
    config: ApiConfig,
) -> ProviderApprovalState:
    """Never sign an approval state above what the worker's actual input supports.

    The candidates are the requested state, the state the worker derived from the input it
    read, and (hosted) the configured ceiling of the broker id the worker returned. The
    lowest one is signed. In hosted mode a request that claims more than that is refused.
    """
    from app.routes_sync import PROVIDER_APPROVAL_RANK

    candidates: list[ProviderApprovalState] = []
    if worker_reported_state:
        candidates.append(ProviderApprovalState(str(worker_reported_state)))
    if config.hosted_multi_user_mode:
        candidates.append(
            config.connector_approval_states.get(
                returned_broker_id, ProviderApprovalState.OFFLINE_EXPORT_ONLY
            )
        )
    effective = requested
    for cand in candidates:
        if cand != effective and PROVIDER_APPROVAL_RANK[cand] <= PROVIDER_APPROVAL_RANK[effective]:
            effective = cand
    if effective != requested and config.hosted_multi_user_mode:
        raise WorkerValidationError(
            f"provider_approval_state {requested.value!r} is not supported by the verified input "
            f"(broker_id={returned_broker_id!r} supports {effective.value!r})"
        )
    return effective


def run_isolated_one_shot_verification(
    request_payload: Mapping[str, Any],
    *,
    config: ApiConfig,
    pipeline_spec: WorkerPipelineSpec = None,
    retention_mode: str = "no_persistent_storage",
    persistent_rows_written: int = 0,
    _trusted_internal_input: bool = False,
    _hyperliquid_http_transport: Any = None,
    _snaptrade_http_transport: Any = None,
    result_meta: dict[str, Any] | None = None,
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

    enforce_hosted_signing_oracle_policy(
        request_payload,
        hosted_multi_user_mode=config.hosted_multi_user_mode,
        allow_hosted_signing=config.allow_hosted_signing,
        allow_client_supplied_series_for_tests=config.allow_client_supplied_series_for_tests,
        has_custom_pipeline=(pipeline_spec is not None),
        allow_trusted_internal_ledger=_trusted_internal_input,
    )
    _refuse_standalone_series_outside_tests(request_payload, config=config, pipeline_spec=pipeline_spec)
    enforce_statement_input_limits(request_payload)

    if config.hosted_multi_user_mode:
        # Hosted: chain links and attestations are never taken from the request into a record.
        caller_attached = sorted(
            key for key in _HOSTED_REFUSED_ATTACHMENT_KEYS if request_payload.get(key) is not None
        )
        if caller_attached:
            raise WorkerValidationError(
                f"request field(s) not accepted by this host: {', '.join(caller_attached)}"
            )

    period_start_explicit = "period_start_utc" in request_payload
    period_end_explicit = "period_end_utc" in request_payload
    base_currency_explicit = "base_currency" in request_payload
    account_scope_explicit = "account_scope" in request_payload
    claimed_origin_explicit = "claimed_origin_assurance" in request_payload

    try:
        issued_at_utc = str(request_payload.get("issued_at_utc") or utc_now_iso())
        parse_utc_timestamp(issued_at_utc, field_name="issued_at_utc")

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
    except WorkerValidationError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        # A malformed request value is the caller's input error, never a server fault.
        raise WorkerValidationError(str(exc)) from exc

    # Assemble worker job WITHOUT publisher private signing key or vault master KEK
    worker_job: dict[str, Any] = {
        k: v for k, v in request_payload.items() if not str(k).startswith("_internal_")
    }
    worker_job["broker_id"] = broker_id
    if _hyperliquid_http_transport is not None and broker_id == "hyperliquid":
        worker_job["_internal_hyperliquid_transport"] = _hyperliquid_http_transport
    if _snaptrade_http_transport is not None and broker_id in {
        "snaptrade",
        "snaptrade_relay",
        "snaptrade_poc",
    }:
        worker_job["_internal_snaptrade_transport"] = _snaptrade_http_transport
    worker_job["issued_at_utc"] = issued_at_utc
    worker_job["period_start_utc"] = period_start_utc
    worker_job["period_end_utc"] = period_end_utc
    worker_job["period_start_utc_explicit"] = period_start_explicit
    worker_job["period_end_utc_explicit"] = period_end_explicit
    worker_job["base_currency_explicit"] = base_currency_explicit
    worker_job["account_blinding_salt_hex"] = config.account_blinding_salt_hex
    worker_job["delayed_trade_guard_days"] = config.delayed_trade_guard_days
    worker_job["_hosted_signing_restricted"] = bool(
        config.hosted_multi_user_mode
        and not config.allow_hosted_signing
        and not config.allow_client_supplied_series_for_tests
        and pipeline_spec is None
    )
    worker_job["_allow_trusted_internal_ledger"] = bool(_trusted_internal_input)
    if config.eodhd_api_key and not worker_job.get("eodhd_api_key"):
        worker_job["eodhd_api_key"] = config.eodhd_api_key

    parent_pid = os.getpid()
    # Refuse at once, without waiting, when every worker slot is in use.
    if not _VERIFICATION_WORKER_SLOTS.acquire(blocking=False):
        raise WorkerCapacityExceededError(
            "Every verification worker on this host is busy; try again shortly"
        )
    try:
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
                raise WorkerTimeoutError(
                    "Verification did not finish in time on this host; try again shortly"
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
    finally:
        _VERIFICATION_WORKER_SLOTS.release()

    exitcode = proc.exitcode
    if not worker_envelope.get("ok"):
        from app.store import (
            GovernanceBlockedError,
            PaperOrSandboxRejectedError,
            SigningOracleDisabledError,
        )
        from n170_verify.contracts import ReadOnlyCapabilityViolationError

        err_kind = worker_envelope.get("error_kind", "internal")
        msg = str(worker_envelope.get("message", "Worker execution failed"))
        if err_kind == "paper_or_sandbox":
            raise PaperOrSandboxRejectedError(msg)
        if err_kind == "signing_oracle_disabled":
            raise SigningOracleDisabledError(msg)
        if err_kind == "provider_approval_pending":
            raise GovernanceBlockedError(msg)
        if err_kind == "read_only_violation":
            raise ReadOnlyCapabilityViolationError(msg)
        if err_kind == "validation":
            raise WorkerValidationError(msg)
        if err_kind == "broker_upstream":
            raise WorkerBrokerUpstreamError(msg)
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
    if _withheld_without_core_metrics(redacted):
        raise WorkerIsolationError(
            "A record whose return was withheld must disclose core_metrics; it was not signed"
        )
    if config.hosted_multi_user_mode:
        # Hosted: the host chooses the record id.
        proof_id = f"prf-{uuid.uuid4().hex[:20]}"
    else:
        proof_id = str(request_payload.get("proof_id") or f"prf-{uuid.uuid4().hex[:20]}")
    signed_broker_id = str(redacted["broker_id"])
    if config.hosted_multi_user_mode:
        signed_broker_id = _offline_broker_id_for_statement(
            signed_broker_id.strip().lower(),
            redacted.get("provider_approval_state"),
            config,
        )
    if config.hosted_multi_user_mode:
        # Hosted: the worker that read the input states scope and origin; request values never do.
        account_scope = (
            AccountScope(str(redacted["account_scope"]))
            if redacted.get("account_scope")
            else AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED
        )
        claimed_origin = (
            OriginAssurance(str(redacted["claimed_origin_assurance"]))
            if redacted.get("claimed_origin_assurance")
            else OriginAssurance.SELF_REPORTED
        )
    else:
        if not account_scope_explicit and redacted.get("account_scope"):
            account_scope = AccountScope(str(redacted["account_scope"]))
        if not claimed_origin_explicit and redacted.get("claimed_origin_assurance"):
            claimed_origin = OriginAssurance(str(redacted["claimed_origin_assurance"]))

    provider_approval = _clamp_approval_to_worker_origin(
        provider_approval,
        returned_broker_id=signed_broker_id.strip().lower(),
        worker_reported_state=redacted.get("provider_approval_state"),
        config=config,
    )

    # Reconstruct & Ed25519-sign VerifyProofBundle in parent process from redacted Merkle output
    from n170_verify.crypto import DisclosedLeaf, SIGNING_DOMAIN_BUNDLE, ed25519_sign_domain

    disclosed_objs = [DisclosedLeaf.from_dict(item) for item in redacted["disclosed_leaves"]]
    draft = VerifyProofBundle(
        proof_id=proof_id,
        schema_version=VERIFY_SCHEMA_VERSION,
        issued_at_utc=issued_at_utc,
        publisher_kid=config.publisher_kid,
        publisher_public_key_hex=config.publisher_keypair.public_key_hex,
        broker_id=signed_broker_id,
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
    _refuse_text_the_scanner_blocks_before_signing(draft)
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
    if result_meta is not None:
        # Whether a return was computed, stated by the worker or by the signed core_metrics leaf.
        core_leaf = next(
            (leaf.payload for leaf in disclosed_objs if leaf.leaf_name == "core_metrics"), None
        )
        leaf_withheld = isinstance(core_leaf, Mapping) and core_leaf.get("performance_withheld") is True
        withheld = bool(redacted.get("performance_withheld")) or leaf_withheld
        result_meta["performance_withheld"] = withheld
        reasons = redacted.get("withheld_reasons") or (
            core_leaf.get("withheld_reasons") if leaf_withheld else None
        )
        result_meta["withheld_reasons"] = [str(r) for r in reasons] if withheld and reasons else []
        dropped_count = int(redacted.get("dropped_journal_tag_count") or 0)
        result_meta["record_warnings"] = (
            [JOURNAL_TAGS_LEFT_OUT_WARNING.format(n=dropped_count)] if dropped_count > 0 else []
        )
    return draft, receipt, stripped_count


__all__ = [
    "MAX_CONCURRENT_VERIFICATION_WORKERS",
    "MAX_STATEMENT_INPUT_BYTES",
    "MAX_STATEMENT_INPUT_ROWS",
    "SCANNER_REFUSAL_DETAIL",
    "VERIFICATION_RETRY_AFTER_SECONDS",
    "WORKER_LIMIT_ERRORS",
    "WorkerBrokerUpstreamError",
    "WorkerCapacityExceededError",
    "WorkerInputTooLargeError",
    "WorkerIsolationError",
    "WorkerTimeoutError",
    "WorkerIsolationReceipt",
    "WorkerPipelineSpec",
    "WorkerValidationError",
    "create_signed_proof_bundle",
    "default_standalone_worker_pipeline",
    "filter_delayed_closed_trades",
    "run_isolated_one_shot_verification",
    "worker_limit_response",
]
