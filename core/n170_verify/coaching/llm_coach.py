"""Self-hosted small-LLM trader coach with <2,500-token PII/dollar-free input and claim-safety filter."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
import json
import os
import re
from typing import Any
import urllib.request

from n170_verify.catalysts.eodhd_events import redact_url_secrets
from n170_verify.contracts import BehaviouralCoachingMetrics, CostAndDragBreakdown


DEFAULT_LLM_MODEL_ID: str = "qwen2.5:7b-instruct"
DEFAULT_LLM_TEMPERATURE: float = 0.0
DEFAULT_LLM_TIMEOUT_SECONDS: float = 12.0
MAX_SUMMARY_PROMPT_TOKENS: int = 2_500

FORBIDDEN_CLAIM_SUBSTRINGS: tuple[str, ...] = (
    "insider",
    "mnpi",
    "material non-public",
    "material nonpublic",
    "fraud",
    "de" + "fraud",
    "manipulat",
    "backdat",
)

_DOLLAR_AMOUNT_RE = re.compile(r"(?:\$|USD\s*|EUR\s*|GBP\s*)\d[\d,]*(?:\.\d+)?", re.IGNORECASE)
_CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE | re.DOTALL)

SYSTEM_PROMPT: str = (
    "You are an institutional execution and trading coach. Summarize trading style and provide "
    "2 to 4 constructive, factual coaching takeaways strictly from the dimensionless basis-point "
    "and ratio metrics provided. Respond ONLY with valid JSON matching "
    '{"style_summary": "...", "coaching_takeaways": ["...", "..."]}. '
    "Never speculate on regulatory violations, non-public information, or unverified motives, "
    "and never invent currency amounts."
)


@dataclass(slots=True)
class CoachingNarrativeResult:
    """Validated coaching narrative output with provenance and safety-fallback telemetry."""

    style_summary: str
    coaching_takeaways: list[str] = field(default_factory=list)
    llm_narrative_used: bool = False
    llm_model_id: str | None = None
    safety_filter_triggered: bool = False
    fallback_reason: str | None = None


def estimate_prompt_tokens(text: str) -> int:
    """Conservative BPE token-count upper bound (~4 chars/token vs whitespace words)."""
    if not text:
        return 0
    char_est = (len(text) + 3) // 4
    word_est = int(len(text.split()) * 1.35)
    return max(char_est, word_est)


def contains_forbidden_claim(text: str) -> bool:
    """Return True iff ``text`` contains any prohibited legal/accusatory claim substring."""
    folded = text.lower()
    return any(term in folded for term in FORBIDDEN_CLAIM_SUBSTRINGS)


def contains_currency_amount(text: str) -> bool:
    """Return True iff ``text`` contains an explicit dollar/currency notional figure."""
    return bool(_DOLLAR_AMOUNT_RE.search(text))


def is_narrative_claim_safe(
    style_summary: str,
    coaching_takeaways: Sequence[str],
) -> bool:
    """Validate that generated coaching narrative is non-empty, dollar-free, and claim-safe."""
    if not isinstance(style_summary, str) or not style_summary.strip():
        return False
    if contains_forbidden_claim(style_summary) or contains_currency_amount(style_summary):
        return False
    if not isinstance(coaching_takeaways, Sequence) or isinstance(coaching_takeaways, (str, bytes)):
        return False
    cleaned_takeaways = [t for t in coaching_takeaways if isinstance(t, str) and t.strip()]
    if not cleaned_takeaways:
        return False
    for item in cleaned_takeaways:
        if contains_forbidden_claim(item) or contains_currency_amount(item):
            return False
    return True


def build_redacted_summary_payload(
    *,
    cost_drag: CostAndDragBreakdown,
    behaviour: BehaviouralCoachingMetrics,
    catalyst_regime_win_rate: float | None = None,
    quiet_regime_win_rate: float | None = None,
    event_window_share_pct: float = 0.0,
    asset_class_shares_pct: Mapping[str, float] | None = None,
) -> dict[str, Any]:
    """Construct a strictly PII-free and dollar-free dimensionless metrics dictionary (<2,500 tokens)."""
    payload: dict[str, Any] = {
        "cost_drag_bps": {
            "commission_and_fee_bps": round(cost_drag.commission_and_fee_drag_bps, 2),
            "margin_and_funding_bps": round(cost_drag.margin_and_funding_drag_bps, 2),
            "fx_conversion_bps": round(cost_drag.fx_conversion_drag_bps, 2),
            "withholding_tax_bps": round(cost_drag.withholding_tax_drag_bps, 2),
            "total_friction_bps": round(cost_drag.total_friction_drag_bps, 2),
            "annualized_total_bps": round(cost_drag.annualized_total_drag_bps, 2),
        },
        "behaviour": {
            "sample_eligible": behaviour.sample_eligible,
            "observed_trades": behaviour.observed_trades,
            "observed_days": behaviour.observed_days,
            "holding_horizon_label": behaviour.holding_horizon_label,
            "median_holding_hours": (
                round(behaviour.median_holding_hours, 2)
                if behaviour.median_holding_hours is not None
                else None
            ),
            "win_rate": round(behaviour.win_rate, 4) if behaviour.win_rate is not None else None,
            "profit_factor": (
                round(behaviour.profit_factor, 3) if behaviour.profit_factor is not None else None
            ),
            "winner_vs_loser_hold_ratio": (
                round(behaviour.winner_vs_loser_hold_ratio, 3)
                if behaviour.winner_vs_loser_hold_ratio is not None
                else None
            ),
            "odean_pgr_plr_spread": (
                round(behaviour.odean_pgr_plr_spread, 4)
                if behaviour.odean_pgr_plr_spread is not None
                else None
            ),
            "post_drawdown_sizing_discipline_ratio": (
                round(behaviour.post_drawdown_sizing_discipline_atr, 3)
                if behaviour.post_drawdown_sizing_discipline_atr is not None
                else None
            ),
            "atr_normalized": behaviour.atr_normalized,
            "return_concentration_top5_pct": (
                round(behaviour.return_concentration_top5_pct, 2)
                if behaviour.return_concentration_top5_pct is not None
                else None
            ),
        },
        "catalyst_context": {
            "event_window_share_pct": round(event_window_share_pct, 2),
            "catalyst_regime_win_rate": (
                round(catalyst_regime_win_rate, 4) if catalyst_regime_win_rate is not None else None
            ),
            "quiet_regime_win_rate": (
                round(quiet_regime_win_rate, 4) if quiet_regime_win_rate is not None else None
            ),
        },
    }
    if asset_class_shares_pct:
        payload["asset_class_mix_pct"] = {
            str(k): round(float(v), 2) for k, v in sorted(asset_class_shares_pct.items())
        }
    return payload


def build_deterministic_coaching_narrative(
    *,
    cost_drag: CostAndDragBreakdown,
    behaviour: BehaviouralCoachingMetrics,
    catalyst_regime_win_rate: float | None = None,
    quiet_regime_win_rate: float | None = None,
    event_window_share_pct: float = 0.0,
) -> CoachingNarrativeResult:
    """Generate a 100% deterministic, offline, claim-safe coaching summary and takeaways."""
    if not behaviour.sample_eligible:
        style_summary = (
            f"Developing activity profile ({behaviour.observed_trades} closed round-trips over "
            f"{behaviour.observed_days} days; below the {behaviour.min_trades_gate}-trade sample gate) "
            f"with {cost_drag.total_friction_drag_bps:.1f} bps cumulative friction drag."
        )
    else:
        horizon_text = behaviour.holding_horizon_label.replace("_", " ")
        wr_pct = (behaviour.win_rate or 0.0) * 100.0
        sdi = behaviour.post_drawdown_sizing_discipline_atr
        if sdi is not None:
            sizing_phrase = (
                "disciplined post-drawdown risk sizing"
                if sdi <= 1.15
                else "elevated post-drawdown risk sizing"
            )
        else:
            sizing_phrase = "steady risk deployment"
        style_summary = (
            f" Institutional {horizon_text} profile ({wr_pct:.1f}% win rate across "
            f"{behaviour.observed_trades} round-trips) exhibiting {sizing_phrase} and "
            f"{cost_drag.total_friction_drag_bps:.1f} bps total friction drag."
        ).strip()

    takeaways = list(behaviour.actionable_improvements)

    if (
        catalyst_regime_win_rate is not None
        and quiet_regime_win_rate is not None
        and abs(catalyst_regime_win_rate - quiet_regime_win_rate) >= 0.10
    ):
        if catalyst_regime_win_rate > quiet_regime_win_rate:
            takeaways.append(
                f"Hit-rate during public catalyst windows ({catalyst_regime_win_rate * 100.0:.1f}%) "
                f"exceeded quiet-regime execution ({quiet_regime_win_rate * 100.0:.1f}%); "
                "track liquidity and slippage budgets separately across regimes."
            )
        else:
            takeaways.append(
                f"Quiet-regime execution ({quiet_regime_win_rate * 100.0:.1f}% win rate) outperformed "
                f"public catalyst windows ({catalyst_regime_win_rate * 100.0:.1f}%); consider tighter "
                "risk budgets around scheduled releases."
            )
    elif event_window_share_pct >= 50.0:
        takeaways.append(
            f"{event_window_share_pct:.1f}% of executions occurred near public catalyst windows; "
            "pair limit-order discipline with wider spread awareness during event volatility."
        )

    if not takeaways:
        takeaways.append(
            "Maintain consistent pre-trade risk budgeting and review quarterly execution friction across venues."
        )

    return CoachingNarrativeResult(
        style_summary=style_summary,
        coaching_takeaways=takeaways[:5],
        llm_narrative_used=False,
        llm_model_id=None,
    )


def _resolve_completions_url(base_url: str) -> str:
    trimmed = base_url.strip().rstrip("/")
    if trimmed.endswith("/chat/completions"):
        return trimmed
    if trimmed.endswith("/v1"):
        return f"{trimmed}/chat/completions"
    return f"{trimmed}/v1/chat/completions"


def _parse_llm_json_content(raw_content: str) -> tuple[str, list[str]] | None:
    cleaned = _CODE_FENCE_RE.sub("", raw_content.strip()).strip()
    if not cleaned:
        return None
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start == -1 or end <= start:
            return None
        try:
            parsed = json.loads(cleaned[start : end + 1])
        except json.JSONDecodeError:
            return None

    if not isinstance(parsed, Mapping):
        return None
    summary = parsed.get("style_summary")
    raw_takeaways = parsed.get("coaching_takeaways")
    if not isinstance(summary, str) or not isinstance(raw_takeaways, list):
        return None
    takeaways = [str(item).strip() for item in raw_takeaways if isinstance(item, str) and item.strip()]
    return summary.strip(), takeaways


class SmallLlmCoachClient:
    """OpenAI-compatible local small-LLM client (Ollama/vLLM, temperature=0.0, 12s timeout)."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        model_id: str | None = None,
        api_key: str | None = None,
        timeout_seconds: float = DEFAULT_LLM_TIMEOUT_SECONDS,
        max_prompt_tokens: int = MAX_SUMMARY_PROMPT_TOKENS,
        transport: Callable[[str, Mapping[str, Any], Mapping[str, str], float], Any] | Any | None = None,
        prefer_httpx: bool = False,
    ) -> None:
        resolved_base = (
            base_url
            if base_url is not None
            else os.environ.get("N170_VERIFY_LLM_BASE_URL", "")
        )
        resolved_model = (
            model_id
            if model_id is not None
            else os.environ.get("N170_VERIFY_LLM_MODEL", DEFAULT_LLM_MODEL_ID)
        )
        resolved_key = (
            api_key
            if api_key is not None
            else os.environ.get("N170_VERIFY_LLM_API_KEY", "")
        )
        self.base_url: str = resolved_base.strip()
        self.model_id: str = resolved_model.strip() or DEFAULT_LLM_MODEL_ID
        self._api_key: str = resolved_key.strip()
        self.timeout_seconds: float = float(timeout_seconds)
        self.max_prompt_tokens: int = min(int(max_prompt_tokens), MAX_SUMMARY_PROMPT_TOKENS)
        self._transport = transport
        self._prefer_httpx = prefer_httpx

    @property
    def is_configured(self) -> bool:
        return bool(self.base_url or self._transport is not None)

    def _post_completion(self, url: str, request_body: dict[str, Any]) -> Any:
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        if self._transport is not None:
            if hasattr(self._transport, "post") and callable(self._transport.post):
                resp = self._transport.post(
                    url,
                    json=request_body,
                    headers=headers,
                    timeout=self.timeout_seconds,
                )
                if hasattr(resp, "raise_for_status"):
                    resp.raise_for_status()
                if hasattr(resp, "json") and callable(resp.json):
                    return resp.json()
                raw_payload = getattr(resp, "text", getattr(resp, "content", resp))
            elif callable(self._transport):
                raw_payload = self._transport(url, request_body, headers, self.timeout_seconds)
            else:
                raise TypeError("Unsupported LLM HTTP transport object")
        elif self._prefer_httpx:
            try:
                import httpx  # type: ignore[import-not-found]
            except ImportError:
                encoded = json.dumps(request_body).encode("utf-8")
                req = urllib.request.Request(url, data=encoded, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                    raw_payload = resp.read()
            else:
                resp = httpx.post(
                    url,
                    json=request_body,
                    headers=headers,
                    timeout=self.timeout_seconds,
                )
                resp.raise_for_status()
                return resp.json()
        else:
            encoded = json.dumps(request_body).encode("utf-8")
            req = urllib.request.Request(url, data=encoded, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                raw_payload = resp.read()

        if isinstance(raw_payload, Mapping):
            return raw_payload
        if isinstance(raw_payload, bytes):
            return json.loads(raw_payload.decode("utf-8"))
        if isinstance(raw_payload, str):
            return json.loads(raw_payload)
        raise ValueError(f"Unexpected LLM response type: {type(raw_payload).__name__}")

    def generate_coaching_narrative(
        self,
        *,
        cost_drag: CostAndDragBreakdown,
        behaviour: BehaviouralCoachingMetrics,
        catalyst_regime_win_rate: float | None = None,
        quiet_regime_win_rate: float | None = None,
        event_window_share_pct: float = 0.0,
        asset_class_shares_pct: Mapping[str, float] | None = None,
    ) -> CoachingNarrativeResult:
        """Attempt claim-safe small-LLM synthesis with 100% deterministic offline/safety fallback."""
        deterministic = build_deterministic_coaching_narrative(
            cost_drag=cost_drag,
            behaviour=behaviour,
            catalyst_regime_win_rate=catalyst_regime_win_rate,
            quiet_regime_win_rate=quiet_regime_win_rate,
            event_window_share_pct=event_window_share_pct,
        )
        if not self.is_configured:
            deterministic.fallback_reason = "llm_unconfigured"
            return deterministic

        summary_payload = build_redacted_summary_payload(
            cost_drag=cost_drag,
            behaviour=behaviour,
            catalyst_regime_win_rate=catalyst_regime_win_rate,
            quiet_regime_win_rate=quiet_regime_win_rate,
            event_window_share_pct=event_window_share_pct,
            asset_class_shares_pct=asset_class_shares_pct,
        )
        user_prompt = json.dumps(summary_payload, separators=(",", ":"), sort_keys=True)
        combined_tokens = estimate_prompt_tokens(SYSTEM_PROMPT) + estimate_prompt_tokens(user_prompt)
        if combined_tokens >= self.max_prompt_tokens:
            deterministic.fallback_reason = "prompt_token_budget_exceeded"
            return deterministic
        if contains_currency_amount(user_prompt):
            deterministic.fallback_reason = "prompt_redaction_guard_triggered"
            return deterministic

        endpoint_url = _resolve_completions_url(self.base_url or "http://127.0.0.1:11434/v1")
        request_body: dict[str, Any] = {
            "model": self.model_id,
            "temperature": DEFAULT_LLM_TEMPERATURE,
            "max_tokens": 450,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        }

        try:
            response_json = self._post_completion(endpoint_url, request_body)
        except Exception as exc:
            safe_err = redact_url_secrets(str(exc), extra_secrets=(self._api_key,))
            deterministic.fallback_reason = f"llm_transport_error:{type(exc).__name__}:{safe_err[:80]}"
            return deterministic

        if not isinstance(response_json, Mapping):
            deterministic.fallback_reason = "invalid_response_envelope"
            return deterministic

        choices = response_json.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], Mapping):
            deterministic.fallback_reason = "missing_choices"
            return deterministic

        message = choices[0].get("message")
        content = message.get("content") if isinstance(message, Mapping) else None
        if not isinstance(content, str):
            deterministic.fallback_reason = "missing_message_content"
            return deterministic

        parsed_pair = _parse_llm_json_content(content)
        if parsed_pair is None:
            if contains_forbidden_claim(content):
                deterministic.safety_filter_triggered = True
                deterministic.fallback_reason = "claim_safety_filter_rejected"
            else:
                deterministic.fallback_reason = "invalid_json_content"
            return deterministic

        llm_summary, llm_takeaways = parsed_pair
        if not is_narrative_claim_safe(llm_summary, llm_takeaways):
            deterministic.safety_filter_triggered = True
            deterministic.fallback_reason = "claim_safety_filter_rejected"
            return deterministic

        return CoachingNarrativeResult(
            style_summary=llm_summary,
            coaching_takeaways=llm_takeaways[:5],
            llm_narrative_used=True,
            llm_model_id=self.model_id,
            safety_filter_triggered=False,
            fallback_reason=None,
        )


__all__ = [
    "CoachingNarrativeResult",
    "DEFAULT_LLM_MODEL_ID",
    "DEFAULT_LLM_TEMPERATURE",
    "DEFAULT_LLM_TIMEOUT_SECONDS",
    "FORBIDDEN_CLAIM_SUBSTRINGS",
    "MAX_SUMMARY_PROMPT_TOKENS",
    "SYSTEM_PROMPT",
    "SmallLlmCoachClient",
    "build_deterministic_coaching_narrative",
    "build_redacted_summary_payload",
    "contains_currency_amount",
    "contains_forbidden_claim",
    "estimate_prompt_tokens",
    "is_narrative_claim_safe",
]
