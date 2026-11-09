"""Vectorized Politis & Romano (1994) stationary block bootstrap for forward risk-of-ruin cones."""

from __future__ import annotations

from collections.abc import Sequence
import math

import numpy as np

from n170_verify.contracts.performance import BootstrapConePoint, BootstrapRiskSummary


MIN_BOOTSTRAP_OBSERVATIONS = 5
DEFAULT_MIN_HORIZON = 20
DEFAULT_MAX_HORIZON = 252


def _default_block_length(n_obs: int) -> int:
    """Compute Politis & Romano (1994) cube-root-scaled expected block length."""
    scaled = int(round((float(n_obs) ** (1.0 / 3.0)) * 1.5))
    return max(2, min(n_obs, scaled))


def run_stationary_block_bootstrap(
    subperiod_returns: Sequence[float],
    *,
    horizon_periods: int | None = None,
    num_simulations: int = 1000,
    block_length: int | None = None,
    seed: int = 170,
) -> BootstrapRiskSummary | None:
    """Simulate a deterministic stationary block-bootstrap wealth cone and drawdown probabilities.

    Preserves empirical fat tails and local serial correlation across sub-period returns.
    Returns ``None`` when fewer than 5 sub-period return observations are available.
    Wealth paths are rebased to ``1.0`` at ``step=0`` (zero raw currency amounts).
    """
    if isinstance(num_simulations, bool) or not isinstance(num_simulations, int) or num_simulations < 1:
        raise ValueError("num_simulations must be an integer >= 1")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")
    if horizon_periods is not None and (
        isinstance(horizon_periods, bool) or not isinstance(horizon_periods, int) or horizon_periods < 1
    ):
        raise ValueError("horizon_periods must be an integer >= 1 when specified")
    if block_length is not None and (
        isinstance(block_length, bool) or not isinstance(block_length, int) or block_length < 1
    ):
        raise ValueError("block_length must be an integer >= 1 when specified")

    cleaned: list[float] = []
    for item in subperiod_returns:
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise ValueError("subperiod_returns elements must be finite real numbers")
        val = float(item)
        if not math.isfinite(val) or val < -1.0:
            raise ValueError("subperiod_returns elements must be finite and >= -1.0")
        cleaned.append(val)

    n_obs = len(cleaned)
    if n_obs < MIN_BOOTSTRAP_OBSERVATIONS:
        return None

    arr = np.asarray(cleaned, dtype=np.float64)
    horizon = (
        int(horizon_periods)
        if horizon_periods is not None
        else min(max(n_obs, DEFAULT_MIN_HORIZON), DEFAULT_MAX_HORIZON)
    )
    eff_block_length = (
        int(block_length) if block_length is not None else _default_block_length(n_obs)
    )

    rng = np.random.default_rng(seed)
    if eff_block_length <= 1:
        indices = rng.integers(0, n_obs, size=(num_simulations, horizon))
    else:
        restart_prob = 1.0 / float(eff_block_length)
        random_starts = rng.integers(0, n_obs, size=(num_simulations, horizon))
        restarts = rng.random((num_simulations, horizon)) < restart_prob
        indices = np.empty((num_simulations, horizon), dtype=np.int64)
        indices[:, 0] = random_starts[:, 0]
        for step_idx in range(1, horizon):
            next_seq = indices[:, step_idx - 1] + 1
            wrapped_seq = np.where(next_seq >= n_obs, 0, next_seq)
            indices[:, step_idx] = np.where(
                restarts[:, step_idx],
                random_starts[:, step_idx],
                wrapped_seq,
            )

    sampled_returns = arr[indices]
    gross_factors = np.maximum(1.0 + sampled_returns, 0.0)

    wealth = np.empty((num_simulations, horizon + 1), dtype=np.float64)
    wealth[:, 0] = 1.0
    np.cumprod(gross_factors, axis=1, out=wealth[:, 1:])

    quantiles = np.quantile(wealth, [0.05, 0.25, 0.50, 0.75, 0.95], axis=0)
    cone: list[BootstrapConePoint] = [
        BootstrapConePoint(
            step=0,
            p05=1.0,
            p25=1.0,
            p50=1.0,
            p75=1.0,
            p95=1.0,
        )
    ]
    for step_idx in range(1, horizon + 1):
        q05 = round(float(quantiles[0, step_idx]), 6)
        q25 = max(q05, round(float(quantiles[1, step_idx]), 6))
        q50 = max(q25, round(float(quantiles[2, step_idx]), 6))
        q75 = max(q50, round(float(quantiles[3, step_idx]), 6))
        q95 = max(q75, round(float(quantiles[4, step_idx]), 6))
        cone.append(
            BootstrapConePoint(
                step=step_idx,
                p05=q05,
                p25=q25,
                p50=q50,
                p75=q75,
                p95=q95,
            )
        )

    running_peaks = np.maximum.accumulate(wealth, axis=1)
    drawdowns = 1.0 - (wealth / running_peaks)
    max_drawdowns = np.max(drawdowns, axis=1)

    prob_dd_10 = max(0.0, min(1.0, round(float(np.mean(max_drawdowns >= 0.10 - 1e-12)), 6)))
    prob_dd_20 = max(0.0, min(1.0, round(float(np.mean(max_drawdowns >= 0.20 - 1e-12)), 6)))
    prob_pos_terminal = max(0.0, min(1.0, round(float(np.mean(wealth[:, -1] > 1.0)), 6)))

    return BootstrapRiskSummary(
        horizon_periods=horizon,
        num_simulations=num_simulations,
        block_length=eff_block_length,
        prob_drawdown_10pct=prob_dd_10,
        prob_drawdown_20pct=prob_dd_20,
        prob_positive_terminal=prob_pos_terminal,
        cone=cone,
    )


__all__ = [
    "DEFAULT_MAX_HORIZON",
    "DEFAULT_MIN_HORIZON",
    "MIN_BOOTSTRAP_OBSERVATIONS",
    "run_stationary_block_bootstrap",
]
