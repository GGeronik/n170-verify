"""Non-normal Probabilistic Sharpe Ratio (PSR), MinTRL, and Getmansky-Lo-Makarov (2004) MA(2) unsmoothing.

Design invariants:
- Sample-size gate: PSR and MinTRL are computed ONLY when ``T >= 30`` return observations exist.
- Single-account multiple-testing Deflated Sharpe adjustment is intentionally NEVER computed because the number
  of unobserved selection trials ``N`` across unenumerated accounts/strategies is unobservable.
- Uses stdlib ``statistics.NormalDist`` + ``numpy`` (with optional ``scipy.optimize`` acceleration
  when installed) so all econometrics run deterministically offline.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
import math
from statistics import NormalDist

import numpy as np

from n170_verify.contracts.performance import ClaimPlausibilityAnalysis


MIN_PSR_OBSERVATIONS = 30
GLM_MIN_OBSERVATIONS = 6
GLM_XI_THRESHOLD = 0.80
GLM_RHO1_THRESHOLD = 0.20

CLAIM_SUFFICIENCY_NOISE_DOMINATED = "INSUFFICIENT_TRACK_RECORD_NOISE_DOMINATED"
CLAIM_SUFFICIENCY_BORDERLINE = "BORDERLINE_SAMPLE"
CLAIM_SUFFICIENCY_SUFFICIENT_IF_UNSMOOTHED = "STATISTICALLY_SUFFICIENT_IF_UNSMOOTHED"

_STD_NORMAL = NormalDist(0.0, 1.0)


@dataclass(frozen=True, slots=True)
class GlmUnsmoothingResult:
    """Getmansky, Lo & Makarov (2004) MA(2) smoothing profile."""

    theta_0: float
    theta_1: float
    theta_2: float
    smoothing_index_xi: float
    lag1_autocorrelation: float
    lag2_autocorrelation: float
    unsmoothed_period_volatility: float
    unsmoothed_annualized_volatility: float
    unsmoothed_period_sharpe: float | None
    unsmoothed_annualized_sharpe: float | None
    requires_unsmoothed_psr: bool


@dataclass(frozen=True, slots=True)
class EconometricBundle:
    """Combined higher-moment, GLM MA(2), PSR, and MinTRL diagnostics."""

    observation_count: int
    psr_sample_eligible: bool
    skewness: float | None
    excess_kurtosis: float | None
    lag1_autocorrelation: float | None
    smoothing_index_xi: float | None
    unsmoothed_volatility: float | None
    unsmoothed_sharpe_ratio: float | None
    probabilistic_sharpe_ratio: float | None
    psr_glm_unsmoothed: float | None
    min_track_record_length_periods: float | None
    glm_profile: GlmUnsmoothingResult | None
    warnings: tuple[str, ...]


def compute_higher_moments(returns: Sequence[float]) -> tuple[float | None, float | None]:
    """Compute standardized sample skewness (gamma_3) and excess kurtosis (gamma_4 - 3).

    Central moments use consistent second-moment standardization so Pearson's inequality
    (``gamma_4 >= gamma_3^2 + 1``) holds identically for every non-degenerate return series.
    """
    n = len(returns)
    if n < 3:
        return None, None

    arr = np.asarray(returns, dtype=np.float64)
    if not np.all(np.isfinite(arr)):
        return None, None

    centered = arr - float(np.mean(arr))
    m2 = float(np.mean(centered * centered))
    if m2 <= 1e-24:
        return None, None

    m3 = float(np.mean(centered**3))
    skew = m3 / (m2**1.5)
    if not math.isfinite(skew):
        skew = None

    if n < 4:
        return skew, None

    m4 = float(np.mean(centered**4))
    excess_kurt = (m4 / (m2 * m2)) - 3.0
    if not math.isfinite(excess_kurt):
        excess_kurt = None

    return skew, excess_kurt


def compute_sample_autocorrelation(returns: Sequence[float], lag: int = 1) -> float | None:
    """Compute Box-Jenkins sample autocorrelation at ``lag`` for ``len(returns) > lag + 1``."""
    if lag < 1 or len(returns) <= lag + 1:
        return None
    arr = np.asarray(returns, dtype=np.float64)
    if not np.all(np.isfinite(arr)):
        return None
    centered = arr - float(np.mean(arr))
    denom = float(np.dot(centered, centered))
    if denom <= 1e-24:
        return None
    num = float(np.dot(centered[lag:], centered[:-lag]))
    rho = num / denom
    return max(-1.0, min(1.0, rho))


def _psr_variance_factor(sr_hat: float, skewness: float, excess_kurtosis: float) -> float:
    """Denominator variance scaling ``1 - gamma_3 * SR + ((gamma_4 - 1) / 4) * SR^2``."""
    raw = 1.0 - skewness * sr_hat + ((excess_kurtosis + 2.0) / 4.0) * (sr_hat * sr_hat)
    return max(raw, 1e-12)


def compute_probabilistic_sharpe_ratio(
    sr_hat: float,
    benchmark_sr: float = 0.0,
    *,
    observation_count: int,
    skewness: float = 0.0,
    excess_kurtosis: float = 0.0,
) -> float | None:
    """Compute Bailey & Lopez de Prado (2012) non-normal Probabilistic Sharpe Ratio (PSR).

    Both ``sr_hat`` and ``benchmark_sr`` are expressed in per-observation-period Sharpe units.
    Returns ``None`` whenever ``observation_count < 30`` (strict sample-size gate).
    """
    if observation_count < MIN_PSR_OBSERVATIONS:
        return None
    if not (
        math.isfinite(sr_hat)
        and math.isfinite(benchmark_sr)
        and math.isfinite(skewness)
        and math.isfinite(excess_kurtosis)
    ):
        return None

    var_factor = _psr_variance_factor(sr_hat, skewness, excess_kurtosis)
    z_score = ((sr_hat - benchmark_sr) * math.sqrt(observation_count - 1.0)) / math.sqrt(var_factor)
    prob = _STD_NORMAL.cdf(z_score)
    return max(0.0, min(1.0, float(prob)))


def compute_min_track_record_length(
    sr_hat: float,
    benchmark_sr: float = 0.0,
    *,
    observation_count: int,
    skewness: float = 0.0,
    excess_kurtosis: float = 0.0,
    confidence_level: float = 0.95,
) -> float | None:
    """Compute Bailey & Lopez de Prado (2012) Minimum Track Record Length (MinTRL) in periods.

    Gated on ``observation_count >= 30`` and ``sr_hat > benchmark_sr``.
    """
    if observation_count < MIN_PSR_OBSERVATIONS:
        return None
    if not (0.5 < confidence_level < 1.0):
        raise ValueError("confidence_level must lie strictly in (0.5, 1.0)")
    if not (math.isfinite(sr_hat) and math.isfinite(benchmark_sr)) or sr_hat <= benchmark_sr:
        return None

    var_factor = _psr_variance_factor(sr_hat, skewness, excess_kurtosis)
    z_alpha = _STD_NORMAL.inv_cdf(confidence_level)
    diff = sr_hat - benchmark_sr
    min_trl = 1.0 + var_factor * ((z_alpha / diff) ** 2)
    return float(min_trl) if math.isfinite(min_trl) else None


def _is_invertible_ma2(c1: float, c2: float, *, margin: float = 1e-4) -> bool:
    """Return True iff ``1 + c1*L + c2*L^2`` is invertible with non-negative GLM smoothing weights."""
    return (
        (c1 >= 0.0)
        and (c2 >= 0.0)
        and (1.0 + c1 + c2 > margin)
        and (1.0 - c1 + c2 > margin)
        and (1.0 - c2 > margin)
    )


def _ma2_profile_nll_vectorized(
    centered: np.ndarray,
    c1_vec: np.ndarray,
    c2_vec: np.ndarray,
) -> np.ndarray:
    """Vectorized Brockwell-Davis Innovations Algorithm Gaussian profile NLL across M candidates."""
    n = centered.shape[0]
    m = c1_vec.shape[0]
    g0 = 1.0 + c1_vec * c1_vec + c2_vec * c2_vec
    g1 = c1_vec * (1.0 + c2_vec)
    g2 = c2_vec

    v_prev2 = np.zeros(m, dtype=np.float64)
    v_prev1 = g0.copy()
    th_prev1 = np.zeros(m, dtype=np.float64)

    res_prev2 = np.zeros(m, dtype=np.float64)
    res_prev1 = np.full(m, centered[0], dtype=np.float64)

    sum_sq_scaled = (res_prev1 * res_prev1) / v_prev1
    sum_log_v = np.log(v_prev1)

    if n >= 2:
        th11 = g1 / v_prev1
        v1 = np.maximum(g0 - th11 * th11 * v_prev1, 1e-12)
        xhat1 = th11 * res_prev1
        res1 = centered[1] - xhat1

        sum_sq_scaled = sum_sq_scaled + (res1 * res1) / v1
        sum_log_v = sum_log_v + np.log(v1)

        v_prev2 = v_prev1
        v_prev1 = v1
        th_prev1 = th11
        res_prev2 = res_prev1
        res_prev1 = res1

    for t in range(2, n):
        th_t2 = g2 / v_prev2
        th_t1 = (g1 - th_t2 * th_prev1 * v_prev2) / v_prev1
        vt = np.maximum(g0 - th_t1 * th_t1 * v_prev1 - th_t2 * th_t2 * v_prev2, 1e-12)
        xhat_t = th_t1 * res_prev1 + th_t2 * res_prev2
        res_t = centered[t] - xhat_t

        sum_sq_scaled = sum_sq_scaled + (res_t * res_t) / vt
        sum_log_v = sum_log_v + np.log(vt)

        v_prev2 = v_prev1
        v_prev1 = vt
        th_prev1 = th_t1
        res_prev2 = res_prev1
        res_prev1 = res_t

    sigma2_hat = np.maximum(sum_sq_scaled / float(n), 1e-30)
    return float(n) * np.log(sigma2_hat) + sum_log_v


def _ma2_profile_nll_scalar(centered: np.ndarray, c1: float, c2: float) -> float:
    if not _is_invertible_ma2(c1, c2):
        return 1e18
    arr_c1 = np.array([c1], dtype=np.float64)
    arr_c2 = np.array([c2], dtype=np.float64)
    val = float(_ma2_profile_nll_vectorized(centered, arr_c1, arr_c2)[0])
    return val if math.isfinite(val) else 1e18


def _nelder_mead_2d(
    centered: np.ndarray,
    init_c1: float,
    init_c2: float,
    *,
    max_iter: int = 80,
) -> tuple[float, float]:
    """Compact 2D Nelder-Mead simplex refinement within the invertible MA(2) triangle."""
    step = 0.04
    simplex = [
        (init_c1, init_c2),
        (init_c1 + step if _is_invertible_ma2(init_c1 + step, init_c2) else init_c1 - step, init_c2),
        (init_c1, init_c2 + step if _is_invertible_ma2(init_c1, init_c2 + step) else init_c2 - step),
    ]
    fvals = [_ma2_profile_nll_scalar(centered, p[0], p[1]) for p in simplex]

    for _ in range(max_iter):
        order = sorted(range(3), key=lambda idx: fvals[idx])
        simplex = [simplex[i] for i in order]
        fvals = [fvals[i] for i in order]

        if abs(fvals[2] - fvals[0]) < 1e-9 and (
            math.hypot(simplex[2][0] - simplex[0][0], simplex[2][1] - simplex[0][1]) < 1e-6
        ):
            break

        mx = 0.5 * (simplex[0][0] + simplex[1][0])
        my = 0.5 * (simplex[0][1] + simplex[1][1])

        rx = mx + (mx - simplex[2][0])
        ry = my + (my - simplex[2][1])
        fr = _ma2_profile_nll_scalar(centered, rx, ry)

        if fvals[0] <= fr < fvals[1]:
            simplex[2] = (rx, ry)
            fvals[2] = fr
            continue

        if fr < fvals[0]:
            ex = mx + 2.0 * (rx - mx)
            ey = my + 2.0 * (ry - my)
            fe = _ma2_profile_nll_scalar(centered, ex, ey)
            if fe < fr:
                simplex[2] = (ex, ey)
                fvals[2] = fe
            else:
                simplex[2] = (rx, ry)
                fvals[2] = fr
            continue

        cx = mx + 0.5 * (simplex[2][0] - mx)
        cy = my + 0.5 * (simplex[2][1] - my)
        fc = _ma2_profile_nll_scalar(centered, cx, cy)
        if fc < fvals[2]:
            simplex[2] = (cx, cy)
            fvals[2] = fc
            continue

        for idx in (1, 2):
            sx = 0.5 * (simplex[0][0] + simplex[idx][0])
            sy = 0.5 * (simplex[0][1] + simplex[idx][1])
            simplex[idx] = (sx, sy)
            fvals[idx] = _ma2_profile_nll_scalar(centered, sx, sy)

    best_idx = min(range(3), key=lambda idx: fvals[idx])
    return simplex[best_idx]


def estimate_glm_ma2(
    returns: Sequence[float],
    *,
    periods_per_year: float = 252.0,
    annual_risk_free_rate: float = 0.0,
) -> GlmUnsmoothingResult | None:
    """Estimate Getmansky, Lo & Makarov (2004) MA(2) return smoothing model via Gaussian MLE.

    Estimates ``(theta_0, theta_1, theta_2)`` satisfying ``theta_0 + theta_1 + theta_2 = 1``,
    smoothing index ``xi = theta_0^2 + theta_1^2 + theta_2^2``, unsmoothed volatility
    ``sigma_obs / sqrt(xi)``, and unsmoothed Sharpe ratio.
    """
    n = len(returns)
    if n < GLM_MIN_OBSERVATIONS or periods_per_year <= 0.0:
        return None

    arr = np.asarray(returns, dtype=np.float64)
    if not np.all(np.isfinite(arr)):
        return None

    mean_r = float(np.mean(arr))
    centered = arr - mean_r
    sample_var = float(np.dot(centered, centered)) / float(n - 1)
    if sample_var <= 1e-24:
        return None
    obs_period_std = math.sqrt(sample_var)

    rho1 = compute_sample_autocorrelation(returns, lag=1)
    rho2 = compute_sample_autocorrelation(returns, lag=2)
    if rho1 is None or rho2 is None:
        return None

    # Stage 1: Vectorized coarse grid over the non-negative invertible GLM MA(2) region.
    grid_vals = np.linspace(0.0, 1.92, 33, dtype=np.float64)
    c2_grid_vals = np.linspace(0.0, 0.96, 25, dtype=np.float64)
    cand_c1: list[float] = [0.0]
    cand_c2: list[float] = [0.0]
    for g1 in grid_vals:
        for g2 in c2_grid_vals:
            if _is_invertible_ma2(float(g1), float(g2), margin=1e-3):
                cand_c1.append(float(g1))
                cand_c2.append(float(g2))

    c1_arr = np.asarray(cand_c1, dtype=np.float64)
    c2_arr = np.asarray(cand_c2, dtype=np.float64)
    nlls = _ma2_profile_nll_vectorized(centered, c1_arr, c2_arr)
    best_grid_idx = int(np.argmin(nlls))
    start_c1 = float(c1_arr[best_grid_idx])
    start_c2 = float(c2_arr[best_grid_idx])

    # Stage 2: Polish via scipy.optimize.minimize when available, else stdlib/numpy Nelder-Mead.
    opt_c1, opt_c2 = start_c1, start_c2
    try:
        from scipy.optimize import minimize  # type: ignore[import-not-found]

        res = minimize(
            lambda pair: _ma2_profile_nll_scalar(centered, float(pair[0]), float(pair[1])),
            x0=np.array([start_c1, start_c2], dtype=np.float64),
            method="Nelder-Mead",
            options={"maxiter": 120, "xatol": 1e-6, "fatol": 1e-8},
        )
        if res.success and _is_invertible_ma2(float(res.x[0]), float(res.x[1])):
            opt_c1, opt_c2 = float(res.x[0]), float(res.x[1])
        else:
            opt_c1, opt_c2 = _nelder_mead_2d(centered, start_c1, start_c2)
    except ImportError:
        opt_c1, opt_c2 = _nelder_mead_2d(centered, start_c1, start_c2)

    denom = 1.0 + opt_c1 + opt_c2
    theta_0 = 1.0 / denom
    theta_1 = opt_c1 / denom
    theta_2 = opt_c2 / denom
    xi = theta_0 * theta_0 + theta_1 * theta_1 + theta_2 * theta_2
    xi = max(xi, 1e-9)

    unsmoothed_period_std = obs_period_std / math.sqrt(xi)
    unsmoothed_ann_vol = unsmoothed_period_std * math.sqrt(periods_per_year)

    rf_period = (1.0 + annual_risk_free_rate) ** (1.0 / periods_per_year) - 1.0
    mean_excess = mean_r - rf_period
    if unsmoothed_period_std > 0.0:
        unsmoothed_period_sr: float | None = mean_excess / unsmoothed_period_std
        unsmoothed_ann_sr: float | None = unsmoothed_period_sr * math.sqrt(periods_per_year)
    else:
        unsmoothed_period_sr = None
        unsmoothed_ann_sr = None

    requires_unsmoothed = (xi < GLM_XI_THRESHOLD) or (rho1 > GLM_RHO1_THRESHOLD)
    return GlmUnsmoothingResult(
        theta_0=theta_0,
        theta_1=theta_1,
        theta_2=theta_2,
        smoothing_index_xi=xi,
        lag1_autocorrelation=rho1,
        lag2_autocorrelation=rho2,
        unsmoothed_period_volatility=unsmoothed_period_std,
        unsmoothed_annualized_volatility=unsmoothed_ann_vol,
        unsmoothed_period_sharpe=unsmoothed_period_sr,
        unsmoothed_annualized_sharpe=unsmoothed_ann_sr,
        requires_unsmoothed_psr=requires_unsmoothed,
    )


def evaluate_econometric_diagnostics(
    returns: Sequence[float],
    *,
    periods_per_year: float = 252.0,
    annual_risk_free_rate: float = 0.0,
    psr_benchmark_sr_annualized: float = 0.0,
    min_trl_confidence: float = 0.95,
) -> EconometricBundle:
    """Compute higher moments, GLM MA(2) unsmoothing, and sample-gated PSR / MinTRL."""
    obs_count = len(returns)
    warnings: list[str] = []

    skew, excess_kurt = compute_higher_moments(returns)
    rho1 = compute_sample_autocorrelation(returns, lag=1)
    glm = estimate_glm_ma2(
        returns,
        periods_per_year=periods_per_year,
        annual_risk_free_rate=annual_risk_free_rate,
    )

    xi = glm.smoothing_index_xi if glm is not None else None
    unsmoothed_vol = glm.unsmoothed_annualized_volatility if glm is not None else None
    unsmoothed_sr = glm.unsmoothed_annualized_sharpe if glm is not None else None

    if obs_count < MIN_PSR_OBSERVATIONS:
        if obs_count > 0:
            warnings.append(
                f"Probabilistic Sharpe Ratio (PSR) and MinTRL require at least {MIN_PSR_OBSERVATIONS} "
                f"return observations (got T={obs_count}); withheld per sample-size gate."
            )
        return EconometricBundle(
            observation_count=obs_count,
            psr_sample_eligible=False,
            skewness=skew,
            excess_kurtosis=excess_kurt,
            lag1_autocorrelation=rho1,
            smoothing_index_xi=xi,
            unsmoothed_volatility=unsmoothed_vol,
            unsmoothed_sharpe_ratio=unsmoothed_sr,
            probabilistic_sharpe_ratio=None,
            psr_glm_unsmoothed=None,
            min_track_record_length_periods=None,
            glm_profile=glm,
            warnings=tuple(warnings),
        )

    arr = np.asarray(returns, dtype=np.float64)
    rf_period = (1.0 + annual_risk_free_rate) ** (1.0 / periods_per_year) - 1.0
    excess = arr - rf_period
    excess_std = float(np.std(excess, ddof=1))
    if excess_std <= 1e-24 or skew is None or excess_kurt is None:
        warnings.append(
            "PSR and MinTRL are undefined because return volatility is zero or higher moments are degenerate."
        )
        return EconometricBundle(
            observation_count=obs_count,
            psr_sample_eligible=True,
            skewness=skew,
            excess_kurtosis=excess_kurt,
            lag1_autocorrelation=rho1,
            smoothing_index_xi=xi,
            unsmoothed_volatility=unsmoothed_vol,
            unsmoothed_sharpe_ratio=unsmoothed_sr,
            probabilistic_sharpe_ratio=None,
            psr_glm_unsmoothed=None,
            min_track_record_length_periods=None,
            glm_profile=glm,
            warnings=tuple(warnings),
        )

    period_sr = float(np.mean(excess)) / excess_std
    benchmark_period_sr = psr_benchmark_sr_annualized / math.sqrt(periods_per_year)

    psr_val = compute_probabilistic_sharpe_ratio(
        period_sr,
        benchmark_period_sr,
        observation_count=obs_count,
        skewness=skew,
        excess_kurtosis=excess_kurt,
    )
    min_trl = compute_min_track_record_length(
        period_sr,
        benchmark_period_sr,
        observation_count=obs_count,
        skewness=skew,
        excess_kurtosis=excess_kurt,
        confidence_level=min_trl_confidence,
    )

    psr_unsmoothed: float | None = None
    should_populate_unsmoothed = (
        (xi is not None and xi < GLM_XI_THRESHOLD)
        or (rho1 is not None and rho1 > GLM_RHO1_THRESHOLD)
    )
    if should_populate_unsmoothed and glm is not None and glm.unsmoothed_period_sharpe is not None:
        psr_unsmoothed = compute_probabilistic_sharpe_ratio(
            glm.unsmoothed_period_sharpe,
            benchmark_period_sr,
            observation_count=obs_count,
            skewness=skew,
            excess_kurtosis=excess_kurt,
        )
        warnings.append(
            f"Positive serial correlation detected (GLM xi={xi:.4f}, rho_1={rho1:.4f}); "
            "populated psr_glm_unsmoothed alongside raw PSR."
        )

    return EconometricBundle(
        observation_count=obs_count,
        psr_sample_eligible=True,
        skewness=skew,
        excess_kurtosis=excess_kurt,
        lag1_autocorrelation=rho1,
        smoothing_index_xi=xi,
        unsmoothed_volatility=unsmoothed_vol,
        unsmoothed_sharpe_ratio=unsmoothed_sr,
        probabilistic_sharpe_ratio=psr_val,
        psr_glm_unsmoothed=psr_unsmoothed,
        min_track_record_length_periods=min_trl,
        glm_profile=glm,
        warnings=tuple(warnings),
    )


def _validate_finite_float(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite real number")
    coerced = float(value)
    if not math.isfinite(coerced):
        raise ValueError(f"{name} must be finite")
    return coerced


def _validate_strict_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    return int(value)


def evaluate_claim_plausibility(
    claimed_sharpe: float,
    observed_periods: int,
    *,
    annualization_factor: int = 252,
    skewness: float = 0.0,
    excess_kurtosis: float = 3.0,
    benchmark_sharpe: float = 0.0,
) -> ClaimPlausibilityAnalysis:
    """Evaluate statistical plausibility of a public Sharpe claim via non-normal PSR and MinTRL.

    Follows Bailey & Lopez de Prado (2012) using the module-wide excess kurtosis convention
    (``excess_kurtosis = gamma_4 - 3``, so normal Gaussian returns have ``excess_kurtosis = 0.0``
    and default fat-tailed returns use ``excess_kurtosis = 3.0``). Never asserts misconduct;
    strictly quantifies finite-sample estimation error and notes return-smoothing caveats.
    """
    cs = _validate_finite_float(claimed_sharpe, "claimed_sharpe")
    obs_n = _validate_strict_int(observed_periods, "observed_periods")
    ann_factor = _validate_strict_int(annualization_factor, "annualization_factor")
    sk = _validate_finite_float(skewness, "skewness")
    ek = _validate_finite_float(excess_kurtosis, "excess_kurtosis")
    bs = _validate_finite_float(benchmark_sharpe, "benchmark_sharpe")

    if obs_n < 2 or obs_n > 25_000:
        raise ValueError("observed_periods must lie in [2, 25000]")
    if ann_factor < 1 or ann_factor > 10_000:
        raise ValueError("annualization_factor must lie in [1, 10000]")
    if abs(cs) > 100.0:
        raise ValueError("claimed_sharpe magnitude must not exceed 100.0")
    if abs(bs) > 100.0:
        raise ValueError("benchmark_sharpe magnitude must not exceed 100.0")
    if abs(sk) > 25.0:
        raise ValueError("skewness magnitude must not exceed 25.0")
    if ek < -2.0 or ek > 200.0:
        raise ValueError("excess_kurtosis must lie in [-2.0, 200.0]")

    sqrt_ann = math.sqrt(float(ann_factor))
    sr_hat = cs / sqrt_ann
    sr_star = bs / sqrt_ann

    v_factor = max(1e-9, 1.0 - sk * sr_hat + ((ek + 2.0) / 4.0) * (sr_hat * sr_hat))
    dof = max(1, obs_n - 1)
    z_score = ((sr_hat - sr_star) * math.sqrt(float(dof))) / math.sqrt(v_factor)
    implied_psr = max(0.0, min(1.0, float(_STD_NORMAL.cdf(z_score))))

    required_min_trl: float | None = None
    if cs > bs:
        z_95 = _STD_NORMAL.inv_cdf(0.95)
        diff = sr_hat - sr_star
        min_trl_raw = 1.0 + v_factor * ((z_95 / diff) ** 2)
        if math.isfinite(min_trl_raw):
            required_min_trl = float(min_trl_raw)

    se_annualized = math.sqrt(float(ann_factor) * v_factor / float(dof))
    num_curve_points = 51
    inv_sqrt_2pi = 1.0 / math.sqrt(2.0 * math.pi)
    bell_curve_points: list[dict[str, float]] = []
    for idx in range(num_curve_points):
        z_offset = -3.5 + (7.0 * float(idx)) / float(num_curve_points - 1)
        x_val = cs + z_offset * se_annualized
        pdf_val = (math.exp(-0.5 * z_offset * z_offset) * inv_sqrt_2pi) / se_annualized
        bell_curve_points.append(
            {
                "sharpe": round(x_val, 6),
                "density": round(pdf_val, 6),
            }
        )

    if obs_n < MIN_PSR_OBSERVATIONS or implied_psr < 0.80 or required_min_trl is None:
        sufficiency_tier = CLAIM_SUFFICIENCY_NOISE_DOMINATED
    elif implied_psr < 0.95:
        sufficiency_tier = CLAIM_SUFFICIENCY_BORDERLINE
    else:
        sufficiency_tier = CLAIM_SUFFICIENCY_SUFFICIENT_IF_UNSMOOTHED

    if required_min_trl is None:
        summary = (
            f"A reported annualized Sharpe of {cs:.2f} over {obs_n} periods does not exceed "
            f"the benchmark Sharpe of {bs:.2f} (tail-adjusted PSR = {implied_psr * 100.0:.1f}%, "
            f"SE = {se_annualized:.2f}); no finite track-record length can establish "
            "outperformance at 95% confidence."
        )
    elif sufficiency_tier == CLAIM_SUFFICIENCY_NOISE_DOMINATED:
        summary = (
            f"Over {obs_n} observed periods, an annualized Sharpe of {cs:.2f} carries a "
            f"tail-adjusted standard error of {se_annualized:.2f} (implied PSR = "
            f"{implied_psr * 100.0:.1f}% vs {bs:.2f} benchmark), whereas approximately "
            f"{math.ceil(required_min_trl)} unsmoothed periods are required for 95% statistical "
            "confidence; finite-sample estimation noise dominates short track records even "
            "before accounting for serial correlation or return smoothing."
        )
    elif sufficiency_tier == CLAIM_SUFFICIENCY_BORDERLINE:
        summary = (
            f"Over {obs_n} observed periods, an annualized Sharpe of {cs:.2f} yields a "
            f"borderline tail-adjusted PSR of {implied_psr * 100.0:.1f}% (SE = "
            f"{se_annualized:.2f} vs {bs:.2f} benchmark), short of the "
            f"~{math.ceil(required_min_trl)} periods required for 95% confidence assuming "
            "unsmoothed, serially independent returns."
        )
    else:
        summary = (
            f"Over {obs_n} observed periods, an annualized Sharpe of {cs:.2f} achieves a "
            f"tail-adjusted PSR of {implied_psr * 100.0:.1f}% (SE = {se_annualized:.2f}, "
            f"exceeding the ~{math.ceil(required_min_trl)}-period 95% MinTRL threshold against "
            f"a {bs:.2f} benchmark), provided returns are unsmoothed and free of positive "
            "serial correlation or survivorship selection."
        )

    return ClaimPlausibilityAnalysis(
        claimed_sharpe=cs,
        annualization_factor=ann_factor,
        observed_periods=obs_n,
        skewness=sk,
        excess_kurtosis=ek,
        benchmark_sharpe=bs,
        implied_psr=implied_psr,
        required_min_trl_periods_95pct=required_min_trl,
        sufficiency_tier=sufficiency_tier,
        bell_curve_points=bell_curve_points,
        plain_english_summary=summary,
    )


__all__ = [
    "CLAIM_SUFFICIENCY_BORDERLINE",
    "CLAIM_SUFFICIENCY_NOISE_DOMINATED",
    "CLAIM_SUFFICIENCY_SUFFICIENT_IF_UNSMOOTHED",
    "EconometricBundle",
    "GLM_MIN_OBSERVATIONS",
    "GLM_RHO1_THRESHOLD",
    "GLM_XI_THRESHOLD",
    "GlmUnsmoothingResult",
    "MIN_PSR_OBSERVATIONS",
    "compute_higher_moments",
    "compute_min_track_record_length",
    "compute_probabilistic_sharpe_ratio",
    "compute_sample_autocorrelation",
    "estimate_glm_ma2",
    "evaluate_claim_plausibility",
    "evaluate_econometric_diagnostics",
]
