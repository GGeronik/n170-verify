#!/usr/bin/env python3
"""Independent SPEC-03 binary64 oracle; Python 3.10+, standard library only.

The signed integer series is the input. This derived, unsigned view never
changes a record. Evaluation follows E1–E15; Q5 uses its specified defaults.
"""

import argparse
import hashlib
import json
import math
import random
import statistics
import sys

VERSION = "n170.verify.statistics.v1"
FREQUENCIES = (1, 4, 12, 52, 252, 365, 366)
SAFE_INTEGER = 9007199254740991
FIGURES = (
    "mean", "sd", "variance", "m2", "m3", "m4", "skewness",
    "skewness_se", "excess_kurtosis", "excess_kurtosis_se", "rho1",
    "rho1_se", "rho1_band", "autocorr_significant", "sharpe_per_interval",
    "sharpe_annualized_nominal", "lo_eta", "sharpe_annualized_adjusted",
    "annualization_code", "V", "sigma_sr", "z", "psr0", "mintrl",
    "mintrl_code", "inference_code",
)
PHI_REFERENCES = (
    (-8.2, 1.2019351542735896e-16), (-5.7, 5.9903714010635321e-09),
    (-3.0, 0.0013498980316300957), (-2.0526, 0.020055693779797306),
    (-1.0, 0.15865525393145705), (0.0, 0.5),
    (1.0, 0.84134474606854293), (1.7238, 0.9576280226859315),
    (2.0526, 0.97994430622020268), (3.0, 0.9986501019683699),
    (5.7, 0.99999999400962858),
)


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


def phi(z):
    z = finite(z)
    root2 = finite(math.sqrt(2))
    argument = finite((-z if z < 0 else z) / root2)
    tail = finite(0.5 * finite(math.erfc(argument)))
    return tail if z < 0 else finite(1 - tail)


def inference_from_moments(T, S, skewness, excess_kurtosis,
                           autocorr_significant=False):
    """Expose the frozen inference formula for F09a's independent guard probes."""
    try:
        if (type(T) is not int or T < 20 or not all(real(x) for x in
                (S, skewness, excess_kurtosis))
                or type(autocorr_significant) is not bool):
            raise ArithmeticError("corrupted moments")
        half_s = finite(0.5 * S)
        square_term = finite(half_s * S)
        leading = finite(1 + square_term)
        skew_term = finite(skewness * S)
        leading = finite(leading - skew_term)
        quarter_kurtosis = finite(excess_kurtosis / 4)
        kurtosis_s = finite(quarter_kurtosis * S)
        kurtosis_term = finite(kurtosis_s * S)
        V = finite(leading + kurtosis_term)
        if V <= 0:
            raise ArithmeticError("nonpositive V")
        sigma_sr = finite(math.sqrt(finite(V / (T - 1))))
        z = finite(S / sigma_sr)
        psr0 = finite(phi(z))
        mintrl = None
        mintrl_code = "MINTRL_UNDEFINED_NONPOSITIVE_EXCESS"
        if S > 0:
            k = finite(1.6448536269514722 / S)
            kk = finite(k * k)
            Vk = finite(V * kk)
            mintrl = math.ceil(finite(1 + Vk))
            mintrl_code = None
        return {"status": "OK", "V": V, "sigma_sr": sigma_sr,
                "z": z, "psr0": psr0, "mintrl": mintrl,
                "mintrl_code": mintrl_code,
                "inference_code": ("STATS_INFERENCE_ASSUMES_IID"
                                   if autocorr_significant else None)}
    except (ArithmeticError, ValueError, TypeError, OverflowError):
        return {"status": "STATS_NON_FINITE", **{key: None for key in
                ("V", "sigma_sr", "z", "psr0", "mintrl", "mintrl_code",
                 "inference_code")}}


def compute(fixture, fixture_sha256=None):
    if not isinstance(fixture, dict):
        fixture = {}
    returns = fixture.get("returns_e8")
    q = fixture.get("periods_per_year")
    schedule = fixture.get("schedule_compatible")
    rf = fixture.get("rf_per_interval", 0)
    result = {"schema": VERSION, "fixture": fixture.get("id"),
              "fixture_sha256": fixture_sha256, "status": "STATS_NON_FINITE",
              "T": len(returns) if isinstance(returns, list) else None,
              "periods_per_year": q if type(q) is int and abs(q) <= SAFE_INTEGER else None,
              "schedule_compatible": schedule if type(schedule) is bool else None,
              "rf_per_interval": rf if real(rf) else None,
              **{key: None for key in FIGURES},
              "labels": {"rf": "excess over 0",
                         "inference": "at observed moments"}}
    if (not isinstance(returns, list)
            or not all(type(x) is int and abs(x) <= SAFE_INTEGER for x in returns)
            or type(q) is not int or q <= 0 or q > SAFE_INTEGER
            or type(schedule) is not bool or not real(rf)):
        return result
    T = len(returns)
    if T < 20:
        result["status"] = "STATS_SAMPLE_INSUFFICIENT"
        return result
    # Q5: exact signed-integer equality, before computing a rounded mean.
    if all(x == returns[0] for x in returns):
        result["status"] = "STATS_ZERO_VARIANCE"
        return result
    compatible = schedule and q in FREQUENCIES
    result["schedule_compatible"] = compatible
    try:
        r = [finite(x / 100000000) for x in returns]
        mean = finite(finite(math.fsum(r)) / T)
        d = [finite(x - mean) for x in r]
        d2 = [finite(x * x) for x in d]
        d3 = [finite(xx * x) for xx, x in zip(d2, d)]
        d4 = [finite(xx * xx) for xx in d2]
        denominator = finite(math.fsum(d2))
        m2 = finite(denominator / T)
        m3 = finite(finite(math.fsum(d3)) / T)
        m4 = finite(finite(math.fsum(d4)) / T)
        variance = finite(finite(T * m2) / (T - 1))
        sd = finite(math.sqrt(variance))
        root_m2 = finite(math.sqrt(m2))
        skewness = finite(m3 / finite(m2 * root_m2))
        excess_kurtosis = finite(finite(m4 / finite(m2 * m2)) - 3)
        skewness_se = finite(math.sqrt(finite(6 / T)))
        excess_kurtosis_se = finite(math.sqrt(finite(24 / T)))
        root_T = finite(math.sqrt(T))
        rho1_se = finite(1 / root_T)
        rho1_band = finite(1.96 / root_T)
        lag_terms = [finite(d[t] * d[t - 1]) for t in range(1, T)]
        rho1 = finite(finite(math.fsum(lag_terms)) / denominator)
        autocorr_significant = abs(rho1) > rho1_band
        S = finite(finite(mean - rf) / sd)
        nominal = eta = adjusted = None
        if compatible:
            root_q = finite(math.sqrt(q))
            nominal = finite(S * root_q)
            eta = 1
            if rho1 > 0:
                fraction = finite((q - 1) / q)
                weight = finite(2 * fraction)
                correction = finite(weight * rho1)
                eta = finite(1 + correction)
            adjusted = finite(nominal / finite(math.sqrt(eta)))
        inference = inference_from_moments(T, S, skewness, excess_kurtosis,
                                            autocorr_significant)
        if inference["status"] != "OK":
            return result
        result.update({"status": "OK", "mean": mean, "sd": sd,
                       "variance": variance, "m2": m2, "m3": m3, "m4": m4,
                       "skewness": skewness, "skewness_se": skewness_se,
                       "excess_kurtosis": excess_kurtosis,
                       "excess_kurtosis_se": excess_kurtosis_se,
                       "rho1": rho1, "rho1_se": rho1_se,
                       "rho1_band": rho1_band,
                       "autocorr_significant": autocorr_significant,
                       "sharpe_per_interval": S,
                       "sharpe_annualized_nominal": nominal, "lo_eta": eta,
                       "sharpe_annualized_adjusted": adjusted,
                       "annualization_code": None if compatible else
                       "SCHEDULE_ANNUALIZATION_REFUSED"})
        result.update({key: value for key, value in inference.items() if key != "status"})
        return result
    except (ArithmeticError, ValueError, TypeError, OverflowError):
        return result


def vectors(seed, count):
    rng = random.Random(seed)
    points = []
    for _ in range(count):
        z = rng.uniform(-10, 10)
        points.append({"z": z, "phi": phi(z)})
    return {"id": "F16", "seed": seed, "count": count,
            "generator": "random.Random(seed).uniform(-10, 10)", "points": points}


def evaluate_input(fixture, digest):
    """Vector inputs use a separate schema; series retain the §6.5 interface."""
    if isinstance(fixture, dict) and fixture.get("schema") == "n170.verify.statistics-phi-fixture.v1":
        if fixture["id"] == "F16":
            points = vectors(fixture["seed"], fixture["count"])["points"]
        else:
            points = [{"z": z, "phi": phi(z)} for z in fixture["z_values"]]
        return {"schema": VERSION, "fixture": fixture["id"],
                "fixture_sha256": digest, "points": points}
    return compute(fixture, digest)


def sanity():
    points = []
    for z, reference in PHI_REFERENCES:
        actual = phi(z)
        other = statistics.NormalDist().cdf(z)
        points.append({"z": z, "reference": reference, "erfc": actual,
                       "exact_match": actual == reference, "normaldist": other,
                       "normaldist_minus_erfc": other - actual})
    sum_vectors = (([0.1] * 10, 1.0),
                   ([1e100, 1.0, -1e100, 1e-100, 1e50, -1.0, -1e50], 1e-100),
                   ([9007199254740992, 1.0, -9007199254740992], 1.0), ([], 0.0))
    sums = [{"terms": terms, "expected": expected, "actual": math.fsum(terms),
             "exact_match": math.fsum(terms) == expected} for terms, expected in sum_vectors]
    ok = all(row["exact_match"] for row in points + sums)
    return {"pass": ok, "phi_points": points, "fsum_vectors": sums,
            "normaldist_note": "Second CDF reported, never substituted for erfc; older Python CDFs may cancel in negative tails."}


def emit(value):
    print(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    compute_parser = commands.add_parser("compute")
    compute_parser.add_argument("input")
    phi_parser = commands.add_parser("phi")
    phi_parser.add_argument("z", type=float)
    vector_parser = commands.add_parser("vectors")
    vector_parser.add_argument("seed", type=int)
    vector_parser.add_argument("count", type=int)
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
        emit(evaluate_input(fixture, hashlib.sha256(raw).hexdigest()))
    elif args.command == "phi":
        emit(phi(args.z))
    elif args.command == "vectors":
        if args.count < 0:
            parser.error("count must be nonnegative")
        emit(vectors(args.seed, args.count))
    else:
        report = sanity()
        emit(report)
        return 0 if report["pass"] else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
