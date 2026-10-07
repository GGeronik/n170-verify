"""Small public synthetic corpus for the supplied-output interpretation boundary.

Expected outcomes are specified here, independently of parser implementation.
This does not benchmark Freqtrade's detector or validate an investment strategy.
"""
from .freqtrade import assess_lookahead

HEADER = "filename,strategy,has_bias,total_signals,biased_entry_signals,biased_exit_signals,biased_indicators\n"
CLEAN = "example.py,Example,False,24,0,0,\n"
FINDING = "example.py,Example,True,24,1,0,future_close\n"


def run_conformance():
    cases = [
        ("positive_signal_control", HEADER + CLEAN, None, "NO_FINDINGS_REPORTED"),
        ("reported_bias_control", HEADER + FINDING, None, "FINDINGS_REPORTED"),
        ("indicator_only_finding", HEADER + "example.py,Example,True,24,0,0,future_close\n", None, "FINDINGS_REPORTED"),
        ("absent_observations", HEADER, None, "NOT_ASSESSABLE"),
        ("zero_signals", HEADER + CLEAN.replace(",24,", ",0,"), None, "NOT_ASSESSABLE"),
        ("hidden_bias_flag", HEADER + FINDING.replace("True", "False"), None, "NOT_ASSESSABLE"),
        ("invented_bias_flag", HEADER + CLEAN.replace("False", "True"), None, "NOT_ASSESSABLE"),
        ("duplicate_strategy", HEADER + CLEAN + CLEAN, None, "NOT_ASSESSABLE"),
        ("negative_count", HEADER + CLEAN.replace(",24,", ",-1,"), None, "NOT_ASSESSABLE"),
        ("nan_count", HEADER + CLEAN.replace(",24,", ",NaN,"), None, "NOT_ASSESSABLE"),
        ("unknown_column", HEADER.rstrip("\n") + ",verified\n" + CLEAN.rstrip("\n") + ",True\n", None, "NOT_ASSESSABLE"),
        ("declared_failed_run", HEADER + CLEAN, {"run_status": "FAILED"}, "NOT_ASSESSABLE"),
        ("declared_missing_strategy", HEADER + CLEAN, {"expected_strategy_count": 2}, "NOT_ASSESSABLE"),
        ("private_unknown_context", HEADER + CLEAN, {"secret": "must-not-appear"}, "NOT_ASSESSABLE"),
    ]
    observations = []
    for name, source, context, expected in cases:
        actual = assess_lookahead(source, context=context)
        boundaries = all(actual["scope"][key] == value for key, value in {
            "tool_execution": "not_performed", "source_authenticity": "unverified",
            "run_completeness": "not_established", "run_freshness": "not_established",
        }.items())
        observations.append({"case": name, "expected": expected, "observed": actual["status"],
                             "boundary_labels_preserved": boundaries,
                             "matched": actual["status"] == expected and boundaries})
    return {"schema": "n170.tool-evidence.conformance.v1", "synthetic": True,
            "scope": "Supplied CSV parser and evidence-claim controls only; no upstream engine run or competitor comparison.",
            "cases": observations, "case_count": len(observations),
            "unexpected_results": [row["case"] for row in observations if not row["matched"]]}
