"""Original synthetic interoperability and fail-closed controls; no engine runs."""

import csv
import hashlib
import io
import json
from pathlib import Path
import unittest

from verify_toolkit.freqtrade import MAX_CSV_BYTES, MAX_ROWS, assess_lookahead


HEADER = [
    "filename", "strategy", "has_bias", "total_signals",
    "biased_entry_signals", "biased_exit_signals", "biased_indicators",
]
CLEAN = ["Synthetic.py", "Synthetic", "False", "20", "0", "0", ""]
EXAMPLES = Path(__file__).resolve().parents[1] / "verify_toolkit" / "examples"


def export(*rows, header=HEADER):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(header)
    writer.writerows(rows)
    return stream.getvalue()


def changed(**values):
    result = dict(zip(HEADER, CLEAN))
    result.update(values)
    return [result[column] for column in HEADER]


class FreqtradeEvidenceTests(unittest.TestCase):
    def test_clean_fixture_is_only_a_reported_observation(self):
        text = (EXAMPLES / "freqtrade-lookahead-clean.csv").read_text()
        result = assess_lookahead(text)
        self.assertEqual(result["status"], "NO_FINDINGS_REPORTED")
        self.assertEqual(result["tested_strategy_count"], 1)
        self.assertEqual(result["scope"]["tool_execution"], "not_performed")
        self.assertEqual(result["scope"]["source_authenticity"], "unverified")
        self.assertEqual(result["scope"]["run_completeness"], "not_established")
        self.assertEqual(result["scope"]["source_sha256"], hashlib.sha256(text.encode()).hexdigest())
        self.assertNotIn("PASSED", json.dumps(result))

    def test_finding_fixture_preserves_counts_and_indicator_list(self):
        result = assess_lookahead((EXAMPLES / "freqtrade-lookahead-findings.csv").read_text())
        self.assertEqual(result["status"], "FINDINGS_REPORTED")
        self.assertEqual(result["rows"][0]["biased_entry_signals"], 2)
        self.assertEqual(result["rows"][0]["biased_indicators"], ["future_close", "whole_history_mean"])

    def test_skipped_fixture_is_not_clean(self):
        result = assess_lookahead((EXAMPLES / "freqtrade-lookahead-not-assessable.csv").read_text())
        self.assertEqual(result["status"], "NOT_ASSESSABLE")
        self.assertEqual(result["tested_strategy_count"], 0)

    def test_bool_export_and_table_spellings(self):
        for flag in ["False", "false", "No", "no"]:
            with self.subTest(flag=flag):
                self.assertEqual(assess_lookahead(export(changed(has_bias=flag)))["status"], "NO_FINDINGS_REPORTED")
        for flag in ["True", "true", "Yes", "yes"]:
            with self.subTest(flag=flag):
                self.assertEqual(assess_lookahead(export(changed(has_bias=flag, biased_entry_signals="1")))["status"], "FINDINGS_REPORTED")

    def test_entry_and_exit_can_both_equal_total(self):
        result = assess_lookahead(export(changed(has_bias="True", biased_entry_signals="20", biased_exit_signals="20")))
        self.assertEqual(result["status"], "FINDINGS_REPORTED")

    def test_indicator_only_finding_and_freqai_target_are_not_silently_ignored(self):
        for indicator in ["future_mean", "&-target"]:
            with self.subTest(indicator=indicator):
                result = assess_lookahead(export(changed(has_bias="True", biased_indicators=indicator)))
                self.assertEqual(result["status"], "FINDINGS_REPORTED")

    def test_optional_leading_index_reordered_headers_bom_and_crlf(self):
        for index_header in ["", "Unnamed: 0"]:
            with self.subTest(index=index_header):
                columns = [index_header] + list(reversed(HEADER))
                text = "\ufeff" + export(["0"] + list(reversed(CLEAN)), header=columns)
                self.assertEqual(assess_lookahead(text)["status"], "NO_FINDINGS_REPORTED")

    def test_empty_and_header_only_exports_are_unassessable(self):
        for text in ["", "\n", export(), "\ufeff"]:
            with self.subTest(text=text):
                self.assertEqual(assess_lookahead(text)["status"], "NOT_ASSESSABLE")

    def test_bad_counts_never_default_to_zero(self):
        for column in HEADER[3:6]:
            for value in ["", "NaN", "nan", "inf", "Infinity", "-1", "1.0", "1e2", "00", "+1", "1000000001"]:
                with self.subTest(column=column, value=value):
                    result = assess_lookahead(export(changed(**{column: value})))
                    self.assertEqual(result["status"], "NOT_ASSESSABLE")

    def test_zero_signals_does_not_count_as_tested(self):
        result = assess_lookahead(export(changed(total_signals="0")))
        self.assertEqual(result["status"], "NOT_ASSESSABLE")
        self.assertEqual(result["tested_strategy_count"], 0)
        self.assertIn("NO_TESTED_SIGNALS", result["reason_codes"])

    def test_unknown_failed_skipped_and_not_run_flags_never_clean(self):
        for flag in ["", "0", "1", "null", "failed", "skipped", "not_run", "error while checking", "too few trades caught (0/10).Test failed."]:
            with self.subTest(flag=flag):
                self.assertEqual(assess_lookahead(export(changed(has_bias=flag)))["status"], "NOT_ASSESSABLE")

    def test_conflicting_bias_flag_or_counts_rejected(self):
        cases = [
            changed(has_bias="True"), changed(biased_entry_signals="1"),
            changed(biased_indicators="future_mean"),
            changed(has_bias="True", biased_entry_signals="21"),
            changed(has_bias="True", biased_exit_signals="21"),
        ]
        for row in cases:
            with self.subTest(row=row):
                self.assertEqual(assess_lookahead(export(row))["status"], "NOT_ASSESSABLE")

    def test_duplicate_rows_columns_and_indices_rejected(self):
        cases = [
            export(CLEAN, CLEAN),
            export(CLEAN + ["False"], header=HEADER + ["has_bias"]),
            export(["0"] + CLEAN, ["0"] + changed(strategy="Another"), header=[""] + HEADER),
            export(CLEAN[:-1], header=HEADER[:-1] + ["has_bias"]),
        ]
        for text in cases:
            with self.subTest(text=text):
                self.assertEqual(assess_lookahead(text)["status"], "NOT_ASSESSABLE")

    def test_extra_missing_and_nonleading_index_columns_rejected(self):
        for text in [
            export(CLEAN + ["secret"], header=HEADER + ["credentials"]),
            export(CLEAN[:-1], header=HEADER[:-1]),
            export(CLEAN + ["0"], header=HEADER + ["Unnamed: 0"]),
        ]:
            with self.subTest(text=text):
                result = assess_lookahead(text)
                self.assertEqual(result["status"], "NOT_ASSESSABLE")
                self.assertNotIn("secret", json.dumps(result))

    def test_malformed_and_oversized_csv_is_bounded(self):
        for text in [
            export(CLEAN[:-1]), export(CLEAN + ["extra"]),
            ",".join(HEADER) + '\n"unterminated',
            export(changed(strategy="bad\x00name")),
            "x" * (MAX_CSV_BYTES + 1), "é" * (MAX_CSV_BYTES // 2 + 1),
            "\ud800", export(changed(biased_indicators="x" * 8_193)),
        ]:
            with self.subTest(size=len(text)):
                self.assertEqual(assess_lookahead(text)["status"], "NOT_ASSESSABLE")

    def test_row_limit_and_rejected_rows_are_bounded(self):
        text = export(*(changed(strategy=f"Synthetic{i}") for i in range(MAX_ROWS + 1)))
        result = assess_lookahead(text)
        self.assertEqual(result["status"], "NOT_ASSESSABLE")
        self.assertEqual(len(result["rows"]), MAX_ROWS)
        self.assertIn("ROW_LIMIT_EXCEEDED", result["reason_codes"])

    def test_unsafe_identifier_values_never_appear_in_report(self):
        for key, value in [
            ("filename", "/private/secret.py"), ("filename", "../secret.py"),
            ("strategy", "<script>alert(1)</script>"),
            ("strategy", "=IMPORTXML(secret)"),
            ("strategy", "bad\nname"),
            ("biased_indicators", "<script>secret</script>"),
        ]:
            with self.subTest(key=key):
                row = changed(**{key: value})
                result = assess_lookahead(export(row))
                self.assertEqual(result["status"], "NOT_ASSESSABLE")
                self.assertNotIn(value, json.dumps(result))

    def test_empty_duplicate_or_excessive_indicator_members_rejected(self):
        for indicators in ["a,", "a,,b", "a,a", ",", ",".join(f"i{x}" for x in range(129))]:
            with self.subTest(indicators=indicators):
                result = assess_lookahead(export(changed(has_bias="True", biased_indicators=indicators)))
                self.assertEqual(result["status"], "NOT_ASSESSABLE")

    def test_mixed_findings_and_invalid_rows_preserve_findings_without_clean_summary(self):
        finding = changed(has_bias="True", biased_entry_signals="1")
        invalid = changed(strategy="Skipped", has_bias="skipped")
        result = assess_lookahead(export(finding, invalid))
        self.assertEqual(result["status"], "NOT_ASSESSABLE")
        self.assertEqual(result["rows"][0]["status"], "FINDINGS_REPORTED")
        self.assertEqual(result["tested_strategy_count"], 1)

    def test_only_bounded_unverified_context_is_retained(self):
        context = {
            "freqtrade_version": "2026.8", "run_status": "COMPLETED",
            "config_sha256": "a" * 64, "expected_strategy_count": 1,
            "run_config": {"timerange": "20260101-20260201", "timeframe": "5m",
                           "minimum_trade_amount": 10, "targeted_trade_amount": 20,
                           "lookahead_allow_limit_orders": False},
        }
        result = assess_lookahead(export(CLEAN), context=context)
        self.assertEqual(result["status"], "NO_FINDINGS_REPORTED")
        self.assertEqual(result["scope"]["declared_context"], context)
        self.assertEqual(result["scope"]["context_authenticity"], "unverified")
        self.assertEqual(result["scope"]["run_completeness"], "not_established")
        context["run_config"]["timeframe"] = "1d"
        self.assertEqual(result["scope"]["declared_context"]["run_config"]["timeframe"], "5m")

    def test_full_configs_secrets_and_bad_context_never_leak(self):
        for context in [
            {"api_key": "secret_value"}, {"run_config": {"exchange": {"key": "secret_value"}}},
            {"freqtrade_version": "secret_value\n"}, {"config_sha256": "secret_value"},
            {"expected_strategy_count": True}, {"expected_strategy_count": 0},
            {"run_status": "secret_value"}, {"run_config": {"timeframe": []}},
            {"run_config": {"minimum_trade_amount": float("nan")}}, [],
        ]:
            with self.subTest(context=context):
                result = assess_lookahead(export(CLEAN), context=context)
                self.assertEqual(result["status"], "NOT_ASSESSABLE")
                self.assertNotIn("secret_value", json.dumps(result, allow_nan=False))

    def test_run_not_completed_and_coverage_mismatch_block_clean_summary(self):
        for context in [
            {"run_status": state} for state in ["FAILED", "SKIPPED", "NOT_RUN", "CANCELLED"]
        ] + [{"expected_strategy_count": 2}]:
            with self.subTest(context=context):
                self.assertEqual(assess_lookahead(export(CLEAN), context=context)["status"], "NOT_ASSESSABLE")

    def test_explicit_minimum_target_and_count_contradictions(self):
        for config in [
            {"minimum_trade_amount": 20}, {"minimum_trade_amount": 21},
            {"targeted_trade_amount": 19},
            {"minimum_trade_amount": 20, "targeted_trade_amount": 19},
        ]:
            with self.subTest(config=config):
                self.assertEqual(assess_lookahead(export(CLEAN), context={"run_config": config})["status"], "NOT_ASSESSABLE")

    def test_non_string_inputs_return_fixed_json_safe_reason(self):
        for supplied in [None, b"csv", {}, [], 1, float("nan")]:
            with self.subTest(type=type(supplied)):
                result = assess_lookahead(supplied)
                self.assertEqual(result["status"], "NOT_ASSESSABLE")
                json.dumps(result, allow_nan=False)


if __name__ == "__main__":
    unittest.main()
