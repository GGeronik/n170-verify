"""Original synthetic runner-boundary unit controls, not engine integration evidence.

These receipts deliberately do not establish that Docker or Freqtrade ran.
Real pinned-engine integration evidence is documented separately in RUNNER.md.
"""

import base64
import copy
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import sys
import threading
import unittest
from unittest.mock import patch

from verify_toolkit.freqtrade import UPSTREAM_REVISION
from verify_toolkit import runner
from verify_toolkit.synthetic import generate_fixture
from verify_toolkit.run_contract import (
    ENGINE_SOURCE_SHA256,
    OUTCOMES,
    TRUST,
    WORKER_SCHEMA,
    classify_worker,
    digest,
    inventory_entry,
    json_bytes,
    verify_run,
)


IMAGE = "sha256:" + "a" * 64
HEADER = [
    "filename", "strategy", "has_bias", "total_signals",
    "biased_entry_signals", "biased_exit_signals", "biased_indicators",
]


def csv_bytes(strategy="Clean", *, finding=False, signals=10):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(HEADER)
    writer.writerow([
        strategy + ".py", strategy, str(finding), signals,
        1 if finding else 0, 0, "future_close" if finding else "",
    ])
    return stream.getvalue().encode()


def worker_receipt(strategy, request_raw, request, *, finding=False, outcome="COMPLETED"):
    # Original metadata copied from the pinned public source inventory, not an engine execution.
    source_inventory = json.loads((Path(__file__).resolve().parents[1] / "verify_toolkit/engine-source.json").read_bytes())
    return {
        "schema": WORKER_SCHEMA,
        "strategy": strategy,
        "engine": {
            "version": "2026.8", "revision": UPSTREAM_REVISION,
            "source_sha256": ENGINE_SOURCE_SHA256,
            "source_after_sha256": ENGINE_SOURCE_SHA256,
            "source_files": source_inventory,
        },
        "environment": {"python": "synthetic-unit-fixture", "platform": "synthetic-unit-fixture",
                        "machine": "arm64", "uid": 1000,
                        "packages": [{"name": "freqtrade", "version": "2026.8"}]},
        "engine_arguments": {
            "command": "lookahead-analysis", "config": ["/input/config.json"],
            "user_data_dir": "/tmp/n170-user", "datadir": "/input/data",
            "strategy_path": "/input/strategies", "strategy": strategy,
            "timeframe": "5m", "timerange": request["timerange"],
            "minimum_trade_amount": request["minimum_trade_amount"],
            "targeted_trade_amount": request["targeted_trade_amount"], "fee": request["fee"],
            "dataformat_ohlcv": "json", "lookahead_analysis_exportfilename": "/output/lookahead.csv",
        },
        "input_inventory": copy.deepcopy(request["input_inventory"]),
        "request_sha256": digest(request_raw),
        "outcome": outcome,
        "analysis": {
            "has_bias": finding, "total_signals": 10,
            "biased_entry_signals": 1 if finding else 0,
            "biased_exit_signals": 0,
            "biased_indicators": ["future_close"] if finding else [],
            "failed_bias_check": False,
        },
    }


def image_identity():
    return {"image_id": IMAGE, "reference": IMAGE, "os": "linux", "architecture": "arm64",
            "docker_version": {"Client": {"Version": "synthetic-unit-fixture"},
                               "Server": {"Version": "synthetic-unit-fixture"}}}


def input_mount(argv):
    mount = argv[argv.index("--mount") + 1]
    return Path(mount.split("src=", 1)[1].split(",dst=", 1)[0])


class ScriptedExecution:
    """Synthetic transport: never launches a container, imports a strategy, or runs Freqtrade."""

    def __init__(self, outcomes=None, *, mutate=None):
        self.outcomes = outcomes or {}
        self.mutate = mutate
        self.calls = []

    def __call__(self, argv, *, stdout_path, stderr_path, **kwargs):
        self.calls.append((argv, kwargs))
        staged = input_mount(argv)
        request_raw = (staged / "request.json").read_bytes()
        request = json.loads(request_raw)
        strategy = request["strategy"]
        outcome = self.outcomes.get(strategy, "NO_FINDINGS_REPORTED")
        if self.mutate:
            self.mutate(staged, request)
        worker = worker_receipt(strategy, request_raw, request,
                                finding=outcome == "FINDINGS_REPORTED",
                                outcome=outcome if outcome in {"FAILED", "INSUFFICIENT"} else "COMPLETED")
        effective_config = (staged / "config.json").read_bytes()
        market_metadata = b'{"scope":"original-synthetic-unit-fixture"}\n'
        worker["effective_config_sha256"] = digest(effective_config)
        worker["offline_adapter"] = {"market_metadata_sha256": digest(market_metadata),
                                     "scope": "original synthetic BTC/USDT spot market metadata",
                                     "detector_modified": False}
        worker["environment"] = {"python": "synthetic-unit-fixture", "platform": "synthetic-unit-fixture",
                                 "machine": "arm64", "uid": 1000,
                                 "packages": [{"name": "freqtrade", "version": "2026.8"}]}
        worker["engine"]["source_after_sha256"] = ENGINE_SOURCE_SHA256
        if outcome == "INPUT_CHANGED":
            worker["input_inventory"] = []
        files = {"worker-result.json": json_bytes(worker), "effective-config.json": effective_config,
                 "market-metadata.json": market_metadata}
        if outcome != "MISSING_OUTPUT":
            files["lookahead.csv"] = (b"malformed output" if outcome == "INVALID_OUTPUT"
                                      else csv_bytes(strategy, finding=outcome == "FINDINGS_REPORTED"))
        payload = json_bytes({name: base64.b64encode(raw).decode() for name, raw in files.items()})
        stdout = b"Original synthetic unit fixture: engine not executed.\n" + runner.BUNDLE_PREFIX + base64.b64encode(payload) + b"\n"
        stdout_path.write_bytes(stdout)
        stderr_path.write_bytes(b"")
        termination = outcome if outcome in {"CANCELLED", "TIMED_OUT"} else None
        return {"exit_code": 1 if outcome == "FAILED" else 0, "termination": termination, "stdout": stdout}


class RunBundleVerificationTests(unittest.TestCase):
    """Construct independent, explicitly synthetic receipts to challenge the verifier."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def fixture(self, outcomes=("NO_FINDINGS_REPORTED",)):
        """Use the real orchestrator with a synthetic transport seam, never an engine."""
        self.directory = self.root / "bundle"
        source = generate_fixture(self.root / "synthetic")
        names = ["Clean" if index == 0 else f"Strategy{index}" for index in range(len(outcomes))]
        selected = {}
        for name in names:
            path = source / "strategies" / (name + ".py")
            path.write_text("# Benign original unit fixture; never executed\n")
            selected[name] = path
        scripted = ScriptedExecution(dict(zip(names, outcomes)))
        cancellation = threading.Event()
        if all(outcome == "SKIPPED" for outcome in outcomes):
            cancellation.set()
        with patch.object(runner, "_image_identity", return_value=image_identity()), patch.object(runner, "_execute", side_effect=scripted):
            self.manifest = runner.run_freqtrade(
                self.directory, image=IMAGE, strategies=selected,
                data=source / "data" / "BTC_USDT-5m.json", acknowledge_local_code=True,
                cancel_event=cancellation,
            )
        self.buffers = {path.relative_to(self.directory).as_posix(): path.read_bytes()
                        for path in self.directory.rglob("*") if path.is_file() and path.name != "manifest.json"}
        return self.manifest

    def refresh_inventory(self):
        inventory = [inventory_entry(path, raw) for path, raw in sorted(self.buffers.items())]
        self.manifest["artifacts"] = inventory
        self.manifest["inputs"] = [entry for entry in inventory if "/input/" in entry["path"]]
        for index, attempt in enumerate(self.manifest["attempts"]):
            attempt["artifacts"] = [entry for entry in inventory if entry["path"].startswith(f"attempts/{index:03d}/")]

    def save(self):
        for path, raw in self.buffers.items():
            target = self.directory / path
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                target.chmod(0o600)
            target.write_bytes(raw)
        (self.directory / "manifest.json").write_bytes(json_bytes(self.manifest))

    def check(self, expected="NOT_ASSESSABLE", **kwargs):
        report = verify_run(self.directory, **kwargs)
        self.assertEqual(report["status"], expected, report)
        json.dumps(report, allow_nan=False)
        return report

    def test_clean_receipt_is_consistent_but_not_authenticated_or_reproduced(self):
        self.fixture()
        report = self.check("NO_FINDINGS_REPORTED")
        self.assertEqual(report["summary"]["assessed_count"], 1)
        self.assertEqual(report["trust"], TRUST)
        self.assertIn("unsigned", report["trust"]["authenticity"])
        self.assertIn("not established", report["trust"]["reproduction"])
        self.assertEqual(report["manifest_pin"], "not_supplied")

    def test_findings_remain_visible_when_another_strategy_failed(self):
        self.fixture(("FINDINGS_REPORTED", "FAILED"))
        report = self.check()
        self.assertEqual(report["summary"]["findings_count"], 1)
        self.assertEqual(report["summary"]["outcome_counts"]["FAILED"], 1)
        self.assertIn("UNASSESSABLE_ATTEMPTS", report["reason_codes"])

    def test_complete_findings_receipt_is_assessable(self):
        self.fixture(("NO_FINDINGS_REPORTED", "FINDINGS_REPORTED"))
        self.assertEqual(self.check("FINDINGS_REPORTED")["summary"]["assessed_count"], 2)

    def test_all_non_assessable_outcomes_stay_non_assessable(self):
        for outcome in sorted(OUTCOMES - {"NO_FINDINGS_REPORTED", "FINDINGS_REPORTED"}):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as tmp:
                self.root = Path(tmp).resolve()
                self.fixture((outcome,))
                self.check()

    def test_incomplete_or_nonfinal_manifest_is_never_clean(self):
        self.fixture()
        for state in ("CREATED", "RUNNING", "PENDING", "FAILED", None):
            with self.subTest(state=state):
                self.manifest["state"] = state
                self.save()
                self.check()

    def test_selected_attempts_require_ordered_bijection(self):
        self.fixture(("NO_FINDINGS_REPORTED", "NO_FINDINGS_REPORTED"))
        original = copy.deepcopy(self.manifest)
        mutations = [
            lambda m: m["attempts"].pop(),
            lambda m: m["attempts"].append(copy.deepcopy(m["attempts"][0])),
            lambda m: m["attempts"].reverse(),
            lambda m: m["request"]["strategies"].append("Omitted"),
            lambda m: m["request"].update(strategies=["Clean", "Clean"]),
            lambda m: m["attempts"][1].update(strategy="Clean"),
            lambda m: m["attempts"][1].update(id="000"),
            lambda m: m["attempts"][1].update(state="RUNNING"),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                self.manifest = copy.deepcopy(original)
                mutation(self.manifest)
                self.save()
                self.check()

    def test_detached_manifest_pin_detects_manifest_rewrite(self):
        self.fixture()
        pin = hashlib.sha256((self.directory / "manifest.json").read_bytes()).hexdigest()
        self.assertEqual(self.check("NO_FINDINGS_REPORTED", manifest_sha256=pin)["manifest_pin"], "matched")
        self.manifest["run_id"] = "rewritten-local-id"
        self.save()
        self.assertNotEqual(self.check(manifest_sha256=pin)["manifest_pin"], "matched")

    def test_changed_input_output_and_log_bytes_are_rejected(self):
        self.fixture()
        for path in (
            "attempts/000/input/strategies/Clean.py",
            "attempts/000/input/data/BTC_USDT-5m.json",
            "attempts/000/input/config.json",
            "attempts/000/input/request.json",
            "attempts/000/output/lookahead.csv",
            "attempts/000/output/worker-result.json",
            "attempts/000/stdout.log", "attempts/000/stderr.log",
        ):
            with self.subTest(path=path):
                target = self.directory / path
                before = target.read_bytes()
                target.chmod(0o600)
                target.write_bytes(before + b"altered")
                self.check()
                target.write_bytes(before)

    def test_missing_and_extra_retained_files_are_rejected(self):
        self.fixture()
        target = self.directory / "attempts/000/output/lookahead.csv"
        target.unlink()
        self.check()
        self.save()
        (self.directory / "unexpected.csv").write_bytes(csv_bytes())
        self.check()

    def test_missing_worker_is_not_clean_even_with_clean_csv(self):
        self.fixture()
        key = "attempts/000/output/worker-result.json"
        (self.directory / key).unlink()
        self.buffers.pop(key)
        self.refresh_inventory()
        self.save()
        self.check()

    def test_omitted_execution_log_is_rejected_even_when_inventory_is_rewritten(self):
        self.fixture()
        key = "attempts/000/stdout.log"
        (self.directory / key).unlink()
        self.buffers.pop(key)
        self.refresh_inventory()
        self.save()
        self.check()

    def test_configuration_declaration_must_match_captured_request(self):
        self.fixture()
        self.manifest["request"]["targeted_trade_amount"] = 9
        self.save()
        self.check()

    def test_command_cannot_claim_another_engine_or_network_boundary(self):
        self.fixture()
        original = copy.deepcopy(self.manifest)
        for replace in ((IMAGE, "sha256:" + "b" * 64), ("none", "host")):
            with self.subTest(replace=replace):
                self.manifest = copy.deepcopy(original)
                argv = self.manifest["attempts"][0]["argv"]
                argv[argv.index(replace[0])] = replace[1]
                self.save()
                self.check()

    def test_effective_configuration_and_market_metadata_remain_bound(self):
        self.fixture()
        for path in ("attempts/000/output/effective-config.json", "attempts/000/output/market-metadata.json"):
            with self.subTest(path=path):
                original = self.buffers[path]
                self.buffers[path] = b'{"replaced":true}\n'
                self.refresh_inventory()
                self.save()
                self.check()
                self.buffers[path] = original

    def test_claimed_observed_environment_must_match_worker_receipt(self):
        self.fixture()
        self.manifest["attempts"][0]["environment"]["observed"]["python"] = "changed runtime"
        self.save()
        self.check()

    def test_missing_csv_is_accounted_without_false_clean(self):
        self.fixture(("MISSING_OUTPUT",))
        report = self.check()
        self.assertEqual(report["summary"]["outcome_counts"]["MISSING_OUTPUT"], 1)

    def test_worker_claim_must_agree_with_captured_inputs(self):
        self.fixture()
        key = "attempts/000/output/worker-result.json"
        original = json.loads(self.buffers[key])
        for field, value in (("request_sha256", "f" * 64), ("input_inventory", [])):
            with self.subTest(field=field):
                worker = copy.deepcopy(original)
                worker[field] = value
                self.buffers[key] = json_bytes(worker)
                self.refresh_inventory()
                self.save()
                self.check()

    def test_worker_engine_revision_and_source_identity_are_required(self):
        self.fixture()
        key = "attempts/000/output/worker-result.json"
        original = json.loads(self.buffers[key])
        for field, value in (("version", "2026.7"), ("revision", "f" * 40), ("source_sha256", "f" * 64)):
            with self.subTest(field=field):
                worker = copy.deepcopy(original)
                worker["engine"][field] = value
                self.buffers[key] = json_bytes(worker)
                self.refresh_inventory()
                self.save()
                self.check()

    def test_stale_wrong_strategy_and_duplicate_csv_rows_are_rejected(self):
        self.fixture()
        key = "attempts/000/output/lookahead.csv"
        for raw in (csv_bytes("PreviousStrategy"), csv_bytes() + csv_bytes().split(b"\r\n", 1)[1]):
            with self.subTest(raw=raw):
                self.buffers[key] = raw
                self.refresh_inventory()
                self.save()
                self.check()

    def test_clean_csv_cannot_override_nonzero_exit(self):
        self.fixture()
        self.manifest["attempts"][0]["exit_code"] = 1
        self.save()
        self.check()

    def test_summary_is_recomputed_instead_of_trusted(self):
        self.fixture(("FINDINGS_REPORTED",))
        self.manifest["summary"]["status"] = "NO_FINDINGS_REPORTED"
        self.manifest["summary"]["findings_count"] = 0
        self.save()
        self.check()

    def test_duplicate_inventory_and_unsafe_paths_are_rejected(self):
        self.fixture()
        original = copy.deepcopy(self.manifest)
        for path in ("../outside", "/tmp/outside", "attempts//000/output", "./output"):
            with self.subTest(path=path):
                self.manifest = copy.deepcopy(original)
                self.manifest["artifacts"][0]["path"] = path
                self.save()
                self.check()
        self.manifest = original
        self.manifest["artifacts"].append(copy.deepcopy(self.manifest["artifacts"][0]))
        self.save()
        self.check()

    def test_symlink_file_and_symlink_parent_cannot_substitute_artifacts(self):
        self.fixture()
        target = self.directory / "attempts/000/output/lookahead.csv"
        outside = self.root / "outside.csv"
        outside.write_bytes(target.read_bytes())
        target.unlink()
        target.symlink_to(outside)
        self.check()
        target.unlink()
        target.write_bytes(outside.read_bytes())
        original = self.directory / "attempts/000/output"
        moved = self.root / "outside-output"
        original.rename(moved)
        original.symlink_to(moved, target_is_directory=True)
        self.check()

    def test_special_file_is_rejected_without_blocking(self):
        self.fixture()
        target = self.directory / "attempts/000/stderr.log"
        target.unlink()
        os.mkfifo(target)
        self.check()

    def test_malformed_private_manifest_is_not_echoed(self):
        self.fixture()
        for raw in (b'{"secret_value":', b'{"schema":"x","schema":"y"}', b'{"value":NaN}', b"[" * 2000):
            with self.subTest(raw=raw[:30]):
                (self.directory / "manifest.json").write_bytes(raw)
                report = self.check()
                self.assertNotIn("secret_value", json.dumps(report))
                self.assertNotIn(str(self.root), json.dumps(report))


class WorkerClassificationTests(unittest.TestCase):
    def setUp(self):
        self.request = {"minimum_trade_amount": 5, "targeted_trade_amount": 10,
                        "strategy": "Clean", "timerange": "20260101-20260103", "fee": 0.001,
                        "input_inventory": [inventory_entry("config.json", b"{}\n")]}
        self.raw_request = json_bytes(self.request)
        self.worker = worker_receipt("Clean", self.raw_request, self.request)

    def classify(self, csv_raw=None):
        return classify_worker(self.worker, csv_bytes() if csv_raw is None else csv_raw,
                               "Clean", self.request, self.request["input_inventory"], self.raw_request)

    def test_clean_control_and_deliberate_leakage_control(self):
        self.assertEqual(self.classify(), "NO_FINDINGS_REPORTED")
        self.worker = worker_receipt("Clean", self.raw_request, self.request, finding=True)
        self.assertEqual(self.classify(csv_bytes(finding=True)), "FINDINGS_REPORTED")

    def test_failed_bias_check_blocks_a_clean_csv(self):
        self.worker["analysis"]["failed_bias_check"] = True
        self.assertEqual(self.classify(), "INSUFFICIENT")

    def test_positive_signal_count_and_minimum_are_required(self):
        for signals in (0, 5, 11):
            with self.subTest(signals=signals):
                self.assertEqual(self.classify(csv_bytes(signals=signals)), "INVALID_OUTPUT")

    def test_worker_and_csv_findings_must_agree(self):
        self.assertEqual(self.classify(csv_bytes(finding=True)), "INVALID_OUTPUT")

    def test_input_receipt_digest_alone_is_not_sufficient(self):
        self.worker["input_inventory"] = []
        self.assertEqual(self.classify(), "INPUT_CHANGED")

    def test_malformed_worker_subobjects_return_safe_invalid_result(self):
        for field in ("engine", "analysis"):
            for supplied in (None, [], "private untrusted detail", 2):
                with self.subTest(field=field, supplied=supplied):
                    self.worker = worker_receipt("Clean", self.raw_request, self.request)
                    self.worker[field] = supplied
                    self.assertEqual(self.classify(), "INVALID_OUTPUT")

    def test_runtime_identity_cannot_be_missing_or_malformed(self):
        for supplied in (None, {}, [], {"uid": 0}, {"python": "unit", "platform": "unit", "machine": "unit", "uid": 1000, "packages": "missing"}):
            with self.subTest(supplied=supplied):
                self.worker = worker_receipt("Clean", self.raw_request, self.request)
                self.worker["environment"] = supplied
                self.assertEqual(self.classify(), "INVALID_OUTPUT")

    def test_engine_source_inventory_and_after_run_identity_must_match_pin(self):
        for field, value in (("source_after_sha256", "f" * 64), ("source_files", [])):
            with self.subTest(field=field):
                self.worker = worker_receipt("Clean", self.raw_request, self.request)
                self.worker["engine"][field] = value
                self.assertEqual(self.classify(), "INVALID_OUTPUT")
        self.worker = worker_receipt("Clean", self.raw_request, self.request)
        self.worker["engine"]["source_files"][0]["sha256"] = "f" * 64
        self.assertEqual(self.classify(), "INVALID_OUTPUT")


class RunnerBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = generate_fixture(self.root / "source")
        self.selected = {name: self.source / "strategies" / (name + ".py")
                         for name in ("N170Clean", "N170Biased")}
        self.data = self.source / "data" / "BTC_USDT-5m.json"
        self.destination = self.root / "run"

    def run_fixture(self, scripted=None, **overrides):
        settings = {"image": IMAGE, "strategies": self.selected, "data": self.data,
                    "acknowledge_local_code": True}
        settings.update(overrides)
        scripted = scripted or ScriptedExecution({"N170Biased": "FINDINGS_REPORTED"})
        with patch.object(runner, "_image_identity", return_value=image_identity()), patch.object(runner, "_execute", side_effect=scripted):
            return runner.run_freqtrade(self.destination, **settings)

    def test_selected_clean_and_finding_attempts_produce_complete_receipt(self):
        manifest = self.run_fixture()
        self.assertEqual(manifest["summary"]["status"], "FINDINGS_REPORTED")
        self.assertEqual([a["strategy"] for a in manifest["attempts"]], list(self.selected))
        self.assertEqual([a["outcome"] for a in manifest["attempts"]], ["NO_FINDINGS_REPORTED", "FINDINGS_REPORTED"])
        self.assertEqual(verify_run(self.destination)["status"], "FINDINGS_REPORTED")
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o700)
        self.assertEqual(json.loads((self.destination / "manifest.json").read_bytes()), manifest)

    def test_every_run_is_exclusive_and_old_bytes_are_preserved(self):
        self.run_fixture()
        before = {p.relative_to(self.destination): p.read_bytes() for p in self.destination.rglob("*") if p.is_file()}
        with self.assertRaises(FileExistsError):
            self.run_fixture()
        after = {p.relative_to(self.destination): p.read_bytes() for p in self.destination.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_no_strategy_is_imported_before_explicit_local_opt_in(self):
        marker = self.root / "must-not-exist"
        self.selected["N170Clean"].write_text(f"raise RuntimeError({str(marker)!r})\n")
        with self.assertRaises(ValueError), patch.object(runner, "_execute") as execute:
            self.run_fixture(acknowledge_local_code=False)
        execute.assert_not_called()
        self.assertFalse(marker.exists())
        self.assertFalse(self.destination.exists())

    def test_configuration_environment_and_resource_bounds_are_explicit(self):
        scripted = ScriptedExecution()
        with patch.dict(os.environ, {"FREQTRADE__EXCHANGE__KEY": "private-secret", "HTTP_PROXY": "private-proxy"}):
            manifest = self.run_fixture(scripted)
            docker_env = runner._docker_env()
        self.assertNotIn("FREQTRADE__EXCHANGE__KEY", docker_env)
        self.assertNotIn("HTTP_PROXY", docker_env)
        for argv, settings in scripted.calls:
            self.assertIsInstance(argv, list)
            self.assertIn(IMAGE, argv)
            for option, value in (("--network", "none"), ("--pull", "never"), ("--cap-drop", "ALL"),
                                  ("--security-opt", "no-new-privileges"), ("--user", "1000:1000"),
                                  ("--memory", "1g"), ("--memory-swap", "1g"), ("--pids-limit", "64"),
                                  ("--cpus", "1"), ("--entrypoint", "python")):
                self.assertEqual(argv[argv.index(option) + 1], value)
            self.assertIn("--read-only", argv)
            self.assertTrue(argv[argv.index("--mount") + 1].endswith(",dst=/input,readonly"))
            self.assertEqual(settings["timeout_seconds"], 120)
        self.assertNotIn("private-secret", json.dumps(manifest))

    def test_changed_original_source_and_data_do_not_change_captured_inputs(self):
        original_source = self.selected["N170Clean"].read_bytes()
        original_data = self.data.read_bytes()

        def substitute_original(_staged, _request):
            self.selected["N170Clean"].write_bytes(b"# replaced after capture\n")
            self.data.write_bytes(b"[]")

        self.run_fixture(ScriptedExecution(mutate=substitute_original))
        staged = self.destination / "attempts/000/input"
        self.assertEqual((staged / "strategies/N170Clean.py").read_bytes(), original_source)
        self.assertEqual((staged / "data/BTC_USDT-5m.json").read_bytes(), original_data)
        self.assertEqual((self.destination / "attempts/001/input/data/BTC_USDT-5m.json").read_bytes(), original_data)
        self.assertEqual(verify_run(self.destination)["status"], "NO_FINDINGS_REPORTED")

    def test_staged_input_mutation_is_detected_after_execution(self):
        def corrupt_staged(staged, _request):
            path = staged / "config.json"
            path.chmod(0o600)
            path.write_bytes(path.read_bytes() + b" ")

        manifest = self.run_fixture(ScriptedExecution(mutate=corrupt_staged))
        self.assertEqual(manifest["summary"]["status"], "NOT_ASSESSABLE")
        self.assertTrue(all(a["outcome"] == "INPUT_CHANGED" for a in manifest["attempts"]))
        self.assertEqual(verify_run(self.destination)["status"], "NOT_ASSESSABLE")

    def test_input_symlink_and_parent_symlink_are_rejected_before_engine(self):
        link = self.root / "link.py"
        link.symlink_to(self.selected["N170Clean"])
        linked_parent = self.root / "linked-strategies"
        linked_parent.symlink_to(self.source / "strategies", target_is_directory=True)
        for path in (link, linked_parent / "N170Clean.py"):
            with self.subTest(path=path), self.assertRaises((OSError, ValueError)):
                self.run_fixture(strategies={"N170Clean": path})
        self.assertFalse(self.destination.exists())

    def test_unsupported_names_and_limits_are_rejected_before_launch(self):
        cases = [
            {"strategies": {"Bad;touch injected": self.selected["N170Clean"]}},
            {"strategies": {}}, {"timeout_seconds": 0}, {"timeout_seconds": 601},
            {"timeout_seconds": True}, {"minimum_trade_amount": 10, "targeted_trade_amount": 10},
            {"targeted_trade_amount": 101}, {"timerange": "20260101; echo secret"},
        ]
        for settings in cases:
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                self.run_fixture(**settings)
        self.assertFalse(self.destination.exists())

    def test_timeout_keeps_full_accounting_and_other_findings(self):
        manifest = self.run_fixture(ScriptedExecution({"N170Clean": "TIMED_OUT", "N170Biased": "FINDINGS_REPORTED"}))
        self.assertEqual([a["outcome"] for a in manifest["attempts"]], ["TIMED_OUT", "FINDINGS_REPORTED"])
        self.assertEqual(manifest["summary"]["status"], "NOT_ASSESSABLE")
        self.assertEqual(manifest["summary"]["findings_count"], 1)

    def test_cancellation_marks_unstarted_selection_skipped(self):
        manifest = self.run_fixture(ScriptedExecution({"N170Clean": "CANCELLED"}))
        self.assertEqual([a["outcome"] for a in manifest["attempts"]], ["CANCELLED", "SKIPPED"])
        self.assertEqual(manifest["summary"]["status"], "NOT_ASSESSABLE")
        self.assertEqual(len(manifest["attempts"]), 2)

    def test_unconfirmed_container_cleanup_is_retained_and_stops_remaining_attempts(self):
        underlying = ScriptedExecution({"N170Clean": "TIMED_OUT"})

        def unconfirmed(*args, **kwargs):
            result = underlying(*args, **kwargs)
            result["cleanup_confirmed"] = False
            return result

        manifest = self.run_fixture(unconfirmed)
        self.assertEqual([a["outcome"] for a in manifest["attempts"]], ["TIMED_OUT", "SKIPPED"])
        self.assertIn("CONTAINER_CLEANUP_UNCONFIRMED", manifest["attempts"][0]["reason_codes"])
        self.assertEqual(manifest["summary"]["status"], "NOT_ASSESSABLE")
        self.assertEqual(len(underlying.calls), 1)

    def test_keyboard_interrupt_finishes_receipt_and_cleans_container(self):
        with patch.object(runner, "_image_identity", return_value=image_identity()), \
                patch.object(runner, "_execute", side_effect=KeyboardInterrupt), \
                patch.object(runner, "_cleanup_container", return_value=True) as cleanup:
            manifest = runner.run_freqtrade(self.destination, image=IMAGE, strategies=self.selected,
                                            data=self.data, acknowledge_local_code=True)
        cleanup.assert_called_once()
        self.assertEqual([a["outcome"] for a in manifest["attempts"]], ["CANCELLED", "SKIPPED"])
        self.assertEqual(json.loads((self.destination / "manifest.json").read_bytes())["state"], "FINALIZED")

    def test_failure_with_clean_csv_cannot_be_clean(self):
        manifest = self.run_fixture(ScriptedExecution({"N170Clean": "FAILED"}))
        self.assertEqual(manifest["attempts"][0]["outcome"], "FAILED")
        self.assertEqual(manifest["summary"]["status"], "NOT_ASSESSABLE")
        self.assertTrue((self.destination / "attempts/000/output/lookahead.csv").exists())

    def test_missing_or_malformed_result_envelope_cannot_be_clean(self):
        for index, stdout in enumerate((b"engine emitted no bundle\n", runner.BUNDLE_PREFIX + b"bad base64\n")):
            def missing(_argv, *, stdout_path, stderr_path, **_kwargs):
                stdout_path.write_bytes(stdout)
                stderr_path.write_bytes(b"")
                return {"exit_code": 0, "termination": None, "stdout": stdout}
            with self.subTest(stdout=stdout):
                self.destination = self.root / f"missing-{index}"
                manifest = self.run_fixture(missing)
                self.assertEqual(manifest["summary"]["status"], "NOT_ASSESSABLE")
                self.assertEqual([a["outcome"] for a in manifest["attempts"]],
                                 ["MISSING_OUTPUT" if index == 0 else "INVALID_OUTPUT"] * 2)

    def test_malformed_worker_object_is_retained_as_safe_finalized_failure(self):
        for index, malformed in enumerate(([], {"offline_adapter": None}, {"engine": []})):
            underlying = ScriptedExecution()

            def malformed_result(*args, **kwargs):
                result = underlying(*args, **kwargs)
                encoded = result["stdout"].split(runner.BUNDLE_PREFIX, 1)[1].strip()
                files = json.loads(base64.b64decode(encoded))
                worker = json.loads(base64.b64decode(files["worker-result.json"]))
                if isinstance(malformed, dict):
                    worker.update(malformed)
                else:
                    worker = malformed
                files["worker-result.json"] = base64.b64encode(json_bytes(worker)).decode()
                result["stdout"] = runner.BUNDLE_PREFIX + base64.b64encode(json_bytes(files)) + b"\n"
                kwargs["stdout_path"].write_bytes(result["stdout"])
                return result

            with self.subTest(malformed=malformed):
                self.destination = self.root / f"malformed-object-{index}"
                manifest = self.run_fixture(malformed_result)
                self.assertEqual(manifest["state"], "FINALIZED")
                self.assertEqual(manifest["summary"]["status"], "NOT_ASSESSABLE")

    def test_image_preparation_failure_leaves_honest_skipped_receipt(self):
        with patch.object(runner, "_image_identity", side_effect=OSError("private-daemon-detail")), \
                patch.object(runner, "_execute") as execute:
            manifest = runner.run_freqtrade(self.destination, image=IMAGE, strategies=self.selected,
                                            data=self.data, acknowledge_local_code=True)
        execute.assert_not_called()
        self.assertEqual([a["outcome"] for a in manifest["attempts"]], ["SKIPPED", "SKIPPED"])
        self.assertEqual(manifest["summary"]["status"], "NOT_ASSESSABLE")
        self.assertNotIn("private-daemon-detail", json.dumps(manifest))


class SubprocessResourceBoundaryTests(unittest.TestCase):
    """Exercise real bounded Python child I/O; no container or strategy execution."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def execute(self, code, *, timeout=2, cancellation=None):
        return runner._execute([sys.executable, "-E", "-S", "-c", code],
                               stdout_path=self.root / "stdout.log", stderr_path=self.root / "stderr.log",
                               timeout_seconds=timeout, docker="docker-unit-fixture",
                               container_name="n170-unit-fixture", cancel_event=cancellation)

    def test_drains_stdout_stderr_and_retains_nonzero_exit(self):
        result = self.execute("import sys; print('stdout'); print('stderr', file=sys.stderr); sys.exit(7)")
        self.assertEqual(result["exit_code"], 7)
        self.assertIsNone(result["termination"])
        self.assertEqual(result["stdout"], b"stdout\n")
        self.assertEqual((self.root / "stderr.log").read_bytes(), b"stderr\n")
        self.assertEqual((self.root / "stdout.log").stat().st_mode & 0o777, 0o600)

    def test_wall_timeout_cleans_container_and_kills_child(self):
        with patch.object(runner, "_cleanup_container", return_value=True) as cleanup:
            result = self.execute("import time; time.sleep(30)", timeout=0.05)
        cleanup.assert_called_once_with("docker-unit-fixture", "n170-unit-fixture")
        self.assertEqual(result["termination"], "TIMED_OUT")
        self.assertIsNotNone(result["exit_code"])

    def test_wall_timeout_still_applies_after_both_output_pipes_close(self):
        with patch.object(runner, "_cleanup_container", return_value=True) as cleanup:
            result = self.execute("import os,time; os.close(1); os.close(2); time.sleep(0.3)", timeout=0.05)
        self.assertEqual(result["termination"], "TIMED_OUT")
        cleanup.assert_called_once()

    def test_cancel_event_cleans_container_and_kills_child(self):
        event = threading.Event()
        event.set()
        with patch.object(runner, "_cleanup_container", return_value=True) as cleanup:
            result = self.execute("import time; time.sleep(30)", cancellation=event)
        cleanup.assert_called_once()
        self.assertEqual(result["termination"], "CANCELLED")

    def test_combined_log_limit_is_enforced_and_cleans_container(self):
        with patch.object(runner, "LOG_LIMIT", 128), patch.object(runner, "_cleanup_container", return_value=True) as cleanup:
            result = self.execute("import sys; sys.stdout.write('x' * 10000); sys.stdout.flush()")
        cleanup.assert_called_once()
        self.assertEqual(result["termination"], "OUTPUT_LIMIT")
        retained = sum((self.root / filename).stat().st_size for filename in ("stdout.log", "stderr.log"))
        self.assertLessEqual(retained, 128)

    def test_process_start_failure_is_fixed_outcome_with_no_secret_echo(self):
        with patch.object(runner.subprocess, "Popen", side_effect=OSError("secret private error")), \
                patch.object(runner, "_cleanup_container", return_value=True) as cleanup:
            result = self.execute("pass")
        self.assertEqual(result["termination"], "PROCESS_ERROR")
        self.assertEqual(result["stdout"], b"")
        cleanup.assert_called_once()
        self.assertNotIn("secret", (self.root / "stderr.log").read_text())


if __name__ == "__main__":
    unittest.main()
