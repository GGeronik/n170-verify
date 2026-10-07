"""Exercise the actual public CLI, disclosure and isolated source distribution."""
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from verify_toolkit.__main__ import main
from verify_toolkit.conformance import CLEAN, HEADER, run_conformance
from verify_toolkit.freqtrade import assess_lookahead
from verify_toolkit.packaging import FILES, package_source, _source_bytes
from verify_toolkit.reporting import render_html, report_for_sharing


class ToolkitDeliveryTests(unittest.TestCase):
    def invoke(self, *args):
        stream = io.StringIO()
        with redirect_stdout(stream):
            code = main(list(map(str, args)))
        return code, json.loads(stream.getvalue())

    def test_default_export_omits_private_research_labels(self):
        source = HEADER + "private-file.py,PrivateStrategy,True,24,1,0,private_signal\n"
        assessment = assess_lookahead(source)
        shared = report_for_sharing(assessment)
        encoded = json.dumps(shared)
        for private in ("private-file.py", "PrivateStrategy", "private_signal"):
            self.assertNotIn(private, encoded)
        self.assertEqual(shared["scope"]["source_sha256"], hashlib.sha256(source.encode()).hexdigest())
        self.assertEqual(assessment["rows"][0]["strategy"], "PrivateStrategy")
        self.assertEqual(report_for_sharing(assessment, include_labels=True)["rows"][0]["strategy"], "PrivateStrategy")

    def test_actual_cli_preserves_source_digest_and_writes_safe_reading_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, out, html = root / "source.csv", root / "report.json", root / "report.html"
            raw = ("\ufeff" + HEADER + CLEAN).replace("\n", "\r\n").encode()
            source.write_bytes(raw)
            code, report = self.invoke("freqtrade-lookahead", source, "--synthetic-example", "--output", out, "--html", html)
            self.assertEqual(code, 0)
            self.assertEqual(report["scope"]["source_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(json.loads(out.read_text()), report)
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)
            page = html.read_text()
            self.assertIn("not an account-performance credential", page)
            self.assertIn("Whole-run coverage", page)
            self.assertIn("Synthetic demonstration", page)
            self.assertNotIn("<script", page)
            self.assertNotIn("Example", page)
            before = out.read_bytes()
            code, _ = self.invoke("freqtrade-lookahead", source, "--output", out)
            self.assertEqual(code, 2)
            self.assertEqual(out.read_bytes(), before)

    def test_html_escapes_every_supplied_text_surface(self):
        payload = "</pre><script>alert('test')</script>"
        report = report_for_sharing(assess_lookahead(HEADER + CLEAN))
        report["rows"][0]["display_label"] = payload
        report["reason_codes"].append(payload)
        report["limitations"].append(payload)
        report["scope"]["test"] = payload
        html = render_html(report)
        self.assertNotIn(payload, html)
        self.assertNotIn("<script", html)
        self.assertIn("&lt;script&gt;", html)

    def test_duplicate_context_and_private_parse_errors_are_not_echoed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, context = root / "private-name.csv", root / "context.json"
            source.write_text(HEADER + CLEAN)
            for content in ('{"run_status":"FAILED","run_status":"COMPLETED"}',
                            '{"private_secret":"do-not-print"', '[' * 2000):
                context.write_text(content)
                code, report = self.invoke("freqtrade-lookahead", source, "--context", context)
                self.assertEqual(code, 2)
                self.assertNotIn("do-not-print", json.dumps(report))
                self.assertNotIn(str(root), json.dumps(report))

    def test_file_boundaries_fail_closed_without_blocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "data.csv"
            source.write_text(HEADER + CLEAN)
            link = root / "link.csv"
            link.symlink_to(source)
            fifo = root / "pipe.csv"
            os.mkfifo(fifo)
            oversized = root / "large.csv"
            oversized.write_bytes(b"x" * 1_048_577)
            invalid = root / "invalid.csv"
            invalid.write_bytes(b"\xff\xff")
            for path in (link, fifo, oversized, invalid, root / "missing.csv"):
                self.assertEqual(self.invoke("freqtrade-lookahead", path)[0], 2)

    def test_cli_accepts_same_supported_csv_byte_budget_as_library(self):
        # Significant valid whitespace is retained for hashing, then normalized
        # per cell. This exercises the former 1,000,000-vs-1MiB boundary gap.
        source_text = HEADER + "".join("example.py" + " " * 1000 + f",S{i},False,24,0,0,\n" for i in range(1000))
        self.assertGreater(len(source_text.encode()), 1_000_000)
        self.assertLessEqual(len(source_text.encode()), 1_048_576)
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "large-valid.csv"
            source.write_text(source_text)
            code, report = self.invoke("freqtrade-lookahead", source)
            self.assertEqual(code, 0)
            self.assertEqual(report["tested_strategy_count"], 1000)

    def test_conformance_has_positive_and_negative_controls(self):
        result = run_conformance()
        self.assertFalse(result["unexpected_results"])
        self.assertEqual({row["expected"] for row in result["cases"]},
                         {"NO_FINDINGS_REPORTED", "FINDINGS_REPORTED", "NOT_ASSESSABLE"})

    def test_allowlisted_package_reproduces_in_clean_stdlib_only_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, second = root / "first.zip", root / "second.zip"
            a, b = package_source(first), package_source(second)
            self.assertEqual(a["archive_sha256"], b["archive_sha256"])
            with self.assertRaises(FileExistsError):
                package_source(first)
            extracted = root / "independent"
            with zipfile.ZipFile(first) as archive:
                expected = {"MANIFEST.json", *("verify_toolkit/" + name for name in FILES)}
                self.assertEqual(set(archive.namelist()), expected)
                manifest = json.loads(archive.read("MANIFEST.json"))
                for name, value in manifest["files"].items():
                    self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(), value["sha256"])
                archive.extractall(extracted)
            process = subprocess.run([sys.executable, "-E", "-S", "-B", "-m", "verify_toolkit", "self-test"],
                                     cwd=extracted, text=True, capture_output=True, timeout=30)
            self.assertEqual(process.returncode, 0, process.stderr)
            result = json.loads(process.stdout)
            self.assertFalse(result["unexpected_results"])

    def test_package_source_rejects_symlinked_files_and_parents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / "outside"
            outside.mkdir()
            (outside / "private.txt").write_text("private")
            source = root / "source"
            source.mkdir()
            (source / "file").symlink_to(outside / "private.txt")
            (source / "parent").symlink_to(outside, target_is_directory=True)
            fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for path in ("file", "parent/private.txt"):
                    with self.assertRaises(OSError):
                        _source_bytes(fd, path)
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
