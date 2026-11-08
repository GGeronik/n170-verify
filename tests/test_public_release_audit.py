from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "public_release_audit",
    ROOT / "scripts" / "public_release_audit.py",
)
assert SPEC and SPEC.loader
audit = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = audit
SPEC.loader.exec_module(audit)


class PublicReleaseAuditTests(unittest.TestCase):
    def audit_tree(self, root: Path, *, require_license: bool = False):
        entries, initial = audit._tree_entries(root)
        return audit.audit_release(
            root,
            entries,
            initial_findings=initial,
            require_license=require_license,
        )

    def test_clean_source_and_example_environment_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "README.md").write_text("prototype source\n", encoding="utf-8")
            (root / ".env.example").write_text("EODHD_API_KEY=\n", encoding="utf-8")
            self.assertEqual(self.audit_tree(root), [])

    def test_private_artifacts_and_secret_are_blocked_without_echoing_value(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            secret = "sk_" + "test_" + "A" * 24
            (root / ".env").write_text(f"STRIPE_SECRET_KEY={secret}\n", encoding="utf-8")
            (root / "runtime.db").write_bytes(b"sqlite")
            (root / "results").mkdir()
            (root / "results" / "portfolio.csv").write_text("private", encoding="utf-8")
            findings = self.audit_tree(root)
            rendered = "\n".join(f"{item.path}:{item.rule}" for item in findings)
            self.assertIn("environment-file", rendered)
            self.assertIn("stripe-secret", rendered)
            self.assertIn("runtime-secret-or-model-artifact", rendered)
            self.assertIn("generated-or-private-directory:results", rendered)
            self.assertNotIn(secret, rendered)

    def test_root_data_is_blocked_even_when_a_filename_says_sample(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root / "data"
            data.mkdir()
            (data / "XAUUSD_5m_sample.csv").write_text("synthetic\n", encoding="utf-8")
            (data / "ibkr-flex-export.xml").write_text("<FlexQueryResponse />", encoding="utf-8")
            rules = {finding.rule for finding in self.audit_tree(root)}
            self.assertIn("unapproved-root-data", rules)
            self.assertIn("broker-export", rules)

    def test_only_exact_reviewed_broker_fixture_path_and_content_are_allowed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            relative = Path("tests/fixtures/import/ibkr-flex-synthetic.csv")
            target = root / relative
            target.parent.mkdir(parents=True)
            shutil.copyfile(ROOT / relative, target)

            self.assertEqual(self.audit_tree(root), [])

    def test_modified_reviewed_broker_fixture_is_blocked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            relative = Path("tests/fixtures/import/ibkr-flex-synthetic.csv")
            target = root / relative
            target.parent.mkdir(parents=True)
            shutil.copyfile(ROOT / relative, target)
            target.write_bytes(target.read_bytes() + b"\n")

            self.assertIn(
                audit.Finding(relative.as_posix(), "reviewed-broker-fixture-integrity"),
                self.audit_tree(root),
            )

    def test_reviewed_broker_fixture_copied_to_another_path_is_blocked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            relative = Path("tests/fixtures/ibkr-flex-copy.csv")
            target = root / relative
            target.parent.mkdir(parents=True)
            shutil.copyfile(ROOT / "tests/fixtures/import/ibkr-flex-synthetic.csv", target)

            self.assertIn(
                audit.Finding(relative.as_posix(), "broker-export"),
                self.audit_tree(root),
            )

    def test_pinned_release_archives_pass_while_unapproved_or_altered_zips_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pinned = Path("release-assets/private-source-challenge/accepted-offline-toolkit.zip")
            target = root / pinned
            target.parent.mkdir(parents=True)
            shutil.copyfile(ROOT / pinned, target)
            self.assertEqual(self.audit_tree(root), [])

            target.write_bytes(target.read_bytes() + b"tamper")
            self.assertIn(
                audit.Finding(pinned.as_posix(), "reviewed-release-archive-integrity"),
                self.audit_tree(root),
            )
            shutil.copyfile(ROOT / pinned, target)

            rogue = root / "unapproved-bundle.zip"
            with zipfile.ZipFile(rogue, "w") as zf:
                zf.writestr("note.txt", "unreviewed archive")
            self.assertIn(
                audit.Finding("unapproved-bundle.zip", "unapproved-binary-file"),
                self.audit_tree(root),
            )

    def test_flex_export_renamed_sample_is_blocked_by_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "portfolio_sample.xml"
            target.write_text(
                '<FlexQueryResponse><FlexStatement accountId="real-account" /></FlexQueryResponse>\n',
                encoding="utf-8",
            )

            self.assertIn(
                audit.Finding("portfolio_sample.xml", "broker-export"),
                self.audit_tree(root),
            )

    def test_license_gate_is_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "README.md").write_text("source\n", encoding="utf-8")
            self.assertIn("missing-root-license", {item.rule for item in self.audit_tree(root, require_license=True)})
            (root / "LICENSE").write_text("Apache-2.0\n", encoding="utf-8")
            self.assertEqual(self.audit_tree(root, require_license=True), [])

    def test_hard_coded_home_path_is_blocked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private_path = "/" + "Users/example/private/"
            (root / "config.py").write_text(f'ROOT = "{private_path}"\n', encoding="utf-8")
            self.assertIn("hard-coded-home-path", {item.rule for item in self.audit_tree(root)})

    def test_git_worktree_pointer_file_is_skipped(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worktree_gitdir = "/" + "Users/example/worktrees/repo/.git/worktrees/branch"
            (root / ".git").write_text(f"gitdir: {worktree_gitdir}\n", encoding="utf-8")
            (root / "README.md").write_text("clean worktree checkout\n", encoding="utf-8")
            self.assertEqual(self.audit_tree(root), [])

    def test_directory_symlinks_are_blocked_without_following_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root.parent / f"{root.name}-outside"
            outside.mkdir()
            try:
                (outside / "private.txt").write_text("do not traverse\n", encoding="utf-8")
                (root / "linked-directory").symlink_to(outside, target_is_directory=True)
                findings = self.audit_tree(root)
                self.assertIn(
                    audit.Finding("linked-directory", "symbolic-link"),
                    findings,
                )
                self.assertFalse(any("private.txt" in finding.path for finding in findings))
            finally:
                (outside / "private.txt").unlink()
                outside.rmdir()

    def test_oversized_files_fail_closed_instead_of_skipping_secret_scan(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "large.txt").write_bytes(b"x" * (audit.MAX_TEXT_BYTES + 1))
            self.assertIn(
                audit.Finding("large.txt", "oversized-release-file"),
                self.audit_tree(root),
            )

    def test_generated_build_and_egg_info_directories_are_blocked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in ("build/output.txt", "dist/bundle.js", "src/example.egg-info/PKG-INFO"):
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("generated\n", encoding="utf-8")
            rendered = {(item.path, item.rule) for item in self.audit_tree(root)}
            self.assertTrue(any(rule.endswith(":build") for _, rule in rendered))
            self.assertTrue(any(rule.endswith(":dist") for _, rule in rendered))
            self.assertTrue(any(rule.endswith(":example.egg-info") for _, rule in rendered))

    def test_unknown_or_disguised_binary_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "payload.bin").write_bytes(b"\x00private material")
            (root / "fake.png").write_bytes(b"\x00not actually a png")
            findings = self.audit_tree(root)
            self.assertIn(audit.Finding("payload.bin", "unapproved-binary-file"), findings)
            self.assertIn(audit.Finding("fake.png", "unapproved-binary-file"), findings)

    def test_small_known_binary_asset_signature_is_allowed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "icon.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"synthetic")
            self.assertEqual(self.audit_tree(root), [])

    def test_tracked_mode_reads_only_git_index(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
            (root / "safe.py").write_text("VALUE = 1\n", encoding="utf-8")
            (root / ".env").write_text("LOCAL_ONLY=yes\n", encoding="utf-8")
            subprocess.run(["git", "add", "safe.py"], cwd=root, check=True)

            self.assertEqual(audit._tracked_entries(root), [("safe.py", False)])

    def test_root_data_and_well_known_gitignore_rules(self):
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("/data/", gitignore.splitlines())
        self.assertNotIn("data/", gitignore.splitlines())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
            (root / ".gitignore").write_text(gitignore, encoding="utf-8")
            (root / "data").mkdir()
            (root / "data" / "private.csv").write_text("private\n", encoding="utf-8")
            package = root / "core" / "n170_verify" / "reference"
            package.mkdir(parents=True)
            (package / "base.py").write_text("VALUE = 1\n", encoding="utf-8")
            well_known = root / "web" / "public" / ".well-known"
            well_known.mkdir(parents=True)
            (well_known / "n170-verify-keys.json").write_text("{}\n", encoding="utf-8")
            (root / ".env.example").write_text("EODHD_API_KEY=\n", encoding="utf-8")

            self.assertEqual(
                subprocess.run(["git", "check-ignore", "--quiet", "data/private.csv"], cwd=root, check=False).returncode,
                0,
            )
            self.assertEqual(
                subprocess.run(["git", "check-ignore", "--quiet", "core/n170_verify/reference/base.py"], cwd=root, check=False).returncode,
                1,
            )
            self.assertEqual(
                subprocess.run(["git", "check-ignore", "--quiet", "web/public/.well-known/n170-verify-keys.json"], cwd=root, check=False).returncode,
                1,
            )
            self.assertEqual(
                subprocess.run(["git", "check-ignore", "--quiet", ".env.example"], cwd=root, check=False).returncode,
                1,
            )


if __name__ == "__main__":
    unittest.main()
