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
            synthetic_probe = "sk_" + "test_" + "A" * 24
            (root / ".env").write_text(f"SYNTHETIC_FIXTURE_PROBE={synthetic_probe}\n", encoding="utf-8")
            (root / "runtime.db").write_bytes(b"sqlite")
            (root / "results").mkdir()
            (root / "results" / "portfolio.csv").write_text("private", encoding="utf-8")
            findings = self.audit_tree(root)
            rendered = "\n".join(f"{item.path}:{item.rule}" for item in findings)
            self.assertIn("environment-file", rendered)
            self.assertIn("stripe-secret", rendered)
            self.assertIn("runtime-secret-or-model-artifact", rendered)
            self.assertIn("generated-or-private-directory:results", rendered)
            self.assertNotIn(synthetic_probe, rendered)

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

    # Credential-shaped inputs below are assembled at run time so that no
    # secret-shaped literal is committed and the audit does not flag this file.
    PERS = "PERS" + "-"

    @staticmethod
    def _consumer_key_shaped(length: int = 50) -> str:
        # A deterministic letters-and-digits value with no separators.
        return (("Qm7" + "xZ2" + "pL9") * (length // 9 + 1))[:length]

    def _rules_for(self, relative: str, content: str) -> tuple[set[str], str]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            findings = self.audit_tree(root)
            rendered = "\n".join(f"{item.path}:{item.rule}" for item in findings)
            return {item.rule for item in findings}, rendered

    def test_snaptrade_personal_client_id_is_blocked_in_every_issued_shape(self):
        variants = {
            "upper": self.PERS + "AB12CD34EF56GH78",
            "lower": self.PERS + "ab12cd34ef56gh78",
            "hyphenated": self.PERS + "ab12-cd34-ef56",
            "mixed-hyphenated": self.PERS + "Ab12-Cd34-Ef56-Gh78",
            "short-hyphenated": self.PERS + "a1b2-c3d4",
        }
        for label, client_id in variants.items():
            with self.subTest(label):
                rules, rendered = self._rules_for("config.py", f'CLIENT_ID = "{client_id}"\n')
                self.assertIn("snaptrade-personal-client-id", rules)
                self.assertNotIn(client_id, rendered)

    def test_snaptrade_consumer_key_assignment_is_blocked_in_common_source_forms(self):
        key = self._consumer_key_shaped(50)
        self.assertRegex(key, r"^[A-Za-z0-9]{50,}$")
        upper = "SNAPTRADE_" + "CONSUMER_KEY"
        lower = "snaptrade_" + "consumer_key"
        camel = "consumer" + "Key"
        forms = {
            "env": (".env.example", f"{upper}={key}\n"),
            "env-export": ("deploy.sh", f"export {upper}={key}\n"),
            "env-quoted": ("deploy.sh", f'{upper}="{key}"\n'),
            "python-assignment": ("settings.py", f'{lower} = "{key}"\n'),
            "python-kwarg": ("settings.py", f"build(client_id='x', consumer_key='{key}')\n"),
            "python-annotation": ("settings.py", f'    {lower}: str = "{key}"\n'),
            "python-environ": ("settings.py", f'os.environ["{upper}"] = "{key}"\n'),
            "python-dict": ("settings.py", f'env = {{"{upper}": "{key}"}}\n'),
            "json": ("config.json", f'{{"{camel}": "{key}"}}\n'),
            "yaml-quoted": ("compose.yml", f'    {upper}: "{key}"\n'),
            "yaml-unquoted": ("compose.yml", f"    {lower}: {key}\n"),
            "javascript-object": ("client.js", f"const c = {{ {camel}: '{key}' }};\n"),
            "javascript-template": ("client.js", f"const c = {{ {camel}: `{key}` }};\n"),
            "typescript-annotation": ("client.ts", f'const {camel}: string = "{key}";\n'),
            "javascript-env": ("client.mjs", f'process.env.{upper} = "{key}";\n'),
        }
        for label, (relative, content) in forms.items():
            with self.subTest(label):
                rules, rendered = self._rules_for(relative, content)
                self.assertIn("snaptrade-consumer-key", rules)
                self.assertNotIn(key, rendered)

    def test_snaptrade_consumer_key_references_and_placeholders_are_not_flagged(self):
        upper = "SNAPTRADE_" + "CONSUMER_KEY"
        lower = "snaptrade_" + "consumer_key"
        benign = {
            "empty-env": f"{upper}=\n",
            "compose-substitution": f'      {upper}: "${{{upper}:-}}"\n',
            "environ-read": f'{lower}=os.environ.get("{upper}", "").strip(),\n',
            "variable-reference": "adapter = build(consumer_key=consumer_key)\n",
            "hyphenated-placeholder": f'{lower}="snap-hmac-consumer-secret-xyz-12345",\n',
            "short-token": f'"{upper}": "N170CONSKEY",\n',
            "short-alnum": f'consumer_key="{self._consumer_key_shaped(31)}"\n',
            "underscore-placeholder": f"{upper}=your_consumer_key_here\n",
        }
        for label, content in benign.items():
            with self.subTest(label):
                rules, _ = self._rules_for("settings.py", content)
                self.assertNotIn("snaptrade-consumer-key", rules)

    def test_reviewed_synthetic_personal_client_ids_pass_only_at_their_reviewed_path(self):
        reviewed_path = "api/tests/test_launch_blockers_hyperliquid_snaptrade.py"
        fixture = self.PERS + "WORKER-" + "ISOLATION-01"
        content = f'CLIENT_ID = "{fixture}"\n'

        rules, _ = self._rules_for(reviewed_path, content)
        self.assertNotIn("snaptrade-personal-client-id", rules)

        rules, _ = self._rules_for("api/tests/test_other.py", content)
        self.assertIn("snaptrade-personal-client-id", rules)

        unreviewed = self.PERS + "ab12-cd34-ef56"
        rules, _ = self._rules_for(reviewed_path, content + f'OTHER = "{unreviewed}"\n')
        self.assertIn("snaptrade-personal-client-id", rules)

        near_miss = fixture + "X"
        rules, _ = self._rules_for(reviewed_path, f'CLIENT_ID = "{near_miss}"\n')
        self.assertIn("snaptrade-personal-client-id", rules)

    def test_snaptrade_rules_pass_on_the_tracked_files_that_hold_synthetic_fixtures(self):
        relatives = (
            "api/tests/test_launch_blockers_hyperliquid_snaptrade.py",
            "api/tests/test_snaptrade_relay.py",
            "api/tests/test_snaptrade_session_binding.py",
            "core/tests/test_connectors_and_mcp_firewall.py",
            "core/tests/test_hyperliquid_and_snaptrade_personal.py",
            "core/tests/test_phase3_connectors.py",
            "core/tests/test_snaptrade_nav_and_fx.py",
            "core/n170_verify/connectors/snaptrade.py",
            ".env.example",
            "docker-compose.yml",
        )
        findings = audit.audit_release(ROOT, [(relative, False) for relative in relatives])
        self.assertEqual(
            [item for item in findings if item.rule.startswith("snaptrade-")],
            [],
        )

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
