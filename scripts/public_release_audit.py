#!/usr/bin/env python3
"""Fail closed when a proposed N170 source release contains private artifacts.

The audit reports paths and rule names only. It never prints a matched secret.
Run against a clean Git checkout with ``--tracked`` before publishing, and add
``--require-license`` once the repository owner has selected a root license.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Iterable, Sequence


MAX_TEXT_BYTES = 8 * 1024 * 1024

SKIP_WALK_DIRS = {".git"}
PROHIBITED_DIR_NAMES = {
    ".agents",
    ".claude",
    ".codex",
    ".mypy_cache",
    ".next",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "graphify-out",
    "htmlcov",
    "node_modules",
    "quarantine",
    "results",
    "venv",
}
PROHIBITED_DIR_SUFFIXES = (".egg-info",)
PROHIBITED_FILE_NAMES = {
    ".DS_Store",
    ".env",
    "signing_key.bin",
    "id_ed25519",
    "id_rsa",
}
PROHIBITED_SUFFIXES = (
    ".db",
    ".db-shm",
    ".db-wal",
    ".jks",
    ".joblib",
    ".keystore",
    ".key",
    ".log",
    ".onnx",
    ".p12",
    ".pem",
    ".pfx",
    ".pkl",
    ".pt",
    ".pth",
    ".sqlite",
    ".sqlite3",
)

SECRET_PATTERNS = (
    ("stripe-secret", re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("private-key-block", re.compile(r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")),
    ("github-token", re.compile(r"(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})")),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_-]{30,}")),
    ("hard-coded-home-path", re.compile(r"/(?:Users|home)/[^/\s'\"]+/")),
    ("known-development-password", re.compile("neo4j/" + "n170")),
)

ALLOWED_BINARY_SIGNATURES = {
    ".gif": (b"GIF87a", b"GIF89a"),
    ".ico": (b"\x00\x00\x01\x00",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".jpg": (b"\xff\xd8\xff",),
    ".otf": (b"OTTO",),
    ".ots-header": (b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94",),
    ".pdf": (b"%PDF-",),
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".ttf": (b"\x00\x01\x00\x00", b"true", b"typ1"),
    ".webp": (b"RIFF",),
    ".woff": (b"wOFF",),
    ".woff2": (b"wOF2",),
}

# Pinned release archives allowed in the public repository by exact path and SHA-256.
# Any unlisted or modified .zip archive fails closed as unapproved-binary-file or
# reviewed-release-archive-integrity.
REVIEWED_RELEASE_ARCHIVES = {
    "release-assets/private-source-challenge/accepted-offline-toolkit.zip": {
        "sha256": "24ad3cc8f88c3b01b076d99b33017f9b090259dffa18e0cb500130d87bf37863",
        "signature": b"PK\x03\x04",
    },
    "release-assets/private-source-challenge/n170-private-source-challenge-v1.zip": {
        "sha256": "e7471919bdf7f5b42ab233d6c89c834a2a3f1952fd0aa268a5931a4b53b35f57",
        "signature": b"PK\x03\x04",
    },
}

# Broker exports are private by default. Only explicitly reviewed synthetic
# fixtures pinned by exact repository path and SHA-256 are allowed.
REVIEWED_BROKER_FIXTURES = {
    "tests/fixtures/import/ibkr-flex-synthetic.csv": {
        "sha256": "b1a292a6df479eac27fbe1928d052da29214b4b57588f4ebffd8e87bece785d5",
        "required_markers": (
            b"Account ID,From Date,To Date",
            b"SYNTHETIC,2025-01-02,2025-01-02",
        ),
    },
}

# Negative-control test files pinned by exact SHA-256 so synthetic test markers
# cannot mask unreviewed edits.
REVIEWED_NEGATIVE_TEST_FILES = {
    "tests/release-policy.test.mjs": {
        "sha256": "ec39c0fde3ca0f106e23e03461154c864e187446d8ca5cd3f6e83ff0b6de054d",
        "reviewed_marker_snippet": '["/' + 'Users/synthetic/private.txt", "-----BEGIN ' + 'PRIVATE KEY-----"]',
    },
}

BROKER_EXPORT_SUFFIXES = {".csv", ".json", ".xml"}
BROKER_EXPORT_NAME_TOKENS = {"flex", "ibkr"}


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    rule: str


def _as_posix(path: str | Path) -> str:
    normalized = PurePosixPath(str(path).replace(os.sep, "/")).as_posix()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _path_rules(relative_path: str, *, is_dir: bool = False) -> list[str]:
    normalized = _as_posix(relative_path)
    pure = PurePosixPath(normalized)
    parts = pure.parts
    name = pure.name
    lower_name = name.lower()
    rules: list[str] = []

    prohibited_parts = [
        part
        for part in parts
        if part in PROHIBITED_DIR_NAMES or part.endswith(PROHIBITED_DIR_SUFFIXES)
    ]
    if prohibited_parts:
        rules.append(f"generated-or-private-directory:{prohibited_parts[0]}")

    if is_dir:
        return rules

    if name in PROHIBITED_FILE_NAMES:
        rules.append(f"private-or-generated-file:{name}")

    if lower_name.startswith(".env") and not lower_name.endswith(".example"):
        rules.append("environment-file")

    if any(lower_name.endswith(suffix) for suffix in PROHIBITED_SUFFIXES):
        rules.append("runtime-secret-or-model-artifact")

    if parts[:1] == ("data",):
        rules.append("unapproved-root-data")

    name_tokens = set(filter(None, re.split(r"[-_.]+", pure.stem.lower())))
    looks_like_broker_export = (
        pure.suffix.lower() in BROKER_EXPORT_SUFFIXES
        and bool(name_tokens & BROKER_EXPORT_NAME_TOKENS)
    )
    if looks_like_broker_export and normalized not in REVIEWED_BROKER_FIXTURES:
        rules.append("broker-export")

    return rules


def _looks_binary(data: bytes) -> bool:
    if b"\x00" in data:
        return True
    if not data:
        return False
    control = sum(byte < 9 or (13 < byte < 32) for byte in data)
    return control / len(data) > 0.05


def _content_rules(path: Path, *, relative_path: str | None = None) -> list[str]:
    try:
        if path.stat().st_size > MAX_TEXT_BYTES:
            return ["oversized-release-file"]
        data = path.read_bytes()
    except (OSError, PermissionError):
        return ["unreadable-release-file"]

    normalized = _as_posix(relative_path) if relative_path is not None else None
    reviewed_archive = REVIEWED_RELEASE_ARCHIVES.get(normalized or "")
    if reviewed_archive is not None:
        digest_ok = hashlib.sha256(data).hexdigest() == reviewed_archive["sha256"]
        sig_ok = data.startswith(reviewed_archive["signature"])
        if not digest_ok or not sig_ok:
            return ["reviewed-release-archive-integrity"]
        return []

    reviewed_fixture = REVIEWED_BROKER_FIXTURES.get(normalized or "")
    if reviewed_fixture is not None:
        digest_matches = hashlib.sha256(data).hexdigest() == reviewed_fixture["sha256"]
        markers_match = all(marker in data for marker in reviewed_fixture["required_markers"])
        if not digest_matches or not markers_match:
            return ["reviewed-broker-fixture-integrity"]
    elif path.suffix.lower() == ".xml":
        folded = data.lower()
        if b"<flexqueryresponse" in folded or b"<flexstatement" in folded:
            return ["broker-export"]

    if _looks_binary(data[:8192]):
        signatures = ALLOWED_BINARY_SIGNATURES.get(path.suffix.lower(), ())
        if not signatures or not any(data.startswith(signature) for signature in signatures):
            return ["unapproved-binary-file"]
        if path.suffix.lower() == ".webp" and data[8:12] != b"WEBP":
            return ["unapproved-binary-file"]
        return []

    text = data.decode("utf-8", errors="replace")
    reviewed_neg = REVIEWED_NEGATIVE_TEST_FILES.get(normalized or "")
    if reviewed_neg is not None:
        if (
            hashlib.sha256(data).hexdigest() != reviewed_neg["sha256"]
            or reviewed_neg["reviewed_marker_snippet"] not in text
        ):
            return ["reviewed-negative-test-integrity"]
        text = text.replace(reviewed_neg["reviewed_marker_snippet"], "", 1)

    return [name for name, pattern in SECRET_PATTERNS if pattern.search(text)]


def _tree_entries(root: Path) -> tuple[list[tuple[str, bool]], list[Finding]]:
    entries: list[tuple[str, bool]] = []
    findings: list[Finding] = []
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        kept_dirs: list[str] = []
        for directory in sorted(dirs):
            candidate = current_path / directory
            relative = _as_posix(candidate.relative_to(root))
            if candidate.is_symlink():
                findings.append(Finding(relative, "symbolic-link"))
                continue
            if directory in SKIP_WALK_DIRS:
                continue
            if directory in PROHIBITED_DIR_NAMES or directory.endswith(PROHIBITED_DIR_SUFFIXES):
                for rule in _path_rules(relative, is_dir=True):
                    findings.append(Finding(relative, rule))
                continue
            kept_dirs.append(directory)
        dirs[:] = kept_dirs
        for filename in sorted(files):
            candidate = current_path / filename
            relative = _as_posix(candidate.relative_to(root))
            if candidate.is_symlink():
                findings.append(Finding(relative, "symbolic-link"))
                continue
            if filename in SKIP_WALK_DIRS:
                continue
            entries.append((relative, False))
    return entries, findings


def _tracked_entries(root: Path) -> list[tuple[str, bool]]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached"],
        cwd=root,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError("--tracked requires a Git checkout")
    return [(_as_posix(item.decode("utf-8")), False) for item in result.stdout.split(b"\0") if item]


def audit_release(
    root: Path,
    entries: Iterable[tuple[str, bool]],
    *,
    initial_findings: Sequence[Finding] = (),
    require_license: bool = False,
) -> list[Finding]:
    findings = list(initial_findings)
    for relative, is_dir in entries:
        for rule in _path_rules(relative, is_dir=is_dir):
            findings.append(Finding(relative, rule))
        if is_dir:
            continue
        absolute = root / relative
        if absolute.is_symlink():
            findings.append(Finding(relative, "symbolic-link"))
            continue
        for rule in _content_rules(absolute, relative_path=relative):
            findings.append(Finding(relative, rule))

    if require_license and not any((root / name).is_file() for name in ("LICENSE", "LICENSE.txt", "COPYING")):
        findings.append(Finding(".", "missing-root-license"))

    return sorted(set(findings))


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Release root to inspect")
    parser.add_argument(
        "--tracked",
        action="store_true",
        help="Inspect only Git-tracked files (recommended in CI)",
    )
    parser.add_argument(
        "--require-license",
        action="store_true",
        help="Block unless a root LICENSE, LICENSE.txt, or COPYING exists",
    )
    parser.add_argument("--max-findings", type=int, default=100, help="Maximum paths printed")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        print(f"ERROR: release root is not a directory: {root}", file=sys.stderr)
        return 2

    try:
        if args.tracked:
            entries = _tracked_entries(root)
            initial: list[Finding] = []
            mode = "tracked source"
        else:
            entries, initial = _tree_entries(root)
            mode = "directory tree"
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    findings = audit_release(
        root,
        entries,
        initial_findings=initial,
        require_license=args.require_license,
    )
    if findings:
        print(f"PUBLIC RELEASE BLOCKED: {len(findings)} finding(s) in {mode}.")
        for finding in findings[: max(args.max_findings, 0)]:
            print(f"BLOCK {finding.path}: {finding.rule}")
        remaining = len(findings) - max(args.max_findings, 0)
        if remaining > 0:
            print(f"... {remaining} additional finding(s) omitted")
        print("Build the public release from a clean checkout; never publish this working directory directly.")
        return 1

    print(f"PUBLIC RELEASE AUDIT PASSED: {len(entries)} {mode} entries checked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
