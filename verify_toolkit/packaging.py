"""Prepare only original toolkit files; never include private N170 modules."""
import hashlib
import json
import os
from pathlib import Path
import stat
import zipfile

FILES = (
    "__init__.py", "__main__.py", "freqtrade.py", "reporting.py", "conformance.py", "packaging.py",
    "README.md", "FREQTRADE.md", "LICENSE", "NOTICE",
    "runner.py", "run_contract.py", "run_review.py", "RUN_REVIEW_V1.md", "engine_worker.py", "synthetic.py",
    "RUNNER.md", "RUN_MANIFEST_V1.md", "engine-source.json", "integration_validation.py",
    "examples/freqtrade-lookahead-clean.csv", "examples/freqtrade-lookahead-findings.csv",
    "examples/freqtrade-lookahead-not-assessable.csv",
)


def _source_bytes(root_fd, name):
    parts = name.split("/")
    current = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current)
        with os.fdopen(fd, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise ValueError("Package source must be a regular file")
            raw = source.read(1_000_001)
            if len(raw) > 1_000_000:
                raise ValueError("Package source exceeds byte limit")
            return raw
    finally:
        os.close(current)


def package_source(destination):
    root = Path(__file__).resolve().parent
    contents = {}
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in FILES:
            contents["verify_toolkit/" + name] = _source_bytes(root_fd, name)
    finally:
        os.close(root_fd)
    manifest = {"schema": "n170.toolkit.source-manifest.v1", "version": "0.2.0",
                "files": {name: {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
                          for name, raw in sorted(contents.items())},
                "trust": "Unsigned inventory of packaged source; not publisher authentication."}
    contents["MANIFEST.json"] = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    # Fixed timestamps/order produce repeatable archives. Exclusive create avoids
    # overwriting a retained release. No VCS/network/publication operation exists.
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_STORED) as archive:
        for name, raw in sorted(contents.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, raw)
    digest = hashlib.sha256(Path(destination).read_bytes()).hexdigest()
    return {"archive_sha256": digest, "source_file_count": len(FILES), "published": False,
            "boundary": "Original offline toolkit and synthetic examples only; no private engine, private strategy, account data or signing keys."}
