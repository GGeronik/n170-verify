// Original synthetic release challenges. Python uses only its standard library.
// These checks inspect the built artifact; they do not contact a package registry.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const app = fileURLToPath(new URL("../", import.meta.url));

function pythonCheck(body) {
  const result = spawnSync("python3", ["-c", String.raw`
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
import warnings
import zipfile

APP = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("recipient_verifier", APP / "scripts/verify-release.py")
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
RAW = (APP / "dist/client/n170-verify-source.zip").read_bytes()
HASH = hashlib.sha256(RAW).hexdigest()

def changed_archive(*, replace=None, omit=(), extra=(), mutate_info=None):
    result = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(RAW)) as source, zipfile.ZipFile(result, "w") as target:
        entries = [(entry, source.read(entry.filename)) for entry in source.infolist()
                   if entry.filename not in omit]
        for name, content in extra:
            entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            entries.append((entry, content))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            for entry, content in sorted(entries, key=lambda item: item[0].filename):
                if mutate_info:
                    mutate_info(entry)
                target.writestr(entry, (replace or {}).get(entry.filename, content))
    return result.getvalue()

def rejects(raw, expected=None):
    try:
        verifier.verify(raw, expected or hashlib.sha256(raw).hexdigest())
    except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile):
        return
    raise AssertionError("recipient verifier accepted the synthetic invalid archive")

${body}
`, app], { encoding: "utf8", timeout: 60_000, maxBuffer: 1024 * 1024 });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stderr || result.stdout);
}

test("public source ZIP carries a complete exact-byte inventory and offline verifier", () => {
  pythonCheck(String.raw`
result = verifier.verify(RAW, HASH)
assert result["status"] == "verified", result
assert result["source_authenticity"] == "not_established", result
assert result["network_required"] is False, result
with zipfile.ZipFile(io.BytesIO(RAW)) as archive:
    names = archive.namelist()
    for required in ("MANIFEST.json", "DEPENDENCIES.json", "COMPONENTS.json", "verify_release.py",
                     "app/package.json", "app/package-lock.json", "app/README.md",
                     "app/scripts/build-public.py", "app/scripts/public-source-inventory.json",
                     "app/scripts/verify-release.py", "app/.github/workflows/ci.yml"):
        assert required in names, required
    assert archive.read("verify_release.py") == (APP / "scripts/verify-release.py").read_bytes()
    for name in names:
        if name.startswith("app/"):
            assert archive.read(name) == (APP / name[4:]).read_bytes(), name
    manifest = json.loads(archive.read("MANIFEST.json"))
    assert set(names) == set(manifest["files"]) | {"MANIFEST.json"}
    for name, descriptor in manifest["files"].items():
        raw = archive.read(name)
        assert descriptor["bytes"] == len(raw), name
        assert descriptor["sha256"] == hashlib.sha256(raw).hexdigest(), name
`);
});

test("recipient verifier rejects altered, missing and extra artifact bytes", () => {
  pythonCheck(String.raw`
rejects(RAW, "0" * 64)
rejects(changed_archive(replace={"app/README.md": b"Original synthetic altered source\n"}))
rejects(changed_archive(omit=("app/README.md",)))
rejects(changed_archive(omit=("MANIFEST.json",)))
rejects(changed_archive(extra=(("app/docs/unreviewed-extra.md", b"Original synthetic extra\n"),)))
`);
});

test("recipient verifier rejects duplicate, unsafe and nonregular archive members", () => {
  pythonCheck(String.raw`
for name in ("app/README.md", "app/readme.md", "../escape", "/absolute", "app//doubled", "app/./dot",
             "app/../escape", "app\\backslash", "app/colon:name", "app/control\nname"):
    rejects(changed_archive(extra=((name, b"Original synthetic path challenge\n"),)))
for mode in (stat.S_IFLNK | 0o777, stat.S_IFDIR | 0o755, stat.S_IFIFO | 0o600):
    def change(entry):
        if entry.filename == "app/README.md":
            entry.external_attr = mode << 16
    rejects(changed_archive(mutate_info=change))
`);
});

test("source ZIP preserves lockfile identities and original complete license notices", () => {
  pythonCheck(String.raw`
with zipfile.ZipFile(io.BytesIO(RAW)) as archive:
    lock = json.loads(archive.read("app/package-lock.json"))
    actual = json.loads(archive.read("DEPENDENCIES.json"))["packages"]
    expected = []
    for path, value in sorted(lock["packages"].items()):
        if path:
            expected.append({"lockfile": "app/package-lock.json", "install_path": path,
                "version": value["version"], "license": value["license"], "integrity": value["integrity"],
                "resolved": value.get("resolved"), "dev": bool(value.get("dev", False)),
                "optional": bool(value.get("optional", False))})
    assert actual == expected
    assert archive.read("app/LICENSE") == (APP / "LICENSE").read_bytes()
    assert archive.read("app/NOTICE") == (APP / "NOTICE").read_bytes()
notices = (APP / "dist/client/third-party-licenses.txt").read_text()
for name in ("react", "react-dom", "scheduler"):
    package = APP / "node_modules" / name
    metadata = json.loads((package / "package.json").read_bytes())
    assert f'{name}@{metadata["version"]} ({metadata["license"]})' in notices
    assert (package / "LICENSE").read_text().strip() in notices, name
`);
});

test("public archive excludes historical private trees and uses the canonical build", () => {
  pythonCheck(String.raw`
with zipfile.ZipFile(io.BytesIO(RAW)) as archive:
    names = archive.namelist()
    for name in names:
        assert not name.startswith(("app/docs/validation/", "app/docs/verification/",
            "app/screenshots/", "app/research_repro/", "app/node_modules/", "app/dist/")), name
        assert ".env" not in Path(name).parts and not any(p.startswith(".env.") and p != ".env.example" for p in Path(name).parts), name
    package = json.loads(archive.read("app/package.json"))
    assert package["scripts"]["build"] == "python3 scripts/build-public.py"
    if "app/scripts/package-review-docs.py" in names:
        wrapper = archive.read("app/scripts/package-review-docs.py").decode()
        assert "build-public.py" in wrapper
        assert "rglob(" not in wrapper and "os.walk(" not in wrapper
`);
});

test("self-consistent replacement remains unauthenticated and cannot match the retained receipt", () => {
  pythonCheck(String.raw`
with zipfile.ZipFile(io.BytesIO(RAW)) as archive:
    manifest = json.loads(archive.read("MANIFEST.json"))
replacement = b"Original synthetic replacement by a different unsigned producer\n"
manifest["files"]["app/README.md"] = {"bytes": len(replacement), "sha256": hashlib.sha256(replacement).hexdigest()}
changed = changed_archive(replace={"app/README.md": replacement,
    "MANIFEST.json": (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()})
rejects(changed, HASH)
# The digest must come from a separately retained trusted channel. Recomputing it
# from this unsigned replacement establishes internal consistency only.
result = verifier.verify(changed, hashlib.sha256(changed).hexdigest())
assert result["source_authenticity"] == "not_established", result
`);
});

test("public synthetic run fixtures do not hide host workspace paths in encoded artifacts", () => {
  pythonCheck(String.raw`
import base64
import re
checked = 0
with zipfile.ZipFile(io.BytesIO(RAW)) as archive:
    for name in archive.namelist():
        if not name.endswith(".json"):
            continue
        value = json.loads(archive.read(name))
        if not isinstance(value, dict) or value.get("schema") != "n170.run-review.v1":
            continue
        for descriptor in [value["manifest"], *value["artifacts"]]:
            content = base64.b64decode(descriptor["base64"], validate=True)
            assert not re.search(rb"/(?:Users/[A-Za-z0-9._-]+/|private/var/folders/)", content), (name, descriptor["path"])
            checked += 1
assert checked > 0, "encoded original synthetic fixture coverage must be nonempty"
`);
});
