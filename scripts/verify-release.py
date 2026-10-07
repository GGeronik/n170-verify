"""Independent offline verifier for an exact N170 source ZIP; no extraction."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import zipfile


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON field: " + key)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def verify(raw, expected):
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("archive SHA-256 differs from expected commitment")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if names != sorted(names) or len(names) != len(set(x.casefold() for x in names)):
            raise ValueError("unordered or duplicated archive members")
        folded_names = {name.casefold() for name in names}
        for name in folded_names:
            parts = name.split("/")
            if any("/".join(parts[:length]) in folded_names for length in range(1, len(parts))):
                raise ValueError("file/directory archive member conflict")
        if sum(entry.file_size for entry in entries) > 128 * 1024 * 1024:
            raise ValueError("archive uncompressed size limit")
        for entry in entries:
            path = PurePosixPath(entry.filename)
            if (not path.parts or path.is_absolute() or str(path) != entry.filename or ".." in path.parts
                or "\\" in entry.filename or ":" in entry.filename
                or any(ord(c) < 32 or ord(c) > 126 for c in entry.filename)
                or not stat.S_ISREG(entry.external_attr >> 16)
                or entry.compress_type != zipfile.ZIP_STORED
                or entry.date_time != (1980, 1, 1, 0, 0, 0)
                or entry.file_size > 16 * 1024 * 1024):
                raise ValueError("unsafe or noncanonical archive member")
        manifest = strict_json(archive.read("MANIFEST.json"))
        if not isinstance(manifest, dict) or manifest.get("schema") != "n170.release.archive.v1":
            raise ValueError("unsupported manifest")
        if (not isinstance(manifest.get("files"), dict)
                or not isinstance(manifest.get("source_freeze_sha256"), str)
                or len(manifest["source_freeze_sha256"]) != 64):
            raise ValueError("malformed manifest")
        expected_names = set(manifest["files"]) | {"MANIFEST.json"}
        if set(names) != expected_names:
            raise ValueError("archive inventory is incomplete or has extra files")
        for name, claim in manifest["files"].items():
            if (not isinstance(claim, dict) or type(claim.get("bytes")) is not int
                    or claim["bytes"] < 0 or not isinstance(claim.get("sha256"), str)):
                raise ValueError("malformed file descriptor")
            content = archive.read(name)
            if len(content) != claim["bytes"] or hashlib.sha256(content).hexdigest() != claim["sha256"]:
                raise ValueError("content mismatch: " + name)
        return {"schema": "n170.release.verification.v1", "status": "verified",
                "archive_sha256": expected, "files": len(manifest["files"]),
                "source_freeze_sha256": manifest["source_freeze_sha256"],
                "source_authenticity": "not_established", "network_required": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive")
    parser.add_argument("--sha256", required=True, help="Expected SHA-256 from a separately retained channel")
    args = parser.parse_args()
    try:
        print(json.dumps(verify(Path(args.archive).read_bytes(), args.sha256), indent=2))
    except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile) as error:
        parser.exit(1, "Verification failed: " + str(error) + "\n")
