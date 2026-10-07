#!/usr/bin/env python3
"""Validate the complete public kit before optionally extracting it.

Python standard library only. Inventory hashes establish internal consistency,
not publisher authenticity. A ZIP hash is trusted only when the caller obtains
the expected value independently through a trusted channel.

Extraction stages validated bytes beside the destination, then publishes with
an atomic, no-replace rename. This uses operating-system APIs through stdlib
ctypes on macOS/Linux, and os.rename on Windows. Unsupported systems fail closed.
No generic check-then-rename fallback is used. All limits are finite and apply
before decompression; extracted permissions come from this program, not the ZIP.
"""

import sys
sys.dont_write_bytecode = True

import argparse
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import tempfile
from types import MappingProxyType
import zipfile
import zlib

INVENTORY = "public-inventory.json"
SCHEMA = "n170.public-challenge-inventory.v1"
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
MAX_INVENTORY = 1024 * 1024
MAX_ENTRIES = 4096  # Including the inventory.
MAX_PATH = 240
MAX_RATIO = 200
RATIO_ALLOWANCE = 1024 * 1024
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_COMPONENT = re.compile(r"[A-Za-z0-9._-]+\Z")
_DEVICES = {"CON", "PRN", "AUX", "NUL", *("COM%d" % i for i in range(1, 10)), *("LPT%d" % i for i in range(1, 10))}


class ArchiveError(ValueError):
    """The input or requested output violates the bounded archive contract."""


def require(condition, message):
    if not condition:
        raise ArchiveError(message)


def validate_path(value):
    require(type(value) is str and 0 < len(value) <= MAX_PATH, "Invalid inventory/member path length")
    parts = value.split("/")
    for part in parts:
        require(bool(_COMPONENT.fullmatch(part)) and part not in (".", ".."), "Unsafe archive path: %r" % value)
        require(not part.endswith("."), "Trailing-dot path component is unsupported")
        require(part.split(".", 1)[0].upper() not in _DEVICES, "Reserved device path component")
    return value


def validate_path_set(paths):
    seen, prefixes = set(), {}
    for path in paths:
        validate_path(path)
        require(path not in seen, "Duplicate archive/inventory path")
        seen.add(path)
        parts = path.split("/")
        for depth in range(1, len(parts) + 1):
            prefix = "/".join(parts[:depth])
            key = prefix.casefold()
            require(key not in prefixes or prefixes[key] == prefix, "Casefold path collision")
            prefixes[key] = prefix
    for path in seen:
        parts = path.split("/")
        require(not any("/".join(parts[:depth]) in seen for depth in range(1, len(parts))), "File/directory prefix collision")


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate inventory JSON field")
        result[key] = value
    return result


def _not_number(_value):
    raise ArchiveError("Inventory numbers must be plain integers")


def _integer(value):
    require(len(value) <= 20 and bool(re.fullmatch(r"0|-?[1-9][0-9]*", value)), "Inventory integers are noncanonical or too large")
    return int(value)


def parse_inventory(data):
    require(type(data) is bytes and len(data) <= MAX_INVENTORY, "Inventory exceeds its byte limit")
    try:
        value = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=_object,
                           parse_int=_integer, parse_float=_not_number, parse_constant=_not_number)
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ArchiveError("Invalid inventory JSON: %s" % exc) from exc
    require(type(value) is dict and set(value) == {"schema_version", "files"}, "Invalid inventory fields")
    require(value["schema_version"] == SCHEMA, "Unsupported inventory schema")
    files = value["files"]
    require(type(files) is list and 0 < len(files) < MAX_ENTRIES, "Invalid inventory file count")
    paths, total = [], 0
    for entry in files:
        require(type(entry) is dict and set(entry) == {"path", "size", "sha256"}, "Invalid inventory entry fields")
        path = validate_path(entry["path"])
        require(path != INVENTORY, "The inventory must not list itself")
        require(type(entry["size"]) is int and 0 <= entry["size"] <= MAX_FILE, "Invalid inventory file size")
        require(type(entry["sha256"]) is str and bool(_HEX.fullmatch(entry["sha256"])), "Invalid inventory SHA-256")
        paths.append(path)
        total += entry["size"]
    require(paths == sorted(paths), "Inventory files must be strictly sorted by path")
    validate_path_set([INVENTORY, *paths])
    require(total + len(data) <= MAX_TOTAL, "Inventory exceeds total unpacked limit")
    return value


def _read_bounded(path, limit):
    # Capture once, bound the read itself, and never reopen this file for extract.
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "Input must be a regular file")
        require(os.fstat(stream.fileno()).st_size <= limit, "Input exceeds archive byte limit")
        data = stream.read(limit + 1)
    require(len(data) <= limit, "Input exceeds archive byte limit")
    return data


def _zip_layout(data, infos):
    """Reject hidden/trailing records, local/central discrepancies and ZIP64.

    This deliberately supports a simple ZIP profile: stored/deflated members,
    no comments, extra fields, data descriptors, multi-disk records or ZIP64.
    The companion deterministic builder emits this profile using stored data.
    """
    require(len(data) >= 22, "Truncated ZIP")
    end = struct.unpack("<4s4H2LH", data[-22:])
    signature, disk, directory_disk, count_disk, count, directory_size, directory_start, comment = end
    require(signature == b"PK\x05\x06" and comment == 0, "ZIP must end exactly at an uncommented end record")
    require(disk == directory_disk == 0 and count_disk == count == len(infos), "Multi-disk or inconsistent ZIP directory")
    require(directory_start + directory_size == len(data) - 22, "Invalid central-directory bounds or ZIP64")
    cursor = 0
    for info in sorted(infos, key=lambda item: item.header_offset):
        require(info.header_offset == cursor and cursor + 30 <= directory_start, "Hidden, overlapping or noncontiguous ZIP member")
        fields = struct.unpack_from("<4s5H3L2H", data, cursor)
        sig, version, flags, method, _time, _date, crc, packed, unpacked, name_size, extra_size = fields
        require(sig == b"PK\x03\x04" and version <= 20, "Unsupported local ZIP header")
        require(flags == info.flag_bits and method == info.compress_type, "Local/central ZIP flags differ")
        require(crc == info.CRC and packed == info.compress_size and unpacked == info.file_size, "Local/central ZIP sizes or checksum differ")
        require(extra_size == 0, "ZIP extra fields are unsupported")
        start = cursor + 30
        require(data[start:start + name_size] == info.filename.encode("ascii"), "Local/central ZIP member names differ")
        cursor = start + name_size + extra_size + packed
        require(cursor <= directory_start, "ZIP member exceeds data region")
    require(cursor == directory_start, "Unlisted data before the central directory")


def _read_member(archive_bytes, info, maximum):
    require(info.file_size <= maximum, "Member exceeds its unpacked byte limit")
    # Local headers and exact member ranges were already checked by _zip_layout.
    start = info.header_offset + 30 + len(info.filename.encode("ascii"))
    packed = archive_bytes[start:start + info.compress_size]
    if info.compress_type == zipfile.ZIP_STORED:
        payload = packed
    else:
        decoder = zlib.decompressobj(-15)
        payload = decoder.decompress(packed, maximum + 1)
        require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
                "Incomplete, excessive or trailing DEFLATE member data")
    require(len(payload) <= maximum and len(payload) == info.file_size, "Decompressed data differs from declared size")
    require(zlib.crc32(payload) == info.CRC, "ZIP member CRC mismatch")
    return payload


class ValidatedArchive:
    """Immutable captured members, independent of any later archive-path change."""
    def __init__(self, digest, members):
        self.archive_sha256 = digest
        self.members = MappingProxyType(dict(members))


def verify_bytes(data, expected_sha256=None):
    require(type(data) is bytes and len(data) <= MAX_ARCHIVE, "Archive exceeds its byte limit")
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha256 is not None:
        require(type(expected_sha256) is str and bool(_HEX.fullmatch(expected_sha256.lower())), "Expected ZIP SHA-256 must be 64 hexadecimal characters")
        require(digest == expected_sha256.lower(), "ZIP hash does not match the externally supplied expected SHA-256")
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            infos = archive.infolist()
            require(0 < len(infos) <= MAX_ENTRIES, "ZIP has too many or no members")
            paths = []
            total = 0
            for info in infos:
                require(info.orig_filename == info.filename, "NUL byte in ZIP member name")
                validate_path(info.filename)
                require(not info.is_dir() and not (info.external_attr & 0x10), "Directory ZIP entries are unsupported")
                mode = info.external_attr >> 16
                require(stat.S_IFMT(mode) in (0, stat.S_IFREG), "Symlink or special ZIP member is forbidden")
                require(not (info.flag_bits & (1 | 0x40)), "Encrypted ZIP members are forbidden")
                require(not (info.flag_bits & ~0x800), "Unsupported ZIP flags or data descriptor")
                require(info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), "Unsupported ZIP compression")
                require(info.compress_type != zipfile.ZIP_STORED or info.compress_size == info.file_size, "Stored member packed/unpacked sizes differ")
                require(info.extract_version <= 20 and not info.extra and not info.comment, "Unsupported ZIP version or metadata")
                require(0 <= info.file_size <= MAX_FILE and 0 <= info.compress_size <= MAX_ARCHIVE, "Member exceeds size bounds")
                require(info.file_size <= max(RATIO_ALLOWANCE, info.compress_size * MAX_RATIO), "Compression ratio exceeds ZIP-bomb bound")
                total += info.file_size
                paths.append(info.filename)
            require(total <= MAX_TOTAL, "Archive exceeds total unpacked byte limit")
            validate_path_set(paths)
            require(INVENTORY in paths, "Missing public inventory")
            _zip_layout(data, infos)
            by_name = {info.filename: info for info in infos}
            inventory_bytes = _read_member(data, by_name[INVENTORY], MAX_INVENTORY)
            inventory = parse_inventory(inventory_bytes)
            expected = {entry["path"]: entry for entry in inventory["files"]}
            require(set(paths) == set(expected) | {INVENTORY}, "ZIP contains unlisted files or omits listed files")
            members = {INVENTORY: inventory_bytes}
            for path, entry in expected.items():
                info = by_name[path]
                require(info.file_size == entry["size"], "Inventory size mismatch: " + path)
                payload = _read_member(data, info, entry["size"])
                require(hashlib.sha256(payload).hexdigest() == entry["sha256"], "Inventory hash mismatch: " + path)
                members[path] = payload
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, EOFError, UnicodeError, struct.error, OverflowError, zlib.error) as exc:
        raise ArchiveError("Invalid or unsupported ZIP: %s" % exc) from exc
    return ValidatedArchive(digest, members)


def verify_archive(path, expected_sha256=None):
    return verify_bytes(_read_bounded(path, MAX_ARCHIVE), expected_sha256)


def publish_no_replace(source, destination):
    """Atomic publication, refusing an existing file, directory or symlink."""
    if sys.platform == "win32":
        os.rename(source, destination)  # Windows refuses an existing destination.
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        function = libc.renamex_np
        function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        result = function(os.fsencode(source), os.fsencode(destination), 0x4)  # RENAME_EXCL
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        function = libc.renameat2
        function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        result = function(-100, os.fsencode(source), -100, os.fsencode(destination), 1)  # AT_FDCWD, RENAME_NOREPLACE
    else:
        raise ArchiveError("Atomic no-replace extraction/publication is unsupported on this platform")
    if result:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), os.fspath(destination))


def _validate_captured_files(files):
    require(hasattr(files, "items") and 0 < len(files) <= MAX_ENTRIES, "Invalid captured file mapping")
    validate_path_set(files)
    total = 0
    for data in files.values():
        require(type(data) is bytes and len(data) <= MAX_FILE, "Captured file exceeds its bound or is not bytes")
        total += len(data)
    require(total <= MAX_TOTAL, "Captured files exceed total byte limit")


def source_file_names(root):
    """Return bounded portable regular-file names; reject links and special nodes."""
    require(hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"), "Secure source reads are unsupported on this platform")
    found, visited = [], 0
    def visit(descriptor, prefix):
        nonlocal visited
        with os.scandir(descriptor) as entries:
            for entry in entries:
                visited += 1
                require(visited <= MAX_ENTRIES * 2, "Source tree has too many filesystem entries")
                name = prefix + entry.name
                validate_path(name)
                require(not entry.is_symlink(), "Source symlinks are forbidden: " + name)
                if entry.is_dir(follow_symlinks=False):
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                    try:
                        visit(child, name + "/")
                    finally:
                        os.close(child)
                else:
                    require(entry.is_file(follow_symlinks=False), "Source special files are forbidden")
                    found.append(name)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        visit(descriptor, "")
    finally:
        os.close(descriptor)
    validate_path_set(found)
    return found


def capture_source_file(root, path, maximum):
    """Bounded component-by-component no-follow read of a source-tree file."""
    validate_path(path)
    require(hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"), "Secure source reads are unsupported on this platform")
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = path.split("/")
        for component in parts[:-1]:
            following = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = following
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=directory)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, "Source file type/size exceeds its bound")
            data = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
            require(before.st_size == after.st_size and before.st_mtime_ns == after.st_mtime_ns and before.st_ctime_ns == after.st_ctime_ns, "Source file changed during capture")
        require(len(data) <= maximum, "Source file exceeds its byte limit")
        return data
    finally:
        os.close(directory)


def verify_extracted_files(files, root):
    """Compare a whole tree against independently checked captured members.

    The caller is responsible for authenticating/validating the supplied mapping.
    This checks the tree now; it cannot prevent a device owner altering it later.
    """
    files = dict(files)
    _validate_captured_files(files)
    root = Path(root).resolve(strict=True)
    require(set(source_file_names(root)) == set(files), "Extracted tree has missing or unlisted files")
    for name, expected in files.items():
        actual = capture_source_file(root, name, len(expected))
        require(actual == expected, "Extracted source differs from verified archive: " + name)
    return root


def publish_verified_files(files, destination):
    """Publish captured members safely; caller must establish their integrity.

    Path/type/size checks are repeated here, regardless of the caller's verifier.
    """
    files = dict(files)
    _validate_captured_files(files)
    destination = Path(destination)
    require(destination.name not in ("", ".", ".."), "Choose a new extraction directory")
    parent = destination.parent.resolve(strict=True)
    destination = parent / destination.name
    require(not os.path.lexists(destination), "Extraction target already exists")
    staging = Path(tempfile.mkdtemp(prefix=".n170-extract-", dir=parent))
    try:
        for name, data in files.items():
            target = staging.joinpath(*name.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            target.chmod(0o644)
        publish_no_replace(staging, destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return destination


def extract_verified(checked, destination):
    require(isinstance(checked, ValidatedArchive), "Extraction requires verified captured archive bytes")
    return publish_verified_files(checked.members, destination)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--expected-sha256", help="ZIP digest obtained independently through a trusted channel")
    parser.add_argument("--extract", type=Path, metavar="NEW_DIRECTORY", help="Validate first, then publish a new directory atomically without replacing anything")
    args = parser.parse_args(argv)
    try:
        checked = verify_archive(args.archive, args.expected_sha256)
        output = extract_verified(checked, args.extract) if args.extract is not None else None
        print(json.dumps({"integrity": "verified", "archive_sha256": checked.archive_sha256,
                          "expected_digest": "matched" if args.expected_sha256 else "not_supplied",
                          "authenticity": "not_established_by_internal_inventory",
                          "files": len(checked.members), "extracted_to": str(output) if output else None}, sort_keys=True))
        return 0
    except (ArchiveError, OSError) as exc:
        print("Archive verification failed: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
