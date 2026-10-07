#!/usr/bin/env python3
"""Data-only verifier and safe extractor for this separately identified public subset."""
import argparse
import hashlib
import json
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath

FROZEN = {
    'original60': '7f78ef603c1ba287928355c75f62474a897e2b15e93b7d4c1bb4ad9589c383cd',
    'order8': '03506adb9e2cde9fe9d24aebdeca47fc5e25fd5c3676c37f193ad9cdddfaa51f',
    'accepted-history': 'b9e405429a222439bd635411eb1f50d92923bc28e723f6ced7636e9d4dfba961',
}
TOOLKIT = '24ad3cc8f88c3b01b076d99b33017f9b090259dffa18e0cb500130d87bf37863'
MODULES = {
    'scripts/verify-reconciliation.mjs': 'b7e31a3901030d8a5761adf72d49f9e1f6afc9ed10a8f7cf91f824f5bb9d5781',
    'scripts/reconciliation-input.mjs': '34255307748c42edbb4d6bcad2dc5160e7281bec330c4ff0bed21a12c43e68f6',
    'scripts/reconciliation-source.mjs': 'cca3a37516488e67be874cfabf87b5d2ae7dabe97725b8f66fd6d140f9e69cd0',
    'scripts/verify-record.mjs': 'f1406f52297d0feb7ea30f42f468d823b8e2480c93d7e09eb4acc6018e2d283c',
}

def require(condition, message):
    if not condition:
        raise ValueError(message)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def strict_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON property')
        result[key] = value
    return result

def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=strict_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))

def safe_name(value):
    require(isinstance(value, str) and '\\' not in value and '\x00' not in value, 'Unsafe path')
    path = PurePosixPath(value)
    require(value and not path.is_absolute() and all(x not in ('', '.', '..') for x in value.split('/')), 'Unsafe path')
    require(not re.match(r'^[A-Za-z]:', value), 'Unsafe path')
    return value

def verify_pack(root, expected_manifest_sha256):
    root = Path(root)
    require(not root.is_symlink() and root.is_dir(), 'Pack must be a regular directory')
    manifest_path = root / 'MANIFEST.json'
    require(not manifest_path.is_symlink() and manifest_path.is_file(), 'Missing pack manifest')
    require(digest(manifest_path.read_bytes()) == expected_manifest_sha256, 'Pack manifest hash mismatch')
    manifest = read_json(manifest_path)
    require(manifest['schema'] == 'n170.public-source-challenge-pack.v1', 'Wrong pack manifest schema')
    expected = {}
    for row in manifest['files']:
        name = safe_name(row['path'])
        require(name not in expected and name != 'MANIFEST.json', 'Duplicate or self-listed payload')
        expected[name] = row
    actual = set()
    for path in root.rglob('*'):
        require(not path.is_symlink(), 'Symlink in pack')
        if path.is_dir():
            continue
        require(path.is_file(), 'Nonregular pack file')
        actual.add(path.relative_to(root).as_posix())
    require(actual == set(expected) | {'MANIFEST.json'}, 'Missing or extra pack payload')
    for name, row in expected.items():
        data = (root / name).read_bytes()
        require(len(data) == row['bytes'] and digest(data) == row['sha256'], 'Pack payload identity mismatch: ' + name)
    freezes = {}
    for label, identity in FROZEN.items():
        path = root / 'provenance' / (label + '.original-MANIFEST.json')
        require(digest(path.read_bytes()) == identity, 'Original freeze identity mismatch')
        freezes[label] = {r['path']: r for r in read_json(path)['files']}
    provenance = read_json(root / 'PROVENANCE.json')
    mapped = {}
    for row in provenance['unchanged_files']:
        name = safe_name(row['path'])
        require(name not in mapped and name in expected, 'Duplicate or absent provenance payload')
        mapped[name] = row
        require(row['bytes'] == expected[name]['bytes'] and row['sha256'] == expected[name]['sha256'], 'Provenance payload mismatch')
        if 'source_freeze' in row:
            label = row['source_freeze']
            require(label in freezes, 'Unknown source freeze')
            if row['original_path'] == 'MANIFEST.json':
                require(row['sha256'] == FROZEN[label], 'Copied original manifest mismatch')
            else:
                original = freezes[label][safe_name(row['original_path'])]
                require(row['bytes'] == original['bytes'] and row['sha256'] == original['sha256'], 'Changed original payload')
        else:
            require(row.get('source_archive_sha256') == TOOLKIT and name in ('LICENSE', 'NOTICE'), 'Unknown archive provenance')
    total = positive = 0
    for label, count in [('original60', 60), ('order8', 8)]:
        suite = root / 'suites' / label
        subset = read_json(suite / 'MANIFEST.json')
        require(subset['schema'] == 'n170.public-source-challenge-subset.v1' and subset['original_manifest_sha256'] == FROZEN[label], 'Wrong subset identity')
        require(subset['original_full_suite_bytes_claimed'] is False, 'Subset mislabelled as full original')
        listed = {}
        for row in subset['files']:
            name = safe_name(row['path'])
            require(name not in listed, 'Duplicate subset payload')
            listed[name] = row
            require(row == freezes[label][name], 'Subset changed original file identity')
            require('suites/' + label + '/' + name in mapped, 'Unmapped suite payload')
        suite_files = {x.relative_to(suite).as_posix() for x in suite.rglob('*') if x.is_file()}
        require(suite_files == set(listed) | {'MANIFEST.json'}, 'Subset inventory mismatch')
        cases = read_json(suite / 'cases.json')['cases']
        require(len(cases) == count and len({c['id'] for c in cases}) == count, 'Wrong case count or duplicate case')
        for case in cases:
            require(re.fullmatch(r'[A-Za-z0-9_-]+', case['id']), 'Unsafe case id')
            for field in ('record', 'reconciliation'):
                require(safe_name(case[field]) in listed, 'Missing case input')
            total += 1
            positive += case['status'] == 'VERIFIED_UNDER_OWNER_ASSERTIONS'
    require(total == 68 and positive == 31, 'Case coverage changed')
    pins = read_json(root / 'SOURCE_PINS.json')
    require(pins['toolkit_archive_sha256'] == TOOLKIT, 'Toolkit pin mismatch')
    require({x['path']: x['sha256'] for x in pins['modules']} == MODULES, 'Closure pin mismatch')
    return {'pack_manifest_sha256': expected_manifest_sha256, 'payload_count': len(expected), 'case_count': total,
            'conditional_positive_cases': positive, 'unchanged_source_files': len(mapped), 'candidate_executed': False}

def extract_archive(archive, archive_sha256, destination):
    archive = Path(archive)
    require(not archive.is_symlink() and archive.is_file(), 'Archive must be regular')
    require(digest(archive.read_bytes()) == archive_sha256, 'Archive hash mismatch')
    destination = Path(destination)
    require(destination.is_absolute() and not destination.exists() and not destination.is_symlink(), 'New absolute destination required')
    with zipfile.ZipFile(archive) as z:
        entries = z.infolist()
        names = set()
        require(len(entries) <= 1000 and sum(i.file_size for i in entries) <= 20_000_000, 'Archive exceeds pack bounds')
        for item in entries:
            name = safe_name(item.filename)
            require(name not in names, 'Duplicate archive member')
            names.add(name)
            mode = item.external_attr >> 16
            require(not item.is_dir() and stat.S_IFMT(mode) in (0, stat.S_IFREG), 'Nonregular archive member')
            require(not item.flag_bits & 1, 'Encrypted archive member')
        destination.mkdir()
        for item in entries:
            path = destination / item.filename
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as out:
                out.write(z.read(item))
    return destination

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--pack-dir')
    group.add_argument('--archive')
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--archive-sha256')
    parser.add_argument('--destination')
    args = parser.parse_args()
    if args.archive:
        require(args.archive_sha256 and args.destination, 'Archive hash and new destination required')
        root = extract_archive(args.archive, args.archive_sha256, args.destination)
    else:
        root = Path(args.pack_dir)
    print(json.dumps(verify_pack(root, args.manifest_sha256), indent=2))

if __name__ == '__main__':
    main()
