// Bounded delivery contract. Expected identities were frozen from the accepted
// 2026-09-27 public artifacts before inspecting the delivery implementation.
// These tests establish delivery integrity, not financial correctness or an audit.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const app = process.env.N170_VERIFY_APP || fileURLToPath(new URL("../", import.meta.url));
const accepted = {
  "new_files": {
    "README.md": {
      "bytes": 3170,
      "sha256": "7bb8c899afd9a34000e1e018379d5bdf2b4b9fb301edb03f00cb28943714e544"
    },
    "RELEASE.json": {
      "bytes": 1194,
      "sha256": "36a412f0963e5db8417129b46b359673db90b6aac29f32daa0872f8f12131d8d"
    },
    "SHA256SUMS": {
      "bytes": 434,
      "sha256": "93695a8610aca7acbf59974ce6339a1be3103fd07e5f852fcd44122429f6e45b"
    },
    "accepted-offline-toolkit.zip": {
      "bytes": 765697,
      "sha256": "24ad3cc8f88c3b01b076d99b33017f9b090259dffa18e0cb500130d87bf37863"
    },
    "n170-private-source-challenge-v1.zip": {
      "bytes": 543799,
      "sha256": "e7471919bdf7f5b42ab233d6c89c834a2a3f1952fd0aa268a5931a4b53b35f57"
    },
    "verify_pack.py": {
      "bytes": 8733,
      "sha256": "2eda69531c3c079f71e1bbfb9e6dc3a6683deddd3bdab7e3ca0b2bcf45e75d72"
    }
  },
  "old_downloads": {
    "README.md": "ed89f81f7562b45b1d03a83d7151f57c2b938d3d3d7520a616a6df2fd69694b0",
    "SHA256SUMS": "e41b5e2fdac20ea18c6bf6eb1969cf0822e2439e463ca9bf1165f2071e190c4e",
    "public-challenge-kit.zip": "5802a438f08afdad9e1d74d7ee9f1ab03b86a059e9d77bb30ea977148c9a0a22",
    "verify_archive.py": "0fb1cd2bd5da6ec6b8f809121ab76219ac36560a2d7cfca056c03eaab5c6fda1"
  },
  "release": {
    "schema": "n170.private-source-challenge-public-release.v1",
    "date": "2026-09-27",
    "status": "prepared_and_locally_accepted_not_published",
    "files": [
      {
        "path": "n170-private-source-challenge-v1.zip",
        "bytes": 543799,
        "sha256": "e7471919bdf7f5b42ab233d6c89c834a2a3f1952fd0aa268a5931a4b53b35f57"
      },
      {
        "path": "verify_pack.py",
        "bytes": 8733,
        "sha256": "2eda69531c3c079f71e1bbfb9e6dc3a6683deddd3bdab7e3ca0b2bcf45e75d72"
      },
      {
        "path": "accepted-offline-toolkit.zip",
        "bytes": 765697,
        "sha256": "24ad3cc8f88c3b01b076d99b33017f9b090259dffa18e0cb500130d87bf37863"
      }
    ],
    "pack_manifest_sha256": "5abe3172731422206ac4418f8c0b8f056b2e8b93d85d6d3624c7747549da2c83",
    "root_acceptance_sha256": "bebf0e1df27132787c5d2ea13f27d5b5a540fe31958b4e7972f55e0288312d07",
    "fresh_execution": {
      "attempts": 1,
      "cases": 68,
      "conditional_positive_cases": 31,
      "raw_passes": 51,
      "raw_flags": 17,
      "expected_status_exit_matches": 68,
      "exact_historical_case_output_files": 204,
      "unresolved_cases": 0
    },
    "outside_human_review": false,
    "personal_account_verified": false,
    "published": false
  },
  "source_pins": {
    "schema": "n170.public-source-challenge-source-pins.v1",
    "toolkit_archive_sha256": "24ad3cc8f88c3b01b076d99b33017f9b090259dffa18e0cb500130d87bf37863",
    "combined_source_archive_sha256": "b234e3f7d250f3819071030eeaa7de0a62c84343dc939a72d0cb61babba1648a",
    "root_source_acceptance_manifest_sha256": "dd8ed8a12cba290ae0bea9eb824fcb6d85ae66535ff0b31e6b5ef2c5be510bf4",
    "node_engines": "^20.19.0 || >=22.12.0",
    "python": "3.9 or newer; standard library only",
    "runner_platforms": "POSIX (Linux or macOS); original harness pipe selector is not certified on Windows",
    "modules": [
      {
        "path": "scripts/verify-reconciliation.mjs",
        "bytes": 19875,
        "sha256": "b7e31a3901030d8a5761adf72d49f9e1f6afc9ed10a8f7cf91f824f5bb9d5781"
      },
      {
        "path": "scripts/reconciliation-input.mjs",
        "bytes": 16769,
        "sha256": "34255307748c42edbb4d6bcad2dc5160e7281bec330c4ff0bed21a12c43e68f6"
      },
      {
        "path": "scripts/reconciliation-source.mjs",
        "bytes": 15978,
        "sha256": "cca3a37516488e67be874cfabf87b5d2ae7dabe97725b8f66fd6d140f9e69cd0"
      },
      {
        "path": "scripts/verify-record.mjs",
        "bytes": 16105,
        "sha256": "f1406f52297d0feb7ea30f42f468d823b8e2480c93d7e09eb4acc6018e2d283c"
      }
    ]
  }
};

function check(body) {
  const result = spawnSync("python3", ["-B", "-c", String.raw`
import copy, hashlib, importlib.util, json, tempfile, zipfile
from pathlib import Path
import sys
app = Path(sys.argv[1])
expected = json.loads(sys.argv[2])
prefix = 'release-assets/private-source-challenge/'
route = 'private-source-challenge/'
pins = expected['new_files']
policy = json.loads((app/'scripts/public-source-inventory.json').read_bytes())
spec = importlib.util.spec_from_file_location('public_build', app/'scripts/build-public.py')
build = importlib.util.module_from_spec(spec); spec.loader.exec_module(build)
def identity(raw):
 return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
def write_policy(root, value):
 (root/build.INVENTORY).write_text(json.dumps(value))
def populate(root, contents):
 for name, raw in contents.items():
  path = root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
def refuses(root, label):
 try: build.collect_source(root)
 except ValueError: return
 raise AssertionError(label + ': unsafe input accepted')
${body}
`, app, JSON.stringify(accepted)], {encoding:"utf8", timeout:60_000, maxBuffer:1024*1024});
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stderr || result.stdout);
}

test("exact ten downloads retain the accepted six private-source artifacts and older four", () => check(String.raw`
assert len(pins) == 6
expected_names = {prefix+name for name in pins} | {'release-assets/challenge-kit/'+name for name in expected['old_downloads']}
assert set(policy['downloads']) == expected_names, 'missing or extra download (including the required challenge pack)'
assert {name for name in policy['files'] if name.startswith('release-assets/')} == expected_names
for name, pin in pins.items():
 source = prefix+name
 assert policy['downloads'][source] == dict(pin, path=route+name), source
 raw = (app/source).read_bytes()
 assert identity(raw) == pin, source
 assert (app/'dist/client'/route/name).read_bytes() == raw, 'delivered bytes: '+name
assert {p.relative_to(app/'release-assets/private-source-challenge').as_posix() for p in (app/'release-assets/private-source-challenge').rglob('*') if p.is_file()} == set(pins)
assert {p.relative_to(app/'dist/client/private-source-challenge').as_posix() for p in (app/'dist/client/private-source-challenge').rglob('*') if p.is_file()} == set(pins)
for name, digest in expected['old_downloads'].items():
 source = 'release-assets/challenge-kit/'+name
 raw = (app/source).read_bytes()
 assert hashlib.sha256(raw).hexdigest() == digest, source
 assert policy['downloads'][source] == dict(identity(raw), path='challenge-kit/'+name)
 assert (app/'dist/client/challenge-kit'/name).read_bytes() == raw, name
with zipfile.ZipFile(app/'dist/client/n170-verify-source.zip') as archive:
 for source in expected_names:
  assert archive.read('app/'+source) == (app/source).read_bytes(), 'editable source archive: '+source
`));

test("frozen challenge and toolkit retain nested identities and unchanged checker modules", () => check(String.raw`
directory = app/'dist/client/private-source-challenge'
release = json.loads((directory/'RELEASE.json').read_bytes())
assert release == expected['release']
assert set(entry['path'] for entry in release['files']) == {'n170-private-source-challenge-v1.zip','accepted-offline-toolkit.zip','verify_pack.py'}
for entry in release['files']:
 assert identity((directory/entry['path']).read_bytes()) == {k:entry[k] for k in ('bytes','sha256')}
checksums = {}
for line in (directory/'SHA256SUMS').read_text().splitlines():
 digest, name = line.split('  ', 1)
 assert name not in checksums, 'duplicate checksum entry'
 checksums[name] = digest
assert checksums == {name:entry['sha256'] for name,entry in pins.items() if name != 'SHA256SUMS'}
with zipfile.ZipFile(directory/'n170-private-source-challenge-v1.zip') as pack, zipfile.ZipFile(directory/'accepted-offline-toolkit.zip') as toolkit:
 raw = pack.read('MANIFEST.json')
 assert hashlib.sha256(raw).hexdigest() == release['pack_manifest_sha256']
 manifest = json.loads(raw)
 assert (manifest['case_count'], manifest['conditional_positive_cases'], manifest['historical_raw_pass'], manifest['historical_raw_flags']) == (68,31,51,17)
 assert len(pack.namelist()) == len(set(pack.namelist()))
 entries = {entry['path']:entry for entry in manifest['files']}
 assert len(entries) == len(manifest['files'])
 assert set(pack.namelist()) == set(entries) | {'MANIFEST.json'}
 for name, entry in entries.items():
  assert identity(pack.read(name)) == {k:entry[k] for k in ('bytes','sha256')}, name
 assert pack.read('verify_pack.py') == (directory/'verify_pack.py').read_bytes()
 source_pins = json.loads(pack.read('SOURCE_PINS.json'))
 assert source_pins == expected['source_pins']
 assert source_pins['toolkit_archive_sha256'] == pins['accepted-offline-toolkit.zip']['sha256']
 toolkit_manifest = json.loads(toolkit.read('MANIFEST.json'))
 assert len(toolkit.namelist()) == len(set(toolkit.namelist()))
 assert set(toolkit.namelist()) == set(toolkit_manifest['files']) | {'MANIFEST.json'}
 for name, entry in toolkit_manifest['files'].items():
  assert identity(toolkit.read(name)) == entry, name
 assert len(source_pins['modules']) == 4
 for entry in source_pins['modules']:
  raw = toolkit.read(entry['path'])
  assert identity(raw) == {k:entry[k] for k in ('bytes','sha256')}
  assert (app/entry['path']).read_bytes() == raw, 'unchanged checker module: '+entry['path']
# Current generated source/toolkit identities may change. The historical
# SOURCE_PINS combined-source identity is never asserted against this build.
`));

test("new download group is accepted; altered, missing and unlisted artifacts are rejected", () => check(String.raw`
original, contents = build.collect_source(app)
assert {prefix+name for name in pins} <= set(contents)
with tempfile.TemporaryDirectory() as directory:
 root = Path(directory); populate(root, contents)
 clean_policy, clean_contents = build.collect_source(root)
 assert clean_policy == original and clean_contents == contents, 'normal new download group'
 for name in pins:
  target = root/prefix/name; raw = target.read_bytes()
  try:
   target.write_bytes(raw+b'changed')
   refuses(root, 'changed pinned '+name)
  finally: target.write_bytes(raw)
 for name in ('n170-private-source-challenge-v1.zip','accepted-offline-toolkit.zip'):
  target = root/prefix/name; raw = target.read_bytes()
  try:
   target.unlink()
   refuses(root, 'missing required '+name)
  finally: target.write_bytes(raw)
 extra = root/prefix/'unlisted.txt'
 try:
  extra.write_text('synthetic')
  refuses(root, 'unlisted release file')
 finally: extra.unlink()
 assert build.collect_source(root)[1] == contents, 'valid control after mutations'
`));

test("download paths reject traversal, deep folders, unapproved families and document collisions", () => check(String.raw`
original, contents = build.collect_source(app)
source = prefix+'README.md'
with tempfile.TemporaryDirectory() as directory:
 root = Path(directory); populate(root, contents)
 for destination in (
  '../private-source-challenge/README.md',
  'private-source-challenge/../private-source-challenge/README.md',
  'private-source-challenge/nested/README.md',
  'unapproved-family/README.md',
  'assets/README.md',
  'private-source-challenge/RELEASE.json',
 ):
  changed = copy.deepcopy(original); changed['downloads'][source]['path'] = destination
  write_policy(root, changed); refuses(root, 'destination '+destination)
 write_policy(root, original)
 for replacement in (
  'release-assets/private-source-challenge/../private-source-challenge/README.md',
 ):
  changed = copy.deepcopy(original)
  changed['files'] = [replacement if name == source else name for name in changed['files']]
  changed['downloads'][replacement] = changed['downloads'].pop(source)
  old = root/source; target = root/replacement
  moved = target.resolve() != old.resolve()
  if moved:
   target.parent.mkdir(parents=True, exist_ok=True); old.rename(target)
  try:
   write_policy(root, changed); refuses(root, 'source '+replacement)
  finally:
   if moved: target.rename(old); target.parent.rmdir()
   write_policy(root, original)
 document = next(iter(original['documents']))
 for destination in ('private-source-challenge/README.md','private-source-challenge'):
  changed = copy.deepcopy(original); changed['documents'][document] = destination
  write_policy(root, changed); refuses(root, 'colliding document '+destination)
 (root/build.INVENTORY).write_bytes(contents[build.INVENTORY])
 assert build.collect_source(root)[1] == contents, 'valid control after path mutations'
`));
