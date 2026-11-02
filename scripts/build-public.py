"""Build editable public source from an explicit inventory. Python standard library."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import stat
import subprocess
import sys
from urllib.parse import unquote, urlsplit
import zipfile

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = 'scripts/public-source-inventory.json'
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
# Exact original Node CLI closure and its delivery documentation/notices.
# All bytes come from the validated source inventory; never walk scripts/docs.
TOOLKIT_SUPPLEMENTAL_FILES = (
    'scripts/verify-reconciliation.mjs',
    'scripts/reconciliation-input.mjs',
    'scripts/reconciliation-source.mjs',
    'scripts/verify-record.mjs',
    'scripts/headline.mjs',
    'scripts/verify-headline.mjs',
    'scripts/verify-witness-receipt.mjs',
    'scripts/verify-continuity.mjs',
    'scripts/ots-verifier.mjs',
    'scripts/verify-dkim-statement.mjs',
    'scripts/verify-tlog.mjs',
    'scripts/witness-fetch.mjs',
    'docs/witness-receipt.md',
    'schemas/witness-receipt-v1.schema.json',
    'docs/verify-reconciliation.md',
    'docs/verify-reconciliation-result.schema.json',
    'LICENSE',
    'NOTICE',
)


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON field: " + key)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def path_name(value):
    if not isinstance(value, str) or not value or '\\' in value or ':' in value:
        raise ValueError('invalid public path')
    path = PurePosixPath(value)
    if (not path.parts or path.is_absolute() or str(path) != value or '..' in path.parts
            or any(ord(c) < 32 or ord(c) > 126 for c in value)
            or any(p in {'.git', 'node_modules', 'dist', 'private', 'secrets', '__pycache__'}
                   or p == '.env' or p.startswith('.env.') for p in path.parts)
            or any(p.startswith('.') and p != '.github' for p in path.parts[:-1])
            or path.suffix.lower() in {'.pem', '.key', '.p12', '.pfx', '.pyc'}):
        raise ValueError('unsafe public path: ' + value)
    return path.parts


def read_regular(root, name):
    parts = path_name(name)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        source = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(source, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError('public input must be a regular file: ' + name)
            raw = stream.read(MAX_FILE + 1)
            if len(raw) > MAX_FILE:
                raise ValueError('public file exceeds limit: ' + name)
            return raw
    finally:
        os.close(fd)


def unique_paths(names):
    seen = set()
    for name in names:
        path_name(name)
        key = name.casefold()
        if key in seen or any(key.startswith(p + '/') or p.startswith(key + '/') for p in seen):
            raise ValueError('duplicate/colliding public paths: ' + name)
        seen.add(key)


def collect_source(root=ROOT):
    root = Path(root)
    policy = strict_json(read_regular(root, INVENTORY))
    if policy.get('schema') != 'n170.public-source-inventory.v1':
        raise ValueError('unsupported public source inventory')
    names = policy['files']
    unique_paths(names)
    downloads = policy.get('downloads', {})
    destinations = [entry['path'] for entry in downloads.values()]
    unique_paths(list(policy['documents'].values()) + destinations)
    if any(len(path_name(name)) != 2 or path_name(name)[0] not in {'private-source-challenge'} for name in destinations):
        raise ValueError('download destination must be an explicit private-source-challenge file')
    reserved = {'assets', 'index.html', 'third-party-licenses.txt', 'n170-verify-source.zip', 'n170-verify-source.zip.sha256', 'n170-verify-toolkit.zip', 'n170-verify-toolkit.zip.sha256', 'verify_release.py'}
    if any('/' in name or name.casefold() in reserved for name in policy['documents'].values()):
        raise ValueError('document destination collides with generated build output')
    if INVENTORY not in names or any(name not in names for name in (*policy['documents'], *downloads)):
        raise ValueError('inventory must include itself and all served document sources')
    contents = {}
    for name in sorted(names):
        try:
            contents[name] = read_regular(root, name)
        except OSError as error:
            raise ValueError('missing, symlink or unsafe public source: ' + name) from error
    for name, entry in downloads.items():
        if set(entry) != {'path', 'bytes', 'sha256'} or entry['bytes'] != len(contents[name]) or entry['sha256'] != digest(contents[name]):
            raise ValueError('download does not match separately retained receipt: ' + name)
    if sum(map(len, contents.values())) > MAX_TOTAL:
        raise ValueError('public source size limit')
    # Vite can consume these paths even when absent from a source ZIP. Fail
    # before running build code. Other unlisted docs/tests are never promoted.
    for entry in root.iterdir():
        if entry.name == 'public' or entry.name == '.env' or entry.name.startswith('.env.'):
            raise ValueError('unreviewed Vite public/environment input: ' + entry.name)
        roots = {name.split('/')[0] for name in names} | {'node_modules', 'dist', '.git', '.DS_Store'}
        if entry.name in roots:
            continue
        if entry.name.startswith('.'):
            # Local configuration directories may coexist with the app. Inspect only this entry's type; never enumerate, read or package its contents.
            if not stat.S_ISDIR(entry.lstat().st_mode):
                raise ValueError('hidden top-level input must be a real directory: ' + entry.name)
            continue
        raise ValueError('unlisted top-level build input: ' + entry.name)
    for prefix in ('src', 'worker', 'verify_toolkit', 'verify_accounting', 'release-assets'):
        for directory, dirs, files in os.walk(root / prefix, followlinks=False):
            for name in dirs + files:
                item = Path(directory) / name
                if item.is_symlink():
                    raise ValueError('source symlink: ' + item.relative_to(root).as_posix())
            # Python CLI use can create bytecode caches; these are generated,
            # excluded files and never enter either public source archive.
            if prefix in ('verify_toolkit', 'verify_accounting') and '__pycache__' in dirs:
                dirs.remove('__pycache__')
            for name in files:
                if (Path(directory) / name).relative_to(root).as_posix() not in contents:
                    raise ValueError('unlisted active source: ' + (Path(directory) / name).relative_to(root).as_posix())
    for name in ('node_modules', 'dist'):
        path = root / name
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            raise ValueError(name + ' must be a real directory')
    return policy, contents


def dependency_inventory(contents):
    lock = strict_json(contents['package-lock.json'])
    packages = []
    for path, entry in sorted(lock['packages'].items()):
        if not path:
            continue
        if not all(entry.get(k) for k in ('version', 'license', 'integrity')):
            raise ValueError('locked dependency lacks version/license/integrity: ' + path)
        packages.append({'lockfile': 'app/package-lock.json', 'install_path': path,
                         **{key: entry.get(key) for key in ('version', 'license', 'integrity', 'resolved')},
                         'dev': bool(entry.get('dev')), 'optional': bool(entry.get('optional'))})
    return {'schema': 'n170.release.dependencies.v1', 'packages': packages,
            'scope': 'Locked metadata; separately installed dependencies are not bundled in source. No vulnerability clearance.'}


def source_archive(contents):
    identity = digest(encoded({name: {'bytes': len(raw), 'sha256': digest(raw)}
                               for name, raw in sorted(contents.items())}))
    payload = {'app/' + name: raw for name, raw in contents.items()}
    payload['verify_release.py'] = contents['scripts/verify-release.py']
    payload['DEPENDENCIES.json'] = encoded(dependency_inventory(contents))
    payload['COMPONENTS.json'] = encoded({'app': {'source_sha256': identity},
        'scope': 'Editable public app and original offline toolkit source. Optional upstream execution engine and accounting oracle are separately installed; neither implementation is bundled.',
        'publication_asserted': False, 'external_human_audit': False})
    manifest = {'schema': 'n170.release.archive.v1', 'source_freeze_sha256': identity,
                'files': {name: {'bytes': len(raw), 'sha256': digest(raw)} for name, raw in sorted(payload.items())},
                'trust': 'Unsigned byte commitment, not producer authentication or an external audit.', 'publication_asserted': False}
    payload['MANIFEST.json'] = encoded(manifest)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name, raw in sorted(payload.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, raw)
    return buffer.getvalue(), manifest


def toolkit_archive(contents):
    payload = {name: raw for name, raw in contents.items()
               if name.startswith(('verify_toolkit/', 'toolkit-tests/', 'verify_accounting/', 'accounting-tests/'))}
    payload.update({name: contents[name] for name in TOOLKIT_SUPPLEMENTAL_FILES})
    payload['verify_release.py'] = contents['scripts/verify-release.py']
    payload['COMPONENTS.json'] = encoded({'scope': 'Original offline toolkit and accounting source with both Python test suites, plus the standalone Node private-source reconciliation CLI, its complete local module closure, guide, result schema and notices. Upstream engine and accounting oracle are separately installed.', 'publication_asserted': False})
    payload['DEPENDENCIES.json'] = encoded({'schema': 'n170.release.dependencies.v1', 'packages': [],
        'node': {'status': 'separately_installed',
                 'engines': strict_json(contents['package.json'])['engines']['node'],
                 'builtins': ['node:crypto', 'node:fs', 'node:url', 'node:util'],
                 'scope': 'Standalone reconciliation CLI and included record verifier; no npm package installation required.'},
        'scope': 'Python standard library and Node.js built-ins for verification. Neither runtime is bundled. Optional upstream engine and Beancount oracle implementations are not bundled.'})
    identity = digest(encoded({name: digest(raw) for name, raw in sorted(payload.items())}))
    manifest = {'schema': 'n170.release.archive.v1', 'source_freeze_sha256': identity,
                'files': {name: {'bytes': len(raw), 'sha256': digest(raw)} for name, raw in sorted(payload.items())},
                'trust': 'Unsigned byte commitment, not producer authentication or external audit.', 'publication_asserted': False}
    payload['MANIFEST.json'] = encoded(manifest)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name, raw in sorted(payload.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)); info.create_system = 3
            info.external_attr = 0o100644 << 16; archive.writestr(info, raw)
    return buffer.getvalue(), manifest


def markdown_links(raw):
    return re.findall(r'\]\(([^)]+)\)', raw.decode())


def check_fixture_privacy(contents):
    """Inspect only known data-only JSON envelopes; never evaluate captured code."""
    checked = 0
    marker = re.compile(rb'/(?:Users/[A-Za-z0-9._-]+/|private/var/folders/)')
    for name, raw in contents.items():
        if not name.startswith('tests/fixtures/') or not name.endswith('.json'):
            continue
        value = strict_json(raw)
        if not isinstance(value, dict) or value.get('schema') != 'n170.run-review.v1':
            continue
        descriptors = [value['manifest'], *value['artifacts']]
        if len(descriptors) > 129:
            raise ValueError('public fixture artifact count limit: ' + name)
        total = 0
        for descriptor in descriptors:
            content = base64.b64decode(descriptor['base64'], validate=True)
            total += len(content)
            if len(content) > MAX_FILE or total > MAX_TOTAL:
                raise ValueError('public fixture decoded size limit: ' + name)
            if marker.search(content):
                raise ValueError('private host path in encoded public fixture: ' + name)
            checked += 1
    return checked


def local_target(source, link):
    url = urlsplit(link)
    if url.scheme or url.netloc or link.startswith('#'):
        return None
    return posixpath.normpath(posixpath.join(posixpath.dirname(source), unquote(url.path)))


def check_source_links(contents):
    checked = 0
    for name, raw in contents.items():
        if not name.endswith(('.md', '.txt')):
            continue
        for link in markdown_links(raw):
            target = local_target(name, link)
            if target is None:
                continue
            if target not in contents and not any(p.startswith(target.rstrip('/') + '/') for p in contents):
                raise ValueError('missing public source link in ' + name + ': ' + link)
            checked += 1
    return checked


def served_document(name, raw, documents, contents):
    if not name.endswith(('.md', '.txt')):
        return raw
    def rewrite(match):
        link = match.group(1)
        target = local_target(name, link)
        if target is None:
            return match.group(0)
        if target in documents:
            url = urlsplit(link)
            return '](' + documents[target] + ('#' + url.fragment if url.fragment else '') + ')'
        if target in contents or any(p.startswith(target.rstrip('/') + '/') for p in contents):
            return '](n170-verify-source.zip)'
        raise ValueError('missing served document link: ' + name + ': ' + link)
    return re.sub(r'\]\(([^)]+)\)', rewrite, raw.decode()).encode()


def check_client(client, contents, documents, downloads=None):
    downloads = downloads or {}
    destinations = {entry['path'] for entry in downloads.values()}
    allowed_directories = {'assets'} | {str(PurePosixPath(name).parent) for name in destinations}
    expected = set(documents.values()) | destinations | {'index.html', 'third-party-licenses.txt', 'n170-verify-source.zip', 'n170-verify-source.zip.sha256', 'n170-verify-toolkit.zip', 'n170-verify-toolkit.zip.sha256', 'verify_release.py'}
    observed = set()
    for path in client.rglob('*'):
        if path.is_symlink():
            raise ValueError('built symlink rejected')
        if path.is_dir():
            if path.relative_to(client).as_posix() not in allowed_directories:
                raise ValueError('unexpected public build directory')
            continue
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError('nonregular public build entry')
        if path.is_file():
            name = path.relative_to(client).as_posix()
            observed.add(name)
            if name.startswith('assets/'):
                if not re.fullmatch(r'assets/[A-Za-z0-9_-]+-[A-Za-z0-9_-]{8}\.(js|css)', name):
                    raise ValueError('unexpected build asset: ' + name)
                if b'sourceMappingURL' in path.read_bytes():
                    raise ValueError('source map in public build')
                expected.add(name)
    if expected != observed or not any(p.startswith('assets/') for p in observed):
        raise ValueError('unexpected public build inventory: ' + repr(sorted(expected ^ observed)))
    for extension in ('js', 'css'):
        if sum(name.startswith('assets/') and name.endswith('.' + extension) for name in observed) != 1:
            raise ValueError('public build requires exactly one ' + extension + ' entry asset')
    links = []
    for name, raw in contents.items():
        if name.endswith('.jsx'):
            links.extend((name, link) for link in re.findall(r'href=["\'](/[^"\']+)["\']', raw.decode()))
    for name in observed:
        if name.endswith(('.md', '.txt')):
            links.extend((name, link) for link in markdown_links((client / name).read_bytes()) if local_target(name, link) is not None)
    for source, link in links:
        target = unquote(urlsplit(link).path)
        target = target.lstrip('/') if target.startswith('/') else local_target(source, link)
        if target not in observed:
            raise ValueError('missing public link in ' + source + ': ' + link)
    return len(links)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preflight', action='store_true', help='Validate inputs and setup without writing a build')
    args = parser.parse_args()
    try:
        policy, contents = collect_source()
        source_links = check_source_links(contents)
        encoded_fixture_entries = check_fixture_privacy(contents)
        dependency_inventory(contents)
        if not shutil.which('node') or not shutil.which('npm'):
            raise ValueError('install Node.js matching package.json engines (including npm), then run npm ci --ignore-scripts')
        version = subprocess.check_output(['node', '--version'], text=True).strip()
        major, minor = map(int, version.lstrip('v').split('.')[:2])
        if not ((major == 20 and minor >= 19) or (major == 22 and minor >= 12) or major > 22):
            raise ValueError('unsupported Node.js ' + version + '; see package.json engines')
        if not (ROOT / 'node_modules/vite/bin/vite.js').is_file():
            raise ValueError('locked dependencies missing: run npm ci --ignore-scripts first; offline installation needs a populated npm cache')
        print(json.dumps({'status': 'preflight_passed', 'source_files': len(contents), 'source_links': source_links, 'encoded_fixture_entries': encoded_fixture_entries, 'node': version, 'python': sys.version.split()[0]}))
        if args.preflight:
            return
        archive, manifest = source_archive(contents)
        # Generated dist is disposable; original archives elsewhere are unchanged.
        for command in (['node', 'scripts/clean-build.mjs'], ['node', 'node_modules/vite/bin/vite.js', 'build'], ['node', 'scripts/prepare-sites-build.mjs']):
            subprocess.run(command, cwd=ROOT, check=True)
        _, after = collect_source()
        if contents != after:
            raise ValueError('public source changed during build; discard output and retry')
        out = ROOT / 'dist/client'
        destinations = dict(policy['documents']) | {name: entry['path'] for name, entry in policy.get('downloads', {}).items()}
        for name, dest in policy['documents'].items():
            (out / dest).write_bytes(served_document(name, contents[name], destinations, contents))
        for name, entry in policy.get('downloads', {}).items():
            target = out / entry['path']
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(contents[name])
        (out / 'n170-verify-source.zip').write_bytes(archive)
        (out / 'n170-verify-source.zip.sha256').write_text(digest(archive) + '  n170-verify-source.zip\n')
        (out / 'verify_release.py').write_bytes(contents['scripts/verify-release.py'])
        toolkit, _ = toolkit_archive(contents)
        (out / 'n170-verify-toolkit.zip').write_bytes(toolkit)
        (out / 'n170-verify-toolkit.zip.sha256').write_text(digest(toolkit) + '  n170-verify-toolkit.zip\n')
        print(json.dumps({'status': 'built', 'source_archive_sha256': digest(archive), 'source_identity': manifest['source_freeze_sha256'], 'public_links': check_client(out, contents, policy['documents'], policy.get('downloads', {})), 'publication_asserted': False}))
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Public build refused: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
