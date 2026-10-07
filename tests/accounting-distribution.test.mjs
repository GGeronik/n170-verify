// Packaging contracts: retained historical receipts and runnable current offline modules.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";
const app = fileURLToPath(new URL("../", import.meta.url));
function check(body) {
  const result = spawnSync("python3", ["-B", "-c", String.raw`
import hashlib, importlib.util, io, json, os, subprocess, sys, tempfile, zipfile
from pathlib import Path
app = Path(sys.argv[1])
node = sys.argv[2]
policy = json.loads((app/'scripts/public-source-inventory.json').read_bytes())
spec = importlib.util.spec_from_file_location('public_build', app/'scripts/build-public.py')
build = importlib.util.module_from_spec(spec); spec.loader.exec_module(build)
${body}
`, app, process.execPath], {encoding:"utf8", timeout:60_000, maxBuffer:1024*1024});
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, result.stderr || result.stdout);
}
test("older challenge downloads retain all four accepted receipts and their original source baseline", () => check(String.raw`
pins = {'README.md':'ed89f81f7562b45b1d03a83d7151f57c2b938d3d3d7520a616a6df2fd69694b0',
'SHA256SUMS':'e41b5e2fdac20ea18c6bf6eb1969cf0822e2439e463ca9bf1165f2071e190c4e',
'public-challenge-kit.zip':'5802a438f08afdad9e1d74d7ee9f1ab03b86a059e9d77bb30ea977148c9a0a22',
'verify_archive.py':'0fb1cd2bd5da6ec6b8f809121ab76219ac36560a2d7cfca056c03eaab5c6fda1'}
assert {name for name in policy['downloads'] if name.startswith('release-assets/challenge-kit/')} == {'release-assets/challenge-kit/'+name for name in pins}
for name, expected in pins.items():
 raw = (app/'dist/client/challenge-kit'/name).read_bytes()
 assert hashlib.sha256(raw).hexdigest() == expected, name
 assert raw == (app/'release-assets/challenge-kit'/name).read_bytes(), name
with zipfile.ZipFile(app/'dist/client/challenge-kit/public-challenge-kit.zip') as kit:
 assert hashlib.sha256(kit.read('payload/accepted-source.zip')).hexdigest() == 'efa705edb9782568aba7561cea448f4e824f1a58cb745930471fb6cee39fe3e5'
`));
test("public build refuses a changed pinned download, path collision, or extra active release asset", () => check(String.raw`
original, contents = build.collect_source(app)
with tempfile.TemporaryDirectory() as directory:
 root = Path(directory)
 for name, raw in contents.items():
  path = root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
 target = root/'release-assets/challenge-kit/README.md'; old = target.read_bytes()
 def refuses():
  try: build.collect_source(root)
  except ValueError: return
  raise AssertionError('unsafe download change accepted')
 target.write_bytes(old+b'changed'); refuses(); target.write_bytes(old)
 extra=root/'release-assets/challenge-kit/unlisted.txt'; extra.write_text('synthetic'); refuses(); extra.unlink()
 changed=json.loads(json.dumps(original)); changed['downloads']['release-assets/challenge-kit/README.md']['path']='assets/injected.js'
 (root/build.INVENTORY).write_text(json.dumps(changed)); refuses()
 changed['downloads']['release-assets/challenge-kit/README.md']['path']='challenge-kit/SHA256SUMS'
 (root/build.INVENTORY).write_text(json.dumps(changed)); refuses()
`));
test("combined toolkit includes original Python packages/tests and standalone Node checker, runs offline, and excludes optional implementations", () => check(String.raw`
with zipfile.ZipFile(app/'dist/client/n170-verify-toolkit.zip') as archive:
 manifest=json.loads(archive.read('MANIFEST.json'))
 supplemental={'scripts/verify-reconciliation.mjs','scripts/reconciliation-input.mjs',
 'scripts/reconciliation-source.mjs','scripts/verify-record.mjs',
 'docs/verify-reconciliation.md','docs/verify-reconciliation-result.schema.json','LICENSE','NOTICE'}
 assert supplemental <= set(policy['files'])
 expected={name for name in policy['files'] if name.startswith(('verify_toolkit/','toolkit-tests/','verify_accounting/','accounting-tests/'))} | supplemental
 assert set(archive.namelist()) == expected | {'MANIFEST.json','COMPONENTS.json','DEPENDENCIES.json','verify_release.py'}
 for name in supplemental:
  assert archive.read(name)==(app/name).read_bytes(), name
 assert set(manifest['files']) == set(archive.namelist())-{'MANIFEST.json'}
 for name, entry in manifest['files'].items():
  raw=archive.read(name); assert len(raw)==entry['bytes'] and hashlib.sha256(raw).hexdigest()==entry['sha256']
 dependencies=json.loads(archive.read('DEPENDENCIES.json'))
 assert dependencies['packages']==[]
 assert dependencies['node']['status']=='separately_installed'
 assert dependencies['node']['engines']==json.loads((app/'package.json').read_bytes())['engines']['node']
 assert dependencies['node']['builtins']==['node:crypto','node:fs','node:url','node:util']
 with tempfile.TemporaryDirectory() as directory:
  archive.extractall(directory)
  assert not any((Path(directory)/name).exists() for name in ('app','src','node_modules','package.json'))
  env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'}; env.pop('PYTHONPATH',None); env.pop('N170_BEANCOUNT_PYTHON',None)
  node_env=dict(env); node_env.pop('NODE_OPTIONS',None); node_env.pop('NODE_PATH',None)
  result=subprocess.run([node,'scripts/verify-reconciliation.mjs','--help'],cwd=directory,env=node_env,capture_output=True,text=True,timeout=10)
  assert result.returncode==0,result.stderr
  assert result.stdout.startswith('Usage: node scripts/verify-reconciliation.mjs '), result.stdout
  assert result.stderr=='',result.stderr
  for module in ('verify_toolkit.run_review_v2','verify_toolkit.accounting_collector','verify_accounting'):
   result=subprocess.run([sys.executable,'-B','-m',module,'--help'],cwd=directory,env=env,capture_output=True,text=True,timeout=10)
   assert result.returncode==0,(module,result.stderr)
  result=subprocess.run([sys.executable,'-B','-m','verify_accounting','check','verify_accounting/fixtures/gain.json'],cwd=directory,env=env,capture_output=True,text=True,timeout=10)
  assert result.returncode==0,result.stderr
  assert json.loads(result.stdout)['status']=='RECONCILED_UNDER_ASSUMPTIONS'
boundaries=json.loads((app/'component-boundaries.json').read_bytes())
assert boundaries['beancount']['upstream_code_bundled'] is False
assert boundaries['freqtrade']['engine_bundled'] is False
assert boundaries['release']['source_authentication'] is False
`));
