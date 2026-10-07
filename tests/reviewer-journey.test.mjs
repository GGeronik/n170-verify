import assert from 'node:assert/strict';
import test from 'node:test';
import { build } from 'esbuild';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateProfileKey, createSigner } from '../src/signing.js';
import { createProfile, appendPerformanceStamp, normalizeProvenance } from '../src/trackRecord.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
async function render(name) {
  const bundle = await build({ entryPoints: [path.join(ROOT, `src/${name}.jsx`)], bundle: true, platform: 'node', format: 'esm', jsx: 'automatic', write: false, logLevel: 'silent' });
  const { default: Component } = await import(`data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].text).toString('base64')}`);
  return renderToStaticMarkup(createElement(Component));
}

test('account help exposes loss, flow timing, coverage and correction boundaries in a native disclosure', async () => {
  const html = await render('AccountPreparationHelp');
  assert.match(html, /^<details[^>]*><summary>What to reconcile: losses, flows and coverage<\/summary>/);
  for (const text of ['Keep every observed gain and loss', 'Transfers entirely within that scope', 'retained dividends and interest', 'A zero net flow does not prove', 'Source authenticity, freshness and completeness are not established', 'Zero or negative NAV, total loss', 'same period boundaries', 'correction reasons are shared']) assert(html.includes(text), text);
});

test('the visible independent commands run unchanged except for the documented quoted paths', async () => {
  const html = await render('IndependentVerifierHelp');
  const source = await readFile(path.join(ROOT, 'src/IndependentVerifierHelp.jsx'), 'utf8');
  const commands = [...source.matchAll(/\{'(node scripts\/verify-record\.mjs [^']+)'\}/g)].map(match=>match[1]);
  assert.equal(commands.length, 2);
  assert.match(html, /Exit 0:/); assert.match(html, /Exit 1:/); assert.match(html, /Exit 2:/);
  assert.match(html, /does not check separate research\/tool observations or AuditZK attestation/);
  const folder = await mkdtemp(path.join(tmpdir(), 'n170 reviewer command '));
  try {
    const key = await generateProfileKey();
    const signer = createSigner(key.privateKey, key.publicKey);
    const empty = await createProfile('Synthetic reviewer instructions', signer);
    const options = { synthetic: true, provenance: { ...normalizeProvenance(), account_scope: 'Synthetic loss and flows', currency: 'EUR', reviewed: true } };
    const previous = await appendPerformanceStamp(empty, 'date,nav,external_flow\n2025-01-01,100,0\n2025-01-02,110,20\n2025-01-03,89,-10', 252, signer, options);
    const current = await appendPerformanceStamp(previous, 'date,nav,external_flow\n2025-01-03,89,0\n2025-01-04,88,0', 252, signer, options);
    const currentFile = path.join(folder, 'current record.json'), previousFile = path.join(folder, 'previous record.json');
    await writeFile(currentFile, JSON.stringify(current));
    await writeFile(previousFile, JSON.stringify(previous));
    // Parse the fixed displayed command without a shell, then replace only its
    // two documented file placeholders. Spaces in real paths remain intact.
    const run = command => {
      const args = [...command.matchAll(/"([^"]+)"|(\S+)/g)].map(match=>match[1] || match[2]);
      assert.equal(args.shift(), 'node');
      return spawnSync(process.execPath, args.map(arg=>arg === '/path/to/current-record.json' ? currentFile : arg === '/path/to/previous-record.json' ? previousFile : arg), { cwd: ROOT, encoding: 'utf8' });
    };
    for (const command of commands) {
      const checked = run(command); assert.equal(checked.status, 0, checked.stderr);
      const result = JSON.parse(checked.stdout); assert.equal(result.source_authenticated, false);
    }
    const extended = JSON.parse(run(commands[1]).stdout);
    assert.equal(extended.previous_copy.status, 'extended');
    await writeFile(currentFile, '{"incomplete":');
    assert.equal(run(commands[0]).status, 1);
    await writeFile(currentFile, JSON.stringify(previous));
    await writeFile(previousFile, JSON.stringify(current));
    const shortened = run(commands[1]); assert.equal(shortened.status, 2);
    assert.equal(JSON.parse(shortened.stdout).previous_copy.status, 'truncated');
  } finally { await rm(folder, { recursive: true, force: true }); }
});
