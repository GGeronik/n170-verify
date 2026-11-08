import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runCli, verifyReconciliation } from '../scripts/verify-reconciliation.mjs';

// Author tests cover input/privacy boundaries. Independently owned financial
// expectations are intentionally not imported, recreated or read here.
test('help is fixed, offline and explains all four result states', () => {
  const result = runCli(['--help']);
  assert.equal(result.exitCode, 0);
  for (const status of ['VERIFIED_UNDER_OWNER_ASSERTIONS', 'MISMATCH', 'NOT_ASSESSABLE', 'INVALID_INPUT']) assert.ok(result.output.includes(status));
  assert.ok(result.output.includes('--event-sha256'));
});

test('unknown, duplicate, missing and placeholder flags refuse without reflecting private input', () => {
  const secret = '/private/ACCOUNT-SENSITIVE-123/values.csv';
  const cases = [[], ['--help', secret], ['--record', secret],
    ['--record', secret, '--record', secret, '--event-sha256', 'a'.repeat(64)],
    ['--record', secret, '--event-sha256', 'EVENT_SHA256', '--reconciliation', secret],
    ['--record', secret, '--event-sha256', 'a'.repeat(64), '--execute', secret],
  ];
  for (const args of cases) {
    const result = runCli(args); assert.equal(result.exitCode, 3);
    assert.equal(JSON.parse(result.output).status, 'INVALID_INPUT');
    assert.ok(!result.output.includes(secret)); assert.ok(!result.output.includes('ACCOUNT-SENSITIVE'));
  }
});

test('filesystem errors are fixed codes without path or OS error disclosure', () => {
  const secret = join(tmpdir(), 'missing-SECRET-ACCOUNT-532593.json');
  const result = runCli(['--record', secret, '--event-sha256', 'a'.repeat(64), '--reconciliation', secret]);
  assert.equal(result.exitCode, 3); assert.ok(!result.output.includes(secret)); assert.ok(!result.output.includes('ENOENT'));
});

test('symlink, directory and oversized signed inputs refuse before private parsing', () => {
  const folder = mkdtempSync(join(tmpdir(), 'n170-source-check-structure-'));
  try {
    const regular = join(folder, 'record.json'), link = join(folder, 'link.json');
    writeFileSync(regular, 'x'.repeat(2000001)); symlinkSync(regular, link);
    for (const path of [folder, regular, link]) {
      const result = runCli(['--record', path, '--event-sha256', 'a'.repeat(64), '--reconciliation', regular]);
      assert.equal(result.exitCode, 3); assert.ok(!result.output.includes(folder));
    }
  } finally { rmSync(folder, { recursive: true, force: true }); }
});

test('malformed inputs cannot leak values through JSON or signed-verifier diagnostics', () => {
  for (const artifact of ['{"secret":"937234.019342 SECRET-ACCOUNT"}', '{"kind":1,"kind":2}', '[]', 'null']) {
    const result = verifyReconciliation('<script>PRIVATE-937234</script>', artifact, 'a'.repeat(64));
    assert.equal(result.status, 'INVALID_INPUT');
    const output = JSON.stringify(result);
    assert.ok(!output.includes('937234')); assert.ok(!output.includes('SECRET-ACCOUNT')); assert.ok(!output.includes('<script>'));
    assert.deepEqual(result.selected_event, null);
  }
});

test('explicit event digest grammar rejects ambiguous selection', () => {
  for (const digest of ['', 'A'.repeat(64), 'a'.repeat(63), 'a'.repeat(65), 1, null, undefined]) {
    const result = verifyReconciliation('{}', '{}', digest);
    assert.deepEqual(result.reasons, ['INVALID_EVENT_SELECTION']);
  }
});

test('independent checker modules only statically import builtins and listed standalone modules', () => {
  const allowed = new Set(['./verify-record.mjs', './reconciliation-source.mjs', './reconciliation-input.mjs','./verify-continuity.mjs','./verify-reconciliation.mjs','./verify-witness-receipt.mjs','./headline.mjs','./ots-verifier.mjs','./verify-broker-source.mjs','./verify-counterfactual.mjs','./verify-dkim-statement.mjs','./verify-ech0196-statement.mjs','./verify-tlog.mjs','./witness-fetch.mjs']);
  for (const name of ['verify-reconciliation.mjs', 'reconciliation-source.mjs', 'reconciliation-input.mjs','headline.mjs','verify-headline.mjs','verify-witness-receipt.mjs','ots-verifier.mjs','verify-broker-source.mjs','verify-counterfactual.mjs','verify-dkim-statement.mjs','verify-ech0196-statement.mjs','verify-tlog.mjs','witness-fetch.mjs']) {
    const text = readFileSync(new URL(`../scripts/${name}`, import.meta.url), 'utf8');
    for (const match of text.matchAll(/\b(?:import|export)\s[^;]*?\bfrom\s*['"]([^'"]+)['"]/g)) assert.ok(match[1].startsWith('node:') || allowed.has(match[1]), `${name} imports outside standalone boundary`);
    assert.ok(!/\bimport\s*\(|\beval\s*\(|\bnew\s+Function\s*\(/.test(text), `${name} must not load input-derived code`);
  }
});
