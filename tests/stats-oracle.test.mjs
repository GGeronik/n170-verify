import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const tests = dirname(fileURLToPath(import.meta.url));
const root = resolve(tests, '..');
const fixtures = join(tests, 'fixtures', 'stats');
const manifest = JSON.parse(readFileSync(join(fixtures, 'MANIFEST.json'), 'utf8'));
const hash = bytes => createHash('sha256').update(bytes).digest('hex');

test('statistics fixtures match their sealed manifest', () => {
  assert.equal(manifest.schema, 'n170.verify.fixture-manifest.v1');
  assert.equal(hash(readFileSync(join(root, manifest.oracle.path))), manifest.oracle.sha256);
  const listed = manifest.files.map(row => row.path);
  assert.deepEqual(listed, [...listed].sort());
  assert.equal(new Set(listed).size, listed.length);
  for (const row of manifest.files) {
    assert.ok(['input', 'expected', 'notes', 'vector'].includes(row.role));
    assert.equal(dirname(row.path), 'tests/fixtures/stats');
    const bytes = readFileSync(join(root, row.path));
    assert.equal(bytes.length, row.bytes, row.path);
    assert.equal(hash(bytes), row.sha256, row.path);
  }
  assert.deepEqual(readdirSync(fixtures).sort(),
    ['MANIFEST.json', ...listed.map(path => path.split('/').at(-1))].sort());
});

test('the oracle reproduces its sealed expectations within tolerance', () => {
  function compare(actual, expected, location, z) {
    if (Array.isArray(expected)) {
      assert.ok(Array.isArray(actual), location);
      assert.equal(actual.length, expected.length, location);
      expected.forEach((value, i) => compare(actual[i], value, `${location}[${i}]`, expected[i]?.z ?? z));
    } else if (expected !== null && typeof expected === 'object') {
      assert.deepEqual(Object.keys(actual), Object.keys(expected), location);
      const pointZ = expected.z ?? z;
      for (const key of Object.keys(expected)) compare(actual[key], expected[key], `${location}.${key}`, pointZ);
    } else if (typeof expected === 'number') {
      assert.ok(Number.isFinite(actual), location);
      const field = location.split('.').at(-1);
      if (['T', 'periods_per_year', 'mintrl'].includes(field)) assert.equal(actual, expected, location);
      else {
        const isPhi = field === 'psr0' || field === 'phi';
        const tolerance = isPhi && Math.abs(z) <= 8 ? 1e-15 : 1e-12 * Math.abs(expected);
        assert.ok(Math.abs(actual - expected) <= tolerance,
          `${location}: ${actual} vs ${expected}, tolerance ${tolerance}`);
      }
    } else assert.equal(actual, expected, location);
  }
  const inputs = manifest.files.filter(row => row.path.endsWith('.input.json'));
  for (const row of inputs) {
    const expected = JSON.parse(readFileSync(join(root, row.path.replace('.input.json', '.expected.json')), 'utf8'));
    const run = spawnSync(process.env.N170_STATS_PYTHON ?? 'python3',
      ['-B', join(root, manifest.oracle.path), 'compute', join(root, row.path)], { encoding: 'utf8' });
    assert.equal(run.status, 0, `${row.path}: ${run.stderr}`);
    compare(JSON.parse(run.stdout), expected, row.path, expected.z);
  }
});
