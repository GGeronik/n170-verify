import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import {
  COUNTERFACTUAL_VERSION,
  COUNTERFACTUAL_INPUT_SCHEMA,
  LEAN_MANIFEST_SCHEMA,
  computeMerkleRoot,
  computeSingleBookPatternProfile,
  sha256Hex,
  verifyCounterfactualAttribution,
} from '../src/counterfactualAttribution.js';
import {
  verifyCounterfactualAttribution as verifyCliCounterfactual,
  runCli,
} from '../scripts/verify-counterfactual.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURES = path.join(ROOT, 'tests/fixtures/counterfactual');
const STATS_FIXTURES = path.join(ROOT, 'tests/fixtures/stats');
const readFixture = (name) => JSON.parse(fs.readFileSync(path.join(FIXTURES, name), 'utf8'));
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');

const manifestBytes = fs.readFileSync(path.join(FIXTURES, 'MANIFEST.json'));
const manifest = JSON.parse(manifestBytes);

function assertDeepFrozen(obj, label = 'root') {
  if (obj === null || typeof obj !== 'object') return;
  assert(Object.isFrozen(obj), `${label} must be frozen`);
  for (const [k, v] of Object.entries(obj)) {
    assertDeepFrozen(v, `${label}.${k}`);
  }
}

function compareDeep(actual, expected, fieldPath = 'root') {
  if (typeof expected === 'number') {
    assert.equal(typeof actual, 'number', `${fieldPath}: expected number`);
    assert(Number.isFinite(actual), `${fieldPath}: expected finite number`);
    if (Number.isInteger(expected) && Number.isInteger(actual)) {
      assert.equal(actual, expected, `${fieldPath}: integer match`);
    } else if (expected === 0) {
      assert.equal(actual, 0, `${fieldPath}: exact zero`);
    } else {
      const tol = 1e-12 * Math.max(1, Math.abs(expected));
      assert(
        Math.abs(actual - expected) <= tol,
        `${fieldPath}: ${actual} vs ${expected} (tol ${tol})`,
      );
    }
    return;
  }
  if (expected === null || typeof expected !== 'object') {
    assert.equal(actual, expected, `${fieldPath}: primitive match`);
    return;
  }
  if (Array.isArray(expected)) {
    assert(Array.isArray(actual), `${fieldPath}: expected array`);
    assert.equal(actual.length, expected.length, `${fieldPath}: array length`);
    for (let i = 0; i < expected.length; i += 1) {
      compareDeep(actual[i], expected[i], `${fieldPath}[${i}]`);
    }
    return;
  }
  assert(
    actual !== null && typeof actual === 'object' && !Array.isArray(actual),
    `${fieldPath}: expected object`,
  );
  assert.deepEqual(
    Object.keys(actual).sort(),
    Object.keys(expected).sort(),
    `${fieldPath}: object keys`,
  );
  for (const key of Object.keys(expected)) {
    compareDeep(actual[key], expected[key], `${fieldPath}.${key}`);
  }
}

test('counterfactual fixture manifest and Python oracle match sealed SHA-256 digests', () => {
  assert.equal(
    digest(manifestBytes),
    'b77d253d7b0d4a09fed5293f092701a83f075529bbae72bd35c7cc8e30050f16',
  );
  assert.equal(manifest.files.length, 48);

  const oracleBytes = fs.readFileSync(path.join(ROOT, 'tests/counterfactual_oracle.py'));
  assert.equal(
    digest(oracleBytes),
    '520718b84f7809a13a271585655ed9fb32aa57d6babfe878a62136c782873972',
  );
  assert.equal(manifest.oracle.sha256, digest(oracleBytes));

  const listed = manifest.files.map((entry) => path.basename(entry.path));
  assert.equal(new Set(listed).size, listed.length);
  assert.deepEqual(
    fs
      .readdirSync(FIXTURES)
      .filter((name) => name !== 'MANIFEST.json')
      .sort(),
    listed.slice().sort(),
  );

  for (const entry of manifest.files) {
    assert.equal(entry.path, `tests/fixtures/counterfactual/${path.basename(entry.path)}`);
    const data = fs.readFileSync(path.join(ROOT, entry.path));
    assert.equal(data.length, entry.bytes, entry.path);
    assert.equal(digest(data), entry.sha256, entry.path);
  }
});

for (const entry of manifest.files.filter((file) => file.role === 'expected')) {
  const expected = readFixture(path.basename(entry.path));
  test(`browser engine and standalone CLI match sealed fixture ${expected.fixture}`, () => {
    const inputName = `${expected.fixture}.input.json`;
    const inputPath = path.join(FIXTURES, inputName);
    const inputBytes = fs.readFileSync(inputPath);
    const inputSha256 = digest(inputBytes);
    assert.equal(inputSha256, expected.fixture_sha256);
    assert.equal(sha256Hex(inputBytes), expected.fixture_sha256);

    const inputObj = JSON.parse(inputBytes.toString('utf8'));
    const actualBrowser = verifyCounterfactualAttribution(inputObj, {
      fixtureSha256: inputSha256,
    });
    const actualBrowserFromText = verifyCounterfactualAttribution(inputBytes.toString('utf8'));
    const actualCli = verifyCliCounterfactual(inputObj, {
      fixtureSha256: inputSha256,
    });

    assertDeepFrozen(actualBrowser);
    assertDeepFrozen(actualCli);
    compareDeep(actualBrowser, expected, `browser(${expected.fixture})`);
    compareDeep(actualBrowserFromText, expected, `browserText(${expected.fixture})`);
    compareDeep(actualCli, expected, `cli(${expected.fixture})`);

    const cliResp = runCli([inputPath]);
    assert.equal(cliResp.exitCode, expected.status === 'OK' ? 0 : 1);
    compareDeep(JSON.parse(cliResp.output), expected, `runCli(${expected.fixture})`);
  });
}

test('computeSingleBookPatternProfile matches single and benchmarked book profiles', () => {
  const cf01Input = readFixture('CF01.input.json');
  const cf01Expected = readFixture('CF01.expected.json');
  const actualE8 = cf01Input.books.ACTUAL.map((x) => x.return_e8);
  const benchE8 = cf01Input.books.FIXED_BENCHMARK.map((x) => x.return_e8);

  const profileWithBench = computeSingleBookPatternProfile(
    actualE8,
    benchE8,
    cf01Input.periods_per_year,
  );
  assertDeepFrozen(profileWithBench);
  compareDeep(profileWithBench, cf01Expected.books.ACTUAL, 'CF01.ACTUAL');

  const cf05Input = readFixture('CF05.input.json');
  const cf05Expected = readFixture('CF05.expected.json');
  const singleProfile = computeSingleBookPatternProfile(
    cf05Input.books.ACTUAL.map((x) => x.return_e8),
    null,
    cf05Input.periods_per_year,
  );
  assertDeepFrozen(singleProfile);
  compareDeep(singleProfile, cf05Expected.books.ACTUAL, 'CF05.ACTUAL');

  assert.equal(computeSingleBookPatternProfile([100, 200, 300], null, 252), null);
  assert.equal(computeSingleBookPatternProfile([100, 200, 300, 400], null, 13), null);
  assert.equal(computeSingleBookPatternProfile([100, 200, 300, -100000000], null, 252), null);

  const l0 = sha256Hex('leaf-0');
  const l1 = sha256Hex('leaf-1');
  const l2 = sha256Hex('leaf-2');
  assert.equal(computeMerkleRoot([l0, l1, l2]).length, 64);
  assert.equal(COUNTERFACTUAL_VERSION, 'n170.verify.counterfactual-attribution.v1');
  assert.equal(COUNTERFACTUAL_INPUT_SCHEMA, 'n170.verify.counterfactual-input.v1');
  assert.equal(LEAN_MANIFEST_SCHEMA, 'n170.verify.lean-replay-manifest.v1');
});

test('standalone CLI verifier enforces import boundaries and exit codes', () => {
  const cliSource = fs.readFileSync(
    path.join(ROOT, 'scripts/verify-counterfactual.mjs'),
    'utf8',
  );
  const cliImports = [
    ...cliSource.matchAll(/(?:import|export)\s[^;]*?from\s*['"]([^'"]+)['"]/g),
  ].map((m) => m[1]);
  assert(cliImports.length > 0);
  assert(cliImports.every((spec) => spec.startsWith('node:')));
  assert(!/\b(?:import\s*\(|eval\s*\(|new\s+Function\s*\()/.test(cliSource));

  const engineSource = fs.readFileSync(
    path.join(ROOT, 'src/counterfactualAttribution.js'),
    'utf8',
  );
  const engineImports = [
    ...engineSource.matchAll(/(?:import|export)\s[^;]*?from\s*['"]([^'"]+)['"]/g),
  ].map((m) => m[1]);
  assert.deepEqual(engineImports, ['./statistics.js']);
  assert(
    !/\b(?:document|window|fetch|localStorage|sessionStorage|WebSocket|XMLHttpRequest)\b/.test(
      engineSource,
    ),
  );

  const helpOut = execFileSync(
    process.execPath,
    [path.join(ROOT, 'scripts/verify-counterfactual.mjs'), '--help'],
    { encoding: 'utf8' },
  );
  assert(helpOut.startsWith('Usage: node scripts/verify-counterfactual.mjs '));

  assert.equal(runCli(['--help']).exitCode, 0);
  assert.equal(runCli([]).exitCode, 3);
  assert.equal(runCli(['--unknown']).exitCode, 3);
  assert.equal(runCli([path.join(FIXTURES, 'DOES_NOT_EXIST.json')]).exitCode, 3);
  assert.equal(runCli([path.join(FIXTURES, 'CF01.input.json')]).exitCode, 0);
  assert.equal(runCli([path.join(FIXTURES, 'CF08.input.json')]).exitCode, 1);
});

let renderCounterfactualPanel;
async function counterfactualMarkup(props) {
  if (!renderCounterfactualPanel) {
    const [{ build }, { createElement }, { renderToStaticMarkup }] = await Promise.all([
      import('esbuild'),
      import('react'),
      import('react-dom/server'),
    ]);
    const bundle = await build({
      entryPoints: [path.join(ROOT, 'src/CounterfactualAttributionPanel.jsx')],
      bundle: true,
      platform: 'node',
      format: 'esm',
      jsx: 'automatic',
      write: false,
      logLevel: 'silent',
      plugins: [
        {
          name: 'shared-react',
          setup(builder) {
            builder.onResolve({ filter: /^react(?:\/|$)/ }, (args) => ({
              path: import.meta.resolve(args.path),
              external: true,
            }));
          },
        },
      ],
    });
    const { default: CounterfactualAttributionPanel } = await import(
      `data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].text).toString('base64')}`
    );
    renderCounterfactualPanel = (value) =>
      renderToStaticMarkup(createElement(CounterfactualAttributionPanel, value));
  }
  return renderCounterfactualPanel(props);
}

test('CounterfactualAttributionPanel SSR renders stamp pattern profiles and 4-book attribution report', async () => {
  const recordProfile = JSON.parse(
    fs.readFileSync(path.join(STATS_FIXTURES, 'F12-R.record.json'), 'utf8'),
  );
  const cf01Text = fs.readFileSync(path.join(FIXTURES, 'CF01.input.json'), 'utf8');
  const html = await counterfactualMarkup({
    profile: recordProfile,
    counterfactualInput: cf01Text,
    onCounterfactualInputChange: () => {},
  });

  assert(html.includes('Behavioral pattern profile and counterfactual attribution (unsigned)'));
  assert(html.includes('Record 1 · 2024-01-31 – 2025-03-31'));
  assert(html.includes('DISCIPLINED_RISK_SCALING'));
  assert(html.includes('MIRROR_SHADOW'));
  assert(html.includes('CLEAN_SHADOW'));
  assert(html.includes('FIXED_BENCHMARK'));
  assert(html.includes('Systematic Process Edge'));
  assert(html.includes('Initial Book / Legacy Transition Drag'));
  assert(html.includes('Discretionary Execution &amp; Risk-Management Alpha'));
  assert(html.includes('Pre-Committed Decision Log Hash-Chain Summary'));
  assert(html.includes('QuantConnect LEAN Replay Receipt Verification'));
  assert(html.includes('ca860c0bfd22711ebf511d015f36a37a2ab87b728ec8fc7bdb70afe251e89c5f'));

  const refusalText = fs.readFileSync(path.join(FIXTURES, 'CF08.input.json'), 'utf8');
  const refusalHtml = await counterfactualMarkup({
    counterfactualInput: refusalText,
  });
  assert(refusalHtml.includes('CF_PROHIBITED_DISCLOSURE_FIELD'));
  assert(refusalHtml.includes('PROHIBITED_FIELD:tickers'));
});
