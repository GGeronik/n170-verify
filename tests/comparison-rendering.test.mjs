import assert from 'node:assert/strict';
import test from 'node:test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { generateProfileKey, createSigner } from '../src/signing.js';
import { appendPerformanceStamp, appendCorrectionStamp, compareProfiles, createProfile, effectiveStamps, normalizeProvenance } from '../src/trackRecord.js';

// Compile the real JSX component with the repository's existing build dependency.
// These are server-rendered React output checks, not browser or accessibility tests.
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const bundle = await build({ entryPoints: [path.join(ROOT, 'src/ComparisonChanges.jsx')], bundle: true, platform: 'node', format: 'esm', jsx: 'automatic', write: false, logLevel: 'silent' });
const { default: ComparisonChanges } = await import(`data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].text).toString('base64')}`);
const csv = (...rows) => `date,nav,external_flow\n${rows.join('\n')}`;
const firstInput = csv('2025-01-01,100,0', '2025-01-02,110,0', '2025-01-03,99,0');
const nextInput = csv('2025-01-03,99,0', '2025-01-04,101,0');
const correctedInput = csv('2025-01-01,100,0', '2025-01-02,120,0', '2025-01-03,102,0');
const correctedAgainInput = csv('2025-01-01,100,0', '2025-01-02,110,0', '2025-01-03,104.5,0');
const provenance = (scope = 'Synthetic USD account', currency = 'USD') => ({ ...normalizeProvenance(), account_scope: scope, currency, reviewed: true });
const options = (scope, currency) => ({ synthetic: true, provenance: provenance(scope, currency) });
async function owner(scope) {
  const key = await generateProfileKey(), signer = createSigner(key.privateKey, key.publicKey);
  const empty = await createProfile('Synthetic rendering checks', signer);
  const first = await appendPerformanceStamp(empty, firstInput, 252, signer, options(scope));
  return { signer, first };
}
async function render(previous, current) {
  const comparison = await compareProfiles(JSON.stringify(previous), JSON.stringify(current));
  return renderToStaticMarkup(createElement(ComparisonChanges, { comparison, effectiveSequences: effectiveStamps(current).map(stamp => stamp.payload.sequence) }));
}

test('prototype-shaped account aliases render exactly instead of inheriting object labels', async () => {
  for (const alias of ['__proto__', 'constructor', 'toString']) {
    const { signer, first } = await owner(alias);
    const later = await appendPerformanceStamp(first, nextInput, 252, signer, options(`${alias} later`, 'EUR'));
    const html = await render(first, later);
    assert(html.includes(`Before: ${alias}</span>`), html);
    assert(html.includes(`Now: ${alias} later</span>`), html);
    assert(html.includes(`<strong>${alias} later</strong>`), html);
  }
});

test('source-enum-looking account aliases stay exact and are not financially reclassified', async () => {
  for (const alias of ['self_reported', 'synthetic_demo']) {
    const { signer, first } = await owner('Original scope');
    const later = await appendPerformanceStamp(first, nextInput, 252, signer, options(alias));
    const html = await render(first, later);
    assert(html.includes(`Declared scope: <strong>${alias}</strong>`), html);
    assert(html.includes(`Now: ${alias}</span>`), html);
  }
});

test('markup-bearing signed scope and correction reason are escaped in the actual component', async () => {
  const { signer, first } = await owner();
  const scope = '<img src="https://invalid.test/a" onerror="alert(1)">';
  const reason = 'Synthetic review </p><script>window.n170Injected=1</script> & preserved.';
  const correction = await appendCorrectionStamp(first, 1, correctedInput, 252, signer, { ...options(scope, 'EUR'), reason });
  const html = await render(first, correction);
  assert(html.includes('&lt;img src=&quot;https://invalid.test/a&quot; onerror=&quot;alert(1)&quot;&gt;'));
  assert(html.includes('&lt;script&gt;window.n170Injected=1&lt;/script&gt; &amp; preserved.'));
  assert(!html.includes('<img')); assert(!html.includes('<script')); assert(!html.includes('src="https://invalid.test'));
  assert(html.includes('Account labels, source declarations and correction reasons remain supplied by the owner.'));
});

test('same-period table prints exact e8 financial controls and withheld volatility', async () => {
  const { signer, first } = await owner();
  const correction = await appendCorrectionStamp(first, 1, correctedInput, 252, signer, { ...options(), reason: 'Synthetic reviewed valuation correction.' });
  const html = await render(first, correction);
  // Hand controls: 100 → 110 → 99 = -1%, maximum sampled drawdown -10%;
  // 100 → 120 → 102 = +2%, maximum sampled drawdown -15%.
  assert(html.includes('<th scope="row">Time-weighted return</th><td>-1.000000%</td><td>2.000000%</td>'));
  assert(html.includes('<th scope="row">Sampled maximum drawdown</th><td>-10.000000%</td><td>-15.000000%</td>'));
  assert(html.includes('<th scope="row">Annualized volatility</th><td>Withheld</td><td>Withheld</td>'));
  assert(html.includes('<th scope="row">Disclosed return intervals</th><td>2</td><td>2</td>'));
  assert(html.includes('Same period · signed results before and after correction'));
});

test('correction of correction identifies superseded intermediate event and exact target', async () => {
  const { signer, first } = await owner();
  const second = await appendPerformanceStamp(first, nextInput, 252, signer, options('EUR account', 'EUR'));
  const third = await appendCorrectionStamp(second, 1, correctedInput, 252, signer, { ...options(), reason: 'Synthetic first correction.' });
  const fourth = await appendCorrectionStamp(third, 3, correctedAgainInput, 252, signer, { ...options(), reason: 'Synthetic correction of correction.' });
  const html = await render(first, fourth);
  assert(html.includes('1 added period · 2 corrections.'));
  assert(html.includes('href="#record-3">Record 3</a> · corrects record 1'));
  assert(html.includes('href="#record-4">Record 4</a> · corrects record 3'));
  assert.equal((html.match(/superseded by a later correction below/g) || []).length, 1);
  assert(html.includes('<th scope="row">Time-weighted return</th><td>2.000000%</td><td>4.500000%</td>'));
  assert(html.includes('<th scope="row">Sampled maximum drawdown</th><td>-15.000000%</td><td>-5.000000%</td>'));
  assert(html.includes('This adds a period; it is not a correction to the preceding period.'));
  assert(html.includes('Scope or currency changes can affect comparability.'));
});

test('adverse checked comparisons and absent comparison render no additions summary', async () => {
  const { signer, first } = await owner();
  const second = await appendPerformanceStamp(first, nextInput, 252, signer, options());
  const fork = await appendPerformanceStamp(first, csv('2025-01-03,99,0', '2025-01-04,110,0'), 252, signer, options());
  const other = await owner();
  for (const [before, after, expectedStatus] of [[second, first, 'truncated'], [second, fork, 'conflicting_history'], [first, other.first, 'replacement']]) {
    const comparison = await compareProfiles(JSON.stringify(before), JSON.stringify(after));
    assert.equal(comparison.status, expectedStatus); assert.equal(comparison.changes, null);
    assert.equal(await render(before, after), '');
  }
  assert.equal(renderToStaticMarkup(createElement(ComparisonChanges, { comparison: null, effectiveSequences: [] })), '');
  assert.equal(renderToStaticMarkup(createElement(ComparisonChanges, { comparison: { status: 'not_supplied' }, effectiveSequences: [] })), '');
});

test('identical copies state no changed signed events without inventing cards or dates', async () => {
  const { first } = await owner();
  const html = await render(first, first);
  assert(html.includes('No signed events changed or were added. This only compares the two supplied copies.'));
  assert(!html.includes('class="change-card"')); assert(!html.includes('added period'));
});
