import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateProfileKey, createSigner } from '../src/signing.js';
import { createProfile, appendPerformanceStamp, appendCorrectionStamp, normalizeProvenance, profileKeyCode } from '../src/trackRecord.js';
import { buildReviewPackage } from '../src/reviewPackage.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BASE = process.env.N170_PREVIEW_URL || 'http://127.0.0.1:4174/';
const origin = new URL(BASE).origin;
assert(['127.0.0.1', 'localhost', '[::1]'].includes(new URL(BASE).hostname), 'Use a local production preview only.');
const out = path.resolve(process.env.N170_EVIDENCE_DIR || path.join(ROOT, 'docs/verification/2026-09-17'));
await mkdir(out, { recursive: true });
const channel = process.env.N170_BROWSER_CHANNEL || undefined;
const fixtureOnly = process.argv.includes('--fixtures-only');
let browser, context;
const tests = [], errors = [], consoleMessages = [], externalRequests = [], screenshots = [], implementation = {};
let page, failure;


const csv = (...rows) => `date,nav,external_flow\n${rows.join('\n')}`;
const firstCsv = csv('2025-01-01,100,0', '2025-01-02,110,0', '2025-01-03,99,0');
const secondCsv = csv('2025-01-03,99,0', '2025-01-04,101,0');
const correctedCsv = csv('2025-01-01,100,0', '2025-01-02,120,0', '2025-01-03,102,0');
const correctedAgainCsv = csv('2025-01-01,100,0', '2025-01-02,110,0', '2025-01-03,104.5,0');
const scope = 'Synthetic <img src=https://invalid.test/scope onerror=window.n170Injected=1>';
const reason = 'Synthetic source review <script>window.n170Injected=1</script> preserved as text.';
const name = 'Synthetic retained-copy comparison';
const metadata = (accountScope, currency) => ({ ...normalizeProvenance(), account_scope: accountScope, currency, reviewed: true });
const json = value => JSON.stringify(value);

async function test(name, action) {
  try { await action(); tests.push({ name, status: 'passed' }); console.log('PASS', name); }
  catch (error) { tests.push({ name, status: 'failed', error: error.message }); throw error; }
}
async function capture(filename) {
  const target = path.join(out, filename);
  await page.screenshot({ path: target, fullPage: true });
  screenshots.push(target);
}
async function earlierPanel() {
  const summary = page.getByText('Add earlier evidence for comparison', { exact: true });
  if (!await summary.locator('..').evaluate(el => el.open)) await summary.click();
}
async function choose(value, previous = false, fileName = previous ? 'synthetic-previous.json' : 'synthetic-current.json') {
  if (previous) await earlierPanel();
  const text = typeof value === 'string' ? value : json(value);
  await page.locator('input[type=file]').nth(previous ? 1 : 0).setInputFiles({ name: fileName, mimeType: fileName.endsWith('.html') ? 'text/html' : 'application/json', buffer: Buffer.from(text) });
  await page.waitForFunction(() => !document.querySelector('fieldset.review-inputs').disabled);
}
async function clearPrevious() {
  await earlierPanel();
  const remove = page.getByRole('button', { name: 'Remove previous copy', exact: true });
  if (await remove.count()) await remove.click();
}
async function checkRecord(current, previous, expectedStatus) {
  await choose(current);
  if (previous === undefined) await clearPrevious(); else await choose(previous, true);
  await page.getByRole('button', { name: 'Check record', exact: true }).click();
  await page.locator('.review-result').waitFor();
  if (expectedStatus) assert((await page.locator('.review-result').innerText()).includes(expectedStatus));
}
async function inert() {
  assert.equal(await page.evaluate(() => window.n170Injected), 0);
  assert.equal(await page.locator('img[src*="invalid.test"],script:not([type="module"])[src*="invalid.test"],#n170-injected').count(), 0);
  assert.deepEqual(externalRequests, []);
}
async function rejected(pattern) {
  await page.getByRole('button', { name: 'Check record', exact: true }).click();
  const alert = page.getByRole('alert').first();
  await alert.waitFor();
  assert.match(await alert.innerText(), pattern);
  assert.equal(await page.locator('.review-result').count(), 0);
  assert.equal(await page.locator('#changes-heading').count(), 0);
}
async function correctionRow(record, row) {
  const card = page.locator('.change-card').filter({ has: page.locator(`a[href="#record-${record}"]`) });
  return card.locator('tbody tr').nth(row).locator('th,td').allTextContents();
}

try {
  for (const file of ['src/ComparisonChanges.jsx', 'src/EmployerReview.jsx', 'src/trackRecord.js', 'src/reviewPackage.js', 'src/calculator.js', 'dist/client/index.html', 'scripts/browser-comparison.mjs']) {
    implementation[file] = createHash('sha256').update(await readFile(path.join(ROOT, file))).digest('hex');
  }
  const key = await generateProfileKey();
  const signer = createSigner(key.privateKey, key.publicKey);
  const empty = await createProfile(name, signer);
  const first = await appendPerformanceStamp(empty, firstCsv, 252, signer, { synthetic: true, provenance: metadata('Synthetic selected USD account', 'USD') });
  const added = await appendPerformanceStamp(first, secondCsv, 252, signer, { synthetic: true, provenance: metadata('Synthetic selected EUR account', 'EUR') });
  const corrected = await appendCorrectionStamp(added, 1, correctedCsv, 252, signer, { synthetic: true, reason, provenance: metadata(scope, 'GBP') });
  const extended = await appendCorrectionStamp(corrected, 3, correctedAgainCsv, 252, signer, { synthetic: true, reason: 'Synthetic second review of the same period.', provenance: metadata('Synthetic reviewed USD account', 'USD') });
  const fork = await appendPerformanceStamp(first, csv('2025-01-03,99,0', '2025-01-04,110,0'), 252, signer, { synthetic: true });
  const otherKey = await generateProfileKey();
  const otherSigner = createSigner(otherKey.privateKey, otherKey.publicKey);
  const replacement = await appendPerformanceStamp(await createProfile(name, otherSigner), firstCsv, 252, otherSigner, { synthetic: true });
  // Independent hand-calculated controls, not expectations copied from comparison output.
  assert.equal(first.stamps[0].payload.metrics.total_return_twr_e8, -1000000);
  assert.equal(corrected.stamps[2].payload.metrics.total_return_twr_e8, 2000000);
  assert.equal(extended.stamps[3].payload.metrics.total_return_twr_e8, 4500000);
  assert.equal(corrected.stamps[2].payload.metrics.max_drawdown_e8, -15000000);
  assert.equal(first.stamps[0].payload.metrics.max_drawdown_e8, -10000000);
  assert.equal(extended.stamps[3].payload.metrics.max_drawdown_e8, -5000000);
  assert.deepEqual(extended.stamps[3].payload.relative_returns.map(row => row.return_e8), [10000000, -5000000]);
  for (const stamp of [first.stamps[0], corrected.stamps[2], extended.stamps[3]]) assert.equal(stamp.payload.metrics.annualized_volatility_e8, null);
  const firstHtml = await buildReviewPackage(first), currentHtml = await buildReviewPackage(extended);
  await writeFile(path.join(out, 'comparison-synthetic-previous.html'), firstHtml);
  await writeFile(path.join(out, 'comparison-synthetic-current.html'), currentHtml);

  tests.push({ name: 'Synthetic fixture generation and independent financial controls', status: 'passed' });
  console.log('PASS Synthetic fixture generation and independent financial controls');
  if (!fixtureOnly) {
    const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
    browser = await chromium.launch(channel ? { channel } : {});
  context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  await context.route('**/*', route => {
    const url = route.request().url();
    if (new URL(url).origin === origin) return route.continue();
    externalRequests.push(url);
    return route.abort('blockedbyclient');
  });
  await context.addInitScript(() => { window.n170Injected = 0; });
    page = await context.newPage();
    page.on('pageerror', error => errors.push(error.message));
    page.on('console', message => { consoleMessages.push({ type: message.type(), text: message.text() }); if (message.type() === 'error') errors.push(message.text()); });
    await page.goto(BASE);
    await page.getByText('Private draft up to date', { exact: true }).waitFor();
    await test('Production identity, meaningful owner entry and no development overlay', async () => {
      assert.equal(new URL(page.url()).origin, origin);
      assert.match(await page.title(), /N170 Verify/);
      assert.equal(await page.getByLabel('Prompt for your AI', { exact: true }).isVisible(), true);
      assert.equal(await page.locator('vite-error-overlay').count(), 0);
      assert.equal(await page.locator('script[src*="/@vite/client"]').count(), 0);
    });
    await page.getByRole('button', { name: 'Review a record', exact: true }).click();
    await test('No retained copy gives no fabricated change summary', async () => {
      await checkRecord(first, undefined, 'No previous copy checked');
      assert.equal(await page.locator('#changes-heading').count(), 0);
    });
    await test('Identical signed copies explicitly report no changed events', async () => {
      await checkRecord(first, first, 'Same history as your retained copy');
      await page.locator('#changes-heading').waitFor();
      assert.equal(await page.locator('.change-card').count(), 0);
      assert.match(await page.locator('.comparison-changes').innerText(), /No signed events changed or were added/);
    });
    await test('HTML current and previous copies show one added period and two corrections', async () => {
      await choose(currentHtml, false, 'synthetic-current.html');
      await choose(firstHtml, true, 'synthetic-previous.html');
      await page.getByRole('button', { name: 'Check record', exact: true }).click();
      await page.locator('#changes-heading').waitFor();
      const text = await page.locator('.comparison-changes').innerText();
      assert.match(text, /1 added period · 2 corrections/);
      assert.equal(await page.locator('.change-card').count(), 3);
      assert.match(text, /corrects record 1/);
      assert.match(text, /corrects record 3/);
      assert.match(text, /from the preceding period, record 1/);
      assert.match(text, /Before: Synthetic selected USD account/);
      assert.match(text, /Now: Synthetic selected EUR account/);
      assert.match(text, /Before: USD/); assert.match(text, /Now: EUR/);
      assert.match(text, /Scope or currency changes can affect comparability/);
      assert.match(text, /This adds a period; it is not a correction/);
      assert.match(text, /changes to signed claims/);
    });
    await test('Rendered correction tables match exact signed and independent financial controls', async () => {
      assert.deepEqual(await correctionRow(3, 0), ['Time-weighted return', '-1.000000%', '2.000000%']);
      assert.deepEqual(await correctionRow(3, 1), ['Sampled maximum drawdown', '-10.000000%', '-15.000000%']);
      assert.deepEqual(await correctionRow(3, 2), ['Annualized volatility', 'Withheld', 'Withheld']);
      assert.deepEqual(await correctionRow(3, 3), ['Disclosed return intervals', '2', '2']);
      assert.deepEqual(await correctionRow(4, 0), ['Time-weighted return', '2.000000%', '4.500000%']);
      assert.deepEqual(await correctionRow(4, 1), ['Sampled maximum drawdown', '-15.000000%', '-5.000000%']);
      const details = page.locator('#record-4 details').filter({ has: page.getByText('Independent checking details', { exact: true }) });
      await details.locator('summary').click();
      assert.deepEqual(await details.locator('tbody tr').nth(0).locator('td').allTextContents(), ['2025-01-01', '2025-01-02', '10.000000%']);
      assert.deepEqual(await details.locator('tbody tr').nth(1).locator('td').allTextContents(), ['2025-01-02', '2025-01-03', '-5.000000%']);
    });
    await test('Correction of correction retains both superseded originals and current period', async () => {
      assert.equal(await page.locator('article.record').count(), 4);
      assert.match(await page.locator('#record-1').innerText(), /Retained original · superseded/);
      assert.match(await page.locator('#record-3').innerText(), /Retained original · superseded/);
      assert.match(await page.locator('#record-4').innerText(), /Current for this period/);
      assert.match(await page.locator('.change-card').filter({ has: page.locator('a[href="#record-3"]') }).innerText(), /superseded by a later correction/);
      assert.match(await page.locator('.coverage').innerText(), /3 return intervals · 4 signed events · 2 corrections/);
    });
    await test('Hostile signed reason and scope stay inert, with six honest evidence dimensions', async () => {
      const changes = await page.locator('.comparison-changes').innerText();
      assert(changes.includes(reason)); assert(changes.includes(scope));
      await inert();
      const rail = await page.locator('.evidence-rail').innerText();
      for (const text of ['Reproduced from disclosed returns', 'Valid for this key', 'Self-reported · not authenticated', 'Not established', 'No independent evidence', 'Supplied observations only']) assert(rail.includes(text));
      assert.match(await page.locator('.review-boundary').innerText(), /Broker authenticity, identity, independent time and complete account coverage are not established/);
    });
    await capture('comparison-desktop.png');
    await test('Keyboard activates a change link and focuses the exact retained record', async () => {
      const link = page.locator('.comparison-changes a[href="#record-4"]');
      await link.focus();
      assert.equal(await link.evaluate(el => document.activeElement === el), true);
      await page.keyboard.press('Enter');
      await page.waitForFunction(() => document.activeElement?.id === 'record-4');
      assert.equal(new URL(page.url()).hash, '#record-4');
      assert.equal(await page.locator('#record-4').getAttribute('tabindex'), '-1');
    });
    await page.setViewportSize({ width: 390, height: 844 });
    await test('390px mobile view keeps comparison tables and hostile text within page width', async () => {
      await page.locator('#changes-heading').scrollIntoViewIfNeeded();
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      assert.equal(await page.locator('#changes-heading').isVisible(), true);
      assert.equal(await page.locator('.change-card table').count(), 2);
      const tableFits = await page.locator('.change-card .table-scroll').evaluateAll(elements => elements.every(el => el.getBoundingClientRect().width <= innerWidth));
      assert.equal(tableFits, true);
      await inert();
    });
    await capture('comparison-mobile.png');
    await page.setViewportSize({ width: 1440, height: 1000 });
    await test('Prototype-shaped and enum-looking account aliases remain exact inert scope text', async () => {
      for (const alias of ['__proto__', 'constructor', 'toString', 'self_reported', 'synthetic_demo']) {
        const declared = await appendPerformanceStamp(first, secondCsv, 252, signer, { synthetic: true, provenance: metadata(alias, 'USD') });
        await checkRecord(declared, first);
        const card = page.locator('.change-card').first();
        assert((await card.innerText()).includes(`Declared scope: ${alias} · USD`), `Scope alias was relabelled or lost: ${alias}`);
        assert.equal(await page.locator('.review-result').count(), 1);
        await inert();
      }
    });
    for (const [label, current, previous, expected] of [
      ['truncated', first, extended, 'History is shorter than your retained copy'],
      ['replacement key', replacement, first, 'Different key or alias: continuity is not established'],
      ['conflicting history', fork, added, 'Conflicting history: an earlier record differs'],
    ]) await test(`${label} stays adverse and shows no normal additions/corrections summary`, async () => {
      await checkRecord(current, previous, expected);
      assert.equal(await page.locator('#changes-heading').count(), 0);
      assert.equal(await page.locator('.change-card').count(), 0);
      assert((await page.getByRole('alert').allTextContents()).some(text => text.includes(expected)));
    });
    await capture('comparison-conflicting-history.png');
    await test('Invalid retained signature blocks the entire comparison', async () => {
      const invalid = structuredClone(first); invalid.stamps[0].signature = 'A'.repeat(86);
      await choose(extended); await choose(invalid, true); await rejected(/signature|invalid/i);
    });
    await test('Tampered current values cannot leave a successful comparison visible', async () => {
      await checkRecord(extended, first);
      const tampered = structuredClone(extended); tampered.stamps[3].payload.metrics.total_return_twr_e8++;
      await choose(tampered);
      assert.equal(await page.locator('.review-result').count(), 0);
      await rejected(/integrity|metric|return/i);
    });
    await test('Wrong expected key clears earlier success and blocks verification', async () => {
      await checkRecord(extended, first);
      await page.getByLabel('Expected key code (optional)', { exact: true }).fill(profileKeyCode(replacement));
      assert.equal(await page.locator('.review-result').count(), 0);
      await rejected(/different key/i);
      await page.getByLabel('Expected key code (optional)', { exact: true }).fill('');
    });
    await test('Pending current-file read clears success and disables every mutable verification control', async () => {
      await checkRecord(extended, first);
      await page.evaluate(() => {
        window.n170OriginalFileText = File.prototype.text;
        File.prototype.text = function () {
          if (this.name === 'synthetic-delayed-current.json') {
            const file = this;
            return new Promise((resolve, reject) => { window.n170FinishFileRead = () => window.n170OriginalFileText.call(file).then(resolve, reject); });
          }
          return window.n170OriginalFileText.call(this);
        };
      });
      await page.locator('input[type=file]').first().setInputFiles({ name: 'synthetic-delayed-current.json', mimeType: 'application/json', buffer: Buffer.from(json(first)) });
      await page.waitForFunction(() => typeof window.n170FinishFileRead === 'function');
      assert.equal(await page.locator('.review-result').count(), 0);
      assert.equal(await page.locator('#evidence-json').inputValue(), '');
      assert.equal(await page.locator('fieldset.review-inputs').getAttribute('aria-busy'), 'true');
      assert.equal(await page.locator('fieldset.review-inputs input,fieldset.review-inputs textarea,fieldset.review-inputs button').evaluateAll(elements => elements.every(el => el.matches(':disabled'))), true);
      await capture('comparison-pending-read.png');
      await page.evaluate(() => window.n170FinishFileRead());
      await page.waitForFunction(() => !document.querySelector('fieldset.review-inputs').disabled);
      assert.equal(await page.locator('#evidence-json').inputValue(), json(first));
      assert.equal(await page.locator('.review-result').count(), 0);
      await page.evaluate(() => { File.prototype.text = window.n170OriginalFileText; delete window.n170OriginalFileText; delete window.n170FinishFileRead; });
      await page.getByRole('button', { name: 'Check record', exact: true }).click();
      await page.locator('#changes-heading').waitFor();
      assert.match(await page.locator('.comparison-changes').innerText(), /No signed events changed or were added/);
    });
    await test('Current-file read failure clears selected evidence and cannot recheck stale contents', async () => {
      await page.evaluate(() => {
        window.n170OriginalFileText = File.prototype.text;
        File.prototype.text = function () { return this.name === 'synthetic-failed-read.json' ? Promise.reject(new Error('Synthetic file read failed.')) : window.n170OriginalFileText.call(this); };
      });
      await page.locator('input[type=file]').first().setInputFiles({ name: 'synthetic-failed-read.json', mimeType: 'application/json', buffer: Buffer.from(json(extended)) });
      await page.getByRole('alert').filter({ hasText: 'Synthetic file read failed.' }).waitFor();
      assert.equal(await page.locator('.review-result').count(), 0);
      assert.equal(await page.locator('#evidence-json').inputValue(), '');
      assert.equal(await page.getByRole('button', { name: 'Check record', exact: true }).isDisabled(), true);
      assert.equal(await page.locator('.upload-zone').innerText(), 'Choose received record');
      await page.evaluate(() => { File.prototype.text = window.n170OriginalFileText; delete window.n170OriginalFileText; });
    });
    await test('Oversized current-file replacement also clears evidence without stale acceptance', async () => {
      await checkRecord(extended, first);
      await page.locator('input[type=file]').first().setInputFiles({ name: 'synthetic-oversized.json', mimeType: 'application/json', buffer: Buffer.alloc(2000001, 32) });
      await page.getByRole('alert').filter({ hasText: 'smaller than 2 MB' }).waitFor();
      assert.equal(await page.locator('.review-result').count(), 0);
      assert.equal(await page.locator('#evidence-json').inputValue(), '');
      assert.equal(await page.getByRole('button', { name: 'Check record', exact: true }).isDisabled(), true);
    });
    await test('No external requests, injected execution or browser errors in the full comparison journey', async () => { await inert(); assert.deepEqual(errors, []); });
    await rm(path.join(out, 'comparison-failure.png'), { force: true });
  }
} catch (error) {
  failure = error;
  if (page) await capture('comparison-failure.png').catch(() => {});
} finally {
  await writeFile(path.join(out, fixtureOnly ? 'comparison-fixture-results.json' : 'comparison-results.json'), JSON.stringify({
    date: new Date().toISOString(), implementation_root: ROOT, implementation_sha256: implementation,
    node: process.version, browser: browser ? await browser.version() : null, channel: browser ? channel || null : null, mode: fixtureOnly ? 'fixtures-only' : 'browser',
    engine: !browser ? 'Browser not executed' : channel === 'chrome' ? 'Installed Google Chrome via Playwright' : channel ? `Chromium channel ${channel} via Playwright` : 'Playwright-managed Chromium',
    url: BASE, user_agent: page ? await page.evaluate(() => navigator.userAgent).catch(() => null) : null,
    viewports: ['1440x1000', '390x844'], tests, errors, console_messages: consoleMessages,
    external_requests: externalRequests, screenshots,
    synthetic_evidence: ['comparison-synthetic-previous.html', 'comparison-synthetic-current.html'].map(file => path.join(out, file)),
    scope: fixtureOnly ? 'Synthetic signed fixture generation, independent hand-calculated no-flow controls and review-package generation only. No browser or UI execution.' : 'Rendered production comparison journey using entirely synthetic observations and keys. Arithmetic controls are hand-calculated no-flow cases. Not a live brokerage test, user pilot, Firefox test, Safari test or full accessibility certification.',
    status: failure ? 'failed' : 'passed', failure: failure?.message || null,
  }, null, 2));
  if (browser) await browser.close();
}
if (failure) throw failure;
console.log(`Comparison evidence: ${path.join(out, fixtureOnly ? 'comparison-fixture-results.json' : 'comparison-results.json')}`);
