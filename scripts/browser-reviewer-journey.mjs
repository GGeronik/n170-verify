import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { createEmptyDraft } from '../src/draftModel.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BASE = process.env.N170_PREVIEW_URL || 'http://127.0.0.1:4174/';
assert(['127.0.0.1','localhost','[::1]'].includes(new URL(BASE).hostname));
const out = path.resolve(process.env.N170_EVIDENCE_DIR || path.join(ROOT, 'docs/verification/reviewer-journey'));
await mkdir(out, { recursive: true });
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const browser = await chromium.launch(process.env.N170_BROWSER_CHANNEL ? { channel: process.env.N170_BROWSER_CHANNEL } : {});
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
const page = await context.newPage();
const errors = [], externalRequests = [], tests = [], screenshots = [];
page.on('pageerror', error=>errors.push(error.message));
page.on('console', message=>{ if (message.type() === 'error') errors.push(message.text()); });
await context.route('**/*', route=> {
  if (new URL(route.request().url()).origin === new URL(BASE).origin) return route.continue();
  externalRequests.push(route.request().url()); return route.abort();
});
async function test(name, action) { await action(); tests.push({ name, status: 'passed' }); console.log('PASS', name); }
async function capture(name, locator = null) { const target = path.join(out, name); if (locator) await locator.screenshot({ path: target }); else await page.screenshot({ path: target, fullPage: true }); screenshots.push(target); }
async function openDetails(label) { const summary = page.getByText(label, { exact: true }); if (!await summary.locator('..').evaluate(el=>el.open)) await summary.click(); }
async function downloadSigned(filename) {
  await openDetails('Machine-readable record & retained checkpoint');
  const received = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download signed JSON', exact: true }).click();
  const file = await received; const target = path.join(out, filename); await file.saveAs(target); return target;
}
// Original, synthetic three-interval fixture: -10%, +10%, -1%.
// It includes one end-of-interval deposit, withdrawal and zero flow.
const input = 'date,nav,external_flow\n2025-01-01,100,0\n2025-01-02,110,20\n2025-01-03,111,-10\n2025-01-04,109.89,0';
const fixture = { kind: 'n170.private-draft.v1', data: { ...createEmptyDraft(), input, original: input, format: 'n170', currency: 'EUR', scope: 'Synthetic selected EUR account', fileName: 'synthetic-loss-flows.csv', synthetic: true } };
try {
  await page.goto(BASE); await page.getByText('Private draft up to date', { exact: true }).waitFor();
  await test('Production page identity and meaningful owner screen', async()=> {
    assert.equal(new URL(page.url()).origin, new URL(BASE).origin);
    assert.match(await page.title(), /N170 Verify/);
    assert.equal(await page.locator('vite-error-overlay,script[src*="/@vite/client"]').count(), 0);
    await page.getByRole('heading', { name: 'Your performance, clearly explained.' }).waitFor();
  });
  await page.getByRole('button', { name: 'Import a file', exact: true }).click();
  await page.getByLabel('Choose export file').setInputFiles({ name: 'synthetic-draft.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(fixture)) });
  await page.getByText('Private draft opened. Source review must be confirmed again for imported files before signing.', { exact: true }).waitFor();
  await test('Reconciliation reports actual source counts and retained synthetic scope', async()=> {
    assert.match(await page.locator('.reconciliation').innerText(), /4 source rows · 4 parsed observations/);
    assert.match(await page.locator('.reconciliation').innerText(), /Synthetic example · no real account/);
    assert.equal(await page.getByLabel('Reporting currency').inputValue(), 'EUR');
  });
  await test('Account guidance opens and closes with the keyboard', async()=> {
    const summary = page.getByText('What to reconcile: losses, flows and coverage', { exact: true });
    await summary.focus(); await page.keyboard.press('Enter');
    assert(await summary.locator('..').evaluate(el=>el.open));
    assert.match(await summary.locator('..').innerText(), /A zero net flow does not prove/);
    await page.keyboard.press('Space'); assert.equal(await summary.locator('..').evaluate(el=>el.open), false);
  });
  await page.getByRole('checkbox', { name: /I checked cash activity/ }).check();
  await page.getByRole('button', { name: 'Reconcile file', exact: true }).click();
  await page.getByText(/Reconciliation complete/).waitFor();
  await capture('01-reconciliation-desktop.png');
  await page.getByRole('button', { name: 'Review calculation', exact: true }).click();
  await test('Loss and flow review uses the existing signed-series calculation', async()=> {
    await page.getByRole('heading', { name: 'Review before you sign', exact: true }).waitFor();
    assert.match(await page.locator('.metrics').innerText(), /-1.99%/);
    assert.match(await page.locator('main').innerText(), /This disclosed period has a loss/);
    assert.match(await page.locator('main').innerText(), /4 NAV observations · 3 return intervals/);
    assert.match(await page.locator('main').innerText(), /2 observations with a nonzero net external flow/);
    assert.match(await page.locator('main').innerText(), /Synthetic example · no real account/);
  });
  await page.getByLabel('Public profile alias', { exact: true }).fill('Synthetic account journey');
  await page.getByRole('button', { name: 'Create profile', exact: true }).click();
  await page.getByText(/Profile created and saved/).waitFor();
  await page.getByRole('checkbox', { name: /I reviewed the calculation/ }).check();
  await page.getByRole('button', { name: 'Sign record & save', exact: true }).click();
  await page.getByRole('heading', { name: 'Ready for a thoughtful review.', exact: true }).waitFor();
  const firstFile = await downloadSigned('synthetic-first.json');
  await openDetails('Rerun the independent verifier');
  await test('Downloaded synthetic record reproduces with the displayed separate verifier', async()=> {
    const checked = spawnSync(process.execPath, ['scripts/verify-record.mjs', firstFile], { cwd: ROOT, encoding: 'utf8' });
    assert.equal(checked.status, 0, checked.stderr);
    const record = JSON.parse(await readFile(firstFile, 'utf8'));
    assert.equal(record.stamps[0].payload.source_kind, 'synthetic_demo');
    assert.equal(record.stamps[0].payload.metrics.total_return_twr_e8, -1990000);
    assert.match(await page.locator('.independent-verifier-help').innerText(), /Exit 2:/);
  });
  await page.getByRole('button', { name: 'Review / correct this period', exact: true }).click();
  await page.getByRole('button', { name: 'Back to observations', exact: true }).click();
  await page.getByRole('button', { name: 'Correct row 4', exact: true }).click();
  await page.getByLabel('Corrected value', { exact: true }).fill('110');
  await page.getByLabel('Reason (included in shared evidence)', { exact: true }).fill('Synthetic closing valuation correction');
  await page.getByRole('button', { name: 'Apply correction', exact: true }).click();
  await page.getByRole('dialog').waitFor({ state: 'hidden' });
  await page.getByRole('button', { name: 'Review calculation', exact: true }).click();
  await page.getByLabel('Record purpose', { exact: true }).selectOption('1');
  await page.getByLabel('Public reason for correction', { exact: true }).fill('Synthetic source review; preserve the losing period.');
  await page.getByRole('checkbox', { name: /I reviewed the calculation/ }).check();
  await page.getByRole('button', { name: 'Sign correction & save', exact: true }).click();
  await page.getByRole('heading', { name: 'Ready for a thoughtful review.', exact: true }).waitFor();
  const currentFile = await downloadSigned('synthetic-corrected.json');
  await page.getByRole('button', { name: 'Save draft', exact: true }).click();
  await page.getByText(/Private draft saved in this browser/).waitFor();
  await page.getByRole('button', { name: 'Open employer review', exact: true }).click();
  await page.getByRole('button', { name: 'Check record', exact: true }).click();
  await page.locator('.review-result').waitFor();
  await openDetails('Add earlier evidence for comparison');
  await page.getByLabel('Choose my previous copy').setInputFiles(firstFile);
  await page.getByRole('button', { name: 'Check record', exact: true }).click();
  await page.locator('.comparison-changes').waitFor();
  await test('Reviewer sees losses, currency, scoped counts and preserved correction history', async()=> {
    assert.match(await page.locator('#record-1').innerText(), /Retained original · superseded/);
    assert.match(await page.locator('#record-2').innerText(), /2 disclosed losing interval\(s\)/);
    assert.match(await page.locator('#record-2').innerText(), /Synthetic selected EUR account/);
    assert.match(await page.locator('#record-2').innerText(), /EUR · no conversion/);
    assert.match(await page.locator('#record-2').innerText(), /2 observations with a nonzero net external flow/);
    const checked = spawnSync(process.execPath, ['scripts/verify-record.mjs', currentFile, firstFile], { cwd: ROOT, encoding: 'utf8' });
    assert.equal(checked.status, 0, checked.stderr);
    assert.equal(JSON.parse(checked.stdout).previous_copy.status, 'extended');
  });
  await openDetails('Rerun the independent verifier'); await capture('02-reviewer-desktop.png');
  await capture('04-verifier-desktop-detail.png', page.locator('.independent-verifier-help'));
  await page.setViewportSize({ width: 390, height: 844 });
  await test('Narrow mobile viewport retains readable verifier commands without page overflow', async()=> {
    await page.locator('.independent-verifier-help').scrollIntoViewIfNeeded();
    assert(await page.evaluate(()=>document.documentElement.scrollWidth <= innerWidth));
    assert(await page.locator('.independent-verifier-help pre').first().isVisible());
  });
  await capture('03-reviewer-mobile.png');
  await capture('05-verifier-mobile-detail.png', page.locator('.independent-verifier-help'));
  await test('Loaded application checks the retained correction while offline', async()=> {
    await context.setOffline(true);
    await page.getByRole('button', { name: 'Check record', exact: true }).click();
    await page.locator('.review-result').waitFor();
    assert.match(await page.locator('.review-result').innerText(), /Retained history preserved/);
    await context.setOffline(false);
  });
  await test('No browser errors or external requests during the local journey', async()=> {
    assert.deepEqual(errors, []); assert.deepEqual(externalRequests, []);
  });
  await writeFile(path.join(out, 'reviewer-journey-results.json'), JSON.stringify({ browser: await browser.version(), url: BASE, viewports: ['1440x1000','390x844'], fixtures: 'Original synthetic accounts only; no real account or outside reviewer', browser_path: 'Browser plugin not available; existing Playwright runtime', offline_scope: 'Already loaded app, not fresh offline installation', tests, errors, externalRequests, screenshots }, null, 2));
} catch (error) {
  await capture('failure.png'); await writeFile(path.join(out, 'reviewer-journey-failure.txt'), `${error.stack}\n${await page.locator('body').innerText()}`); throw error;
} finally { await browser.close(); }
