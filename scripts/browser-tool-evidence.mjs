import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseToolEvidence, TOOL_EVIDENCE_MAX_BYTES } from '../src/toolEvidence.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BASE = process.env.N170_PREVIEW_URL || 'http://127.0.0.1:4182/';
assert(['127.0.0.1', 'localhost', '[::1]'].includes(new URL(BASE).hostname));
const out = process.env.N170_EVIDENCE_DIR || '/private/tmp/n170-tool-evidence-browser';
await mkdir(out, { recursive: true });
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const browser = await chromium.launch(process.env.N170_BROWSER_CHANNEL ? { channel: process.env.N170_BROWSER_CHANNEL } : {});
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
const checks = [], errors = [], externalRequests = [], screenshots = [];
await context.route('**/*', route => {
  if (new URL(route.request().url()).origin === new URL(BASE).origin) return route.continue();
  externalRequests.push(route.request().url()); return route.abort();
});
await context.addInitScript(() => {
  const read = File.prototype.arrayBuffer;
  File.prototype.arrayBuffer = async function () {
    if (this.name.startsWith('slow-')) await new Promise(resolve => setTimeout(resolve, 800));
    if (this.name.includes('read-failure')) throw new Error('PRIVATE SOURCE ERROR');
    return read.call(this);
  };
  window.observationWrites = [];
  for (const method of ['add', 'put', 'delete', 'clear']) {
    const original = IDBObjectStore.prototype[method];
    IDBObjectStore.prototype[method] = function (...args) { window.observationWrites.push(`idb:${method}`); return original.apply(this, args); };
  }
  const set = Storage.prototype.setItem;
  Storage.prototype.setItem = function (...args) { window.observationWrites.push('storage:setItem'); return set.apply(this, args); };
  window.n170Injected = 0;
});
const page = await context.newPage();
page.on('pageerror', error => errors.push(error.message));
page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
const fixture = async name => JSON.parse(await readFile(path.join(ROOT, 'examples', `tool-evidence-${name}.json`), 'utf8'));
const findings = await fixture('findings'), clean = await fixture('clean'), failed = await fixture('failed'), insufficient = await fixture('insufficient');
async function test(name, fn) { await fn(); checks.push({ name, status: 'passed' }); console.log('PASS', name); }
async function choose(value, name = 'observations.json') {
  await page.getByLabel('Choose observation JSON').setInputFiles({ name, mimeType: 'application/json', buffer: Buffer.isBuffer(value) ? value : Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)) });
}
async function loaded() { await page.locator('.tool-result').waitFor(); }
async function rejected() { await page.getByRole('alert').waitFor(); assert.equal(await page.locator('.tool-result').count(), 0); }
async function screenshot(name) { const file = path.join(out, name); await page.screenshot({ path: file, fullPage: true }); screenshots.push(file); }
let failure;
try {
  await page.goto(BASE);
  await page.getByText('Private draft up to date', { exact: true }).waitFor();
  await page.getByRole('button', { name: 'Tool observations', exact: true }).click();
  await page.evaluate(() => { window.observationWrites = []; });
  await test('Production identity and substantive separate workflow', async () => {
    assert.match(await page.title(), /N170 Verify/);
    assert.equal(new URL(page.url()).origin, new URL(BASE).origin);
    assert.equal(await page.getByRole('heading', { name: 'Inspect tool observations.' }).isVisible(), true);
    assert.equal(await page.locator('vite-error-overlay,script[src*="/@vite/client"]').count(), 0);
    assert.equal(await page.getByRole('button', { name: 'Download observation JSON' }).count(), 0);
  });
  await test('Keyboard example activation focuses result and states synthetic/unknown boundaries', async () => {
    await page.getByRole('button', { name: 'Try synthetic observations' }).focus(); await page.keyboard.press('Enter'); await loaded();
    assert.equal(await page.locator('#tool-result-heading').evaluate(el => el === document.activeElement), true);
    const body = await page.locator('.tool-result').innerText();
    for (const term of ['Synthetic demonstration.', 'Unknown · unverified', 'Unknown · not established', 'not a completed eight-dimension', 'never change signed account']) assert(body.includes(term), term);
    await screenshot('tool-observations-desktop.png');
  });
  await test('Visible observation text meets measured contrast and keyboard file input has a name', async () => {
    const lowContrast = await page.locator('.tool-evidence').evaluate(root => {
      const luminance = color => color.match(/[\d.]+/g).slice(0, 3).map(Number).map(v => { v /= 255; return v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4; }).reduce((n, v, i) => n + v * [.2126, .7152, .0722][i], 0);
      return [...root.querySelectorAll('h1,h2,h3,p,li,label,button,a,summary,td,th,small')].filter(el => el.getClientRects().length && !el.disabled).flatMap(el => {
        const style = getComputedStyle(el); let parent = el, background;
        while (parent) { const value = getComputedStyle(parent).backgroundColor; if (value !== 'rgba(0, 0, 0, 0)' && value !== 'transparent') { background = value; break; } parent = parent.parentElement; }
        const a = luminance(style.color), b = luminance(background || 'rgb(248,249,246)');
        const ratio = (Math.max(a, b) + .05) / (Math.min(a, b) + .05);
        const required = parseFloat(style.fontSize) >= 24 || (parseFloat(style.fontSize) >= 18.66 && Number(style.fontWeight) >= 700) ? 3 : 4.5;
        return ratio >= required ? [] : [{ text: el.textContent.slice(0, 80), ratio, required }];
      });
    });
    assert.deepEqual(lowContrast, []);
    await page.getByLabel('Choose observation JSON').focus();
    assert.equal(await page.evaluate(() => document.activeElement.type), 'file');
  });
  await test('Default export omits labels, preserves findings and synthetic scope, and round trips', async () => {
    const event = page.waitForEvent('download'); await page.getByRole('button', { name: 'Download observation JSON' }).click();
    const saved = await event, data = await readFile(await saved.path(), 'utf8');
    const value = parseToolEvidence(data);
    assert.equal(value.status, 'FINDINGS_REPORTED'); assert.equal(value.example_declaration, 'synthetic');
    assert.equal(value.disclosure.strategy_labels_included, false);
    for (const row of value.rows) for (const field of ['strategy', 'filename', 'biased_indicators']) assert(!Object.hasOwn(row, field));
    await choose(data); await loaded();
  });
  await test('Available labels require explicit opt-in on each replacement', async () => {
    await choose(findings); await loaded();
    const checkbox = page.getByRole('checkbox', { name: /Include any available/ }); assert.equal(await checkbox.isChecked(), false);
    await checkbox.check(); const event = page.waitForEvent('download'); await page.getByRole('button', { name: 'Download observation JSON' }).click();
    const data = JSON.parse(await readFile(await (await event).path(), 'utf8'));
    assert.equal(data.rows[0].strategy, findings.rows[0].strategy);
    await choose(clean); await loaded(); assert.equal(await checkbox.isChecked(), false);
  });
  await test('Clean rows remain scoped observations, never strategy clearance', async () => {
    assert.match(await page.locator('#tool-result-heading').innerText(), /no findings/i);
    assert.match(await page.locator('.tool-result').innerText(), /does not establish absence of lookahead bias/);
  });
  await test('Failed runs and insufficient rows remain visible with unknown counts', async () => {
    await choose(failed); await loaded(); assert.match(await page.locator('.tool-result').innerText(), /FAILED/);
    assert.equal(parseToolEvidence(JSON.stringify(failed)).status, 'NOT_ASSESSABLE');
    await choose(insufficient); await loaded(); assert.match(await page.locator('.tool-result table').innerText(), /Unknown/);
    await screenshot('tool-observations-insufficient.png');
  });
  await test('Malformed, duplicate-key, forged-trust, unknown-version, nested and invalid UTF-8 imports clear results', async () => {
    const forged = structuredClone(findings); forged.scope.source_authenticity = 'verified';
    const version = structuredClone(findings); version.schema += '.future';
    const hostile = structuredClone(findings); hostile.scope['__proto__'] = { authenticated: true };
    for (const value of ['{', '{"schema":"a","schema":"b"}', forged, version, '['.repeat(24) + '0' + ']'.repeat(24), Buffer.from([0xc3, 0x28]), '{"__proto__":{"authenticated":true},' + JSON.stringify(findings).slice(1)]) {
      await choose(findings); await loaded(); await choose(value); await rejected();
      assert(!(await page.getByRole('alert').innerText()).includes('PRIVATE SOURCE ERROR'));
    }
    await screenshot('tool-observations-rejected.png');
  });
  await test('Oversized replacement clears previous result before reading', async () => {
    await choose(clean); await loaded(); await choose(Buffer.alloc(TOOL_EVIDENCE_MAX_BYTES + 1, 32)); await rejected();
    assert.match(await page.getByRole('alert').innerText(), /4 MiB/);
  });
  await test('Slow old read cannot overwrite a newer import', async () => {
    await choose(findings, 'slow-old.json'); assert.equal(await page.locator('.tool-result').count(), 0);
    await choose(clean); await loaded(); await page.waitForTimeout(950);
    assert.match(await page.locator('#tool-result-heading').innerText(), /no findings/i);
  });
  await test('Failed replacement and clear invalidate delayed work', async () => {
    await choose(findings, 'slow-old.json'); await choose(clean, 'read-failure.json'); await rejected(); await page.waitForTimeout(950); assert.equal(await page.locator('.tool-result').count(), 0);
    await choose(findings, 'slow-clear.json'); await page.getByRole('button', { name: 'Clear observations', exact: true }).click(); await page.waitForTimeout(950);
    assert.equal(await page.locator('.tool-result').count(), 0); assert.equal(await page.getByRole('alert').count(), 0);
  });
  await test('Markup-bearing labels are rejected or rendered inert without outbound requests', async () => {
    const hostile = structuredClone(findings); hostile.rows[0].display_label = '<img src="https://invalid.test/x" onerror="window.n170Injected=1">';
    await choose(hostile);
    await page.waitForFunction(() => document.querySelector('.tool-result') || document.querySelector('[role=alert]'));
    assert.equal(await page.evaluate(() => window.n170Injected), 0);
    assert.equal(await page.locator('img[src*="invalid.test"],script[src*="invalid.test"]').count(), 0);
    assert.deepEqual(externalRequests, []);
  });
  await test('Mobile layout, keyboard table access and local offline export', async () => {
    await page.setViewportSize({ width: 390, height: 844 }); await page.getByRole('button', { name: 'Try synthetic observations' }).click(); await loaded();
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await page.getByRole('region', { name: 'Reported strategy observations' }).focus();
    assert.equal(await page.evaluate(() => document.activeElement.getAttribute('role')), 'region');
    await screenshot('tool-observations-mobile.png');
    await context.setOffline(true); await choose(clean); await loaded();
    const event = page.waitForEvent('download'); await page.getByRole('button', { name: 'Download observation JSON' }).click();
    assert.equal(parseToolEvidence(await readFile(await (await event).path(), 'utf8')).status, 'NO_FINDINGS_REPORTED');
    await context.setOffline(false);
  });
  await test('Observation inspection and export make no storage writes or external requests', async () => {
    assert.deepEqual(await page.evaluate(() => window.observationWrites), []); assert.deepEqual(externalRequests, []);
  });
  await test('Leaving the view clears observations and invalidates pending reads', async () => {
    await choose(findings, 'slow-leave.json'); await page.getByRole('button', { name: 'Methods', exact: true }).first().click();
    await page.waitForTimeout(950); await page.getByRole('button', { name: 'Tool observations', exact: true }).click();
    assert.equal(await page.locator('.tool-result').count(), 0);
  });
  await test('Console remains free of application errors', async () => { assert.deepEqual(errors, []); });
} catch (error) { failure = error; await screenshot('tool-observations-failure.png'); }
await writeFile(path.join(out, 'tool-evidence-browser-results.json'), JSON.stringify({ browser: await browser.version(), base: BASE, viewports: ['1440x1000', '390x844'], browserPlugin: 'not available; existing Playwright used', checks, errors, externalRequests, screenshots, failure: failure?.stack || null, offlineScope: 'Already loaded production app; no service worker or offline first load claim' }, null, 2) + '\n');
await browser.close();
if (failure) throw failure;
