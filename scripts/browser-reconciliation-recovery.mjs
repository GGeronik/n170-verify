// Independent synthetic browser challenges for replacement and recovery paths.
// This exercises the rendered workspace; no producer implementation is mocked.
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { createEmptyDraft } from '../src/reconciliationDraft.js';

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const out = process.env.N170_EVIDENCE_DIR || path.join(root, '../track2-evidence/recovery');
const base = process.env.N170_PREVIEW_URL || 'http://127.0.0.1:4187/';
const ownedSources = ['src/OwnerWorkspace.jsx', 'src/AccountReconciliationPanel.jsx', 'src/reconciliationDraft.js', 'src/reconciliation.js'];
const hashes = async () => Object.fromEntries(await Promise.all(ownedSources.map(async file => [file, createHash('sha256').update(await readFile(path.join(root, file))).digest('hex')])));
const csv = 'date,nav,external_flow\n2025-03-03,100,0\n2025-03-04,110,0';
const rejected = 'date,nav,external_flow\n2025-03-03,100,0\n"unclosed';
const attempt = (fileName, disposition = 'unresolved') => ({ text: rejected, fileName, disposition, reason: disposition === 'unresolved' ? '' : 'Synthetic unrelated account retained outside the selected scope.' });
const fixture = sources => ({
  ...createEmptyDraft(), input: csv, scope: 'Synthetic recovery account', synthetic: true, flowTimingConfirmed: true,
  reconciliation: { ...createEmptyDraft().reconciliation, sources: sources || [], flowActivity: 'reviewed_no_hidden', flowTiming: 'interval_end' },
});
const report = {
  started_at: new Date().toISOString(), base, tests: [],
  scope: 'Six isolated Chromium UI recovery checks using original synthetic account inputs. File read failures/delays are injected; production source is unchanged.',
  limitations: ['This is agent validation, not an external audit.', 'Injected read failures and delays exercise recovery logic; physical disk faults are not reproduced.', 'Chromium only; other browser engines are not covered by this harness.'],
  source_sha256_before: await hashes(),
};
await mkdir(out, { recursive: true });
const browser = await chromium.launch({ headless: true });
report.browser = await browser.version();

async function start(draft) {
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
  const page = await context.newPage();
  page.setDefaultTimeout(6000);
  const runtimeErrors = [];
  page.on('pageerror', error => runtimeErrors.push(error.message));
  await page.goto(base);
  await page.getByText('Private draft up to date', { exact: true }).waitFor();
  // Fixture setup writes only this isolated browser context's private draft.
  await page.evaluate(async data => {
    const db = await new Promise((resolve, reject) => {
      const request = indexedDB.open('n170-verify-drafts', 1);
      request.onupgradeneeded = () => request.result.createObjectStore('drafts');
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    await new Promise((resolve, reject) => {
      const transaction = db.transaction('drafts', 'readwrite');
      transaction.objectStore('drafts').put({ revision: 1, data, savedAt: '2025-03-05T00:00:00.000Z' }, 'workspace');
      transaction.oncomplete = resolve;
      transaction.onerror = () => reject(transaction.error);
    });
    db.close();
  }, draft);
  await page.reload();
  await page.getByText('Saved private draft restored in this browser.', { exact: true }).waitFor();
  await page.getByRole('button', { name: 'Import a file', exact: true }).click();
  return { context, page, runtimeErrors };
}
const observations = page => page.getByLabel('Date, net asset value, external flow', { exact: true });
const choose = (page, file) => page.locator('.upload-zone input[type=file]').setInputFiles(file);
async function exportedDraft(page, name) {
  const event = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export private draft', exact: true }).click();
  const download = await event;
  const target = path.join(out, `${name}.json`);
  await download.saveAs(target);
  return JSON.parse(await readFile(target, 'utf8')).data;
}
async function waitForAttempt(page, name) {
  await page.locator('[aria-labelledby="account-reconciliation-heading"]').getByText(name, { exact: true }).last().waitFor();
  await page.getByText('Selected scope remains blocked. Unresolved evidence is retained below.', { exact: true }).waitFor();
}
async function check(name, draft, work) {
  const started = Date.now();
  let state;
  try {
    state = await start(draft);
    const evidence = await work(state.page);
    assert.deepEqual(state.runtimeErrors, [], 'No uncaught application errors');
    await state.page.screenshot({ path: path.join(out, `${name}.png`), fullPage: true });
    report.tests.push({ name, status: 'passed', elapsed_ms: Date.now() - started, evidence });
    console.log(`PASS ${name}`);
  } catch (error) {
    if (state) {
      await state.page.screenshot({ path: path.join(out, `${name}-failure.png`), fullPage: true }).catch(() => {});
      await writeFile(path.join(out, `${name}-failure.txt`), `${error.stack}\n\n${await state.page.locator('body').innerText().catch(() => '')}`);
    }
    report.tests.push({ name, status: 'failed', elapsed_ms: Date.now() - started, error: error.stack, runtimeErrors: state?.runtimeErrors || [] });
    console.log(`FAIL ${name}: ${error.message}`);
  } finally {
    await state?.context.close();
    await writeFile(path.join(out, 'results.json'), `${JSON.stringify(report, null, 2)}\n`);
  }
}

try {
  await check('blocked_handoff_preserves_active_observations', fixture(), async page => {
    const packet = JSON.parse(await readFile(path.join(root, 'examples/agent-handoff-synthetic.json'), 'utf8'));
    packet.account_scope = 'Synthetic missing-period replacement';
    packet.coverage.missing_periods = [{ start: '2025-01-04', end: '2025-01-05', reason: 'Synthetic unavailable source interval.' }];
    const text = JSON.stringify(packet);
    await choose(page, { name: 'blocked-synthetic-handoff.json', mimeType: 'application/json', buffer: Buffer.from(text) });
    await waitForAttempt(page, 'blocked-synthetic-handoff.json');
    assert.equal(await observations(page).inputValue(), csv);
    assert.equal(await page.getByRole('dialog').count(), 0);
    const stored = await exportedDraft(page, 'blocked-handoff-private-draft');
    assert.equal(stored.reconciliation.sources[0].text, text);
    assert.equal(stored.reconciliation.sources[0].disposition, 'unresolved');
    return { original_observations_preserved: true, rejected_text_retained_exactly: true };
  });

  await check('unread_file_retains_exact_declared_length', fixture(), async page => {
    const bytes = Buffer.from('Synthetic inaccessible input bytes.\n');
    await page.evaluate(() => {
      const original = File.prototype.arrayBuffer;
      File.prototype.arrayBuffer = function () {
        if (this.name === 'unread-synthetic.csv') return Promise.reject(new DOMException('Injected synthetic read failure', 'NotReadableError'));
        return original.call(this);
      };
    });
    await choose(page, { name: 'unread-synthetic.csv', mimeType: 'text/csv', buffer: bytes });
    await waitForAttempt(page, 'unread-synthetic.csv');
    assert.equal(await observations(page).inputValue(), csv);
    const stored = await exportedDraft(page, 'unread-file-private-draft');
    const source = stored.reconciliation.sources.find(item => item.fileName === 'unread-synthetic.csv');
    assert.equal(source.unconsumed.byteLength, bytes.length);
    assert.equal(source.disposition, 'unresolved');
    assert.equal(source.text, '');
    assert.equal('rawBytesBase64' in source, false);
    return { declared_bytes: bytes.length, original_observations_preserved: true, missing_bytes_not_hashed: true };
  });

  await check('delayed_read_after_navigation_cannot_replace_saved_work', fixture(), async page => {
    await page.evaluate(() => {
      const original = File.prototype.arrayBuffer;
      File.prototype.arrayBuffer = async function () {
        const bytes = await original.call(this);
        if (this.name !== 'delayed-synthetic.csv') return bytes;
        window.syntheticReadStarted = true;
        return new Promise(resolve => { window.releaseSyntheticRead = () => resolve(bytes); });
      };
    });
    await choose(page, { name: 'delayed-synthetic.csv', mimeType: 'text/csv', buffer: Buffer.from(csv.replace('110,0', '150,0')) });
    await page.waitForFunction(() => window.syntheticReadStarted === true);
    await page.getByRole('button', { name: 'Review a record', exact: true }).click();
    await page.getByRole('heading', { name: 'Open a performance record', exact: true }).waitFor();
    await page.evaluate(() => window.releaseSyntheticRead());
    await page.getByRole('button', { name: 'Prepare a record', exact: true }).click();
    await page.getByText('Saved private draft restored in this browser.', { exact: true }).waitFor();
    await page.getByRole('button', { name: 'Import a file', exact: true }).click();
    assert.equal(await observations(page).inputValue(), csv);
    const stored = await exportedDraft(page, 'after-delayed-read-private-draft');
    assert.equal(stored.input, csv);
    assert.equal(stored.reconciliation.sources.length, 0);
    return { late_read_did_not_replace_new_mount: true, saved_input_unchanged: true };
  });

  await check('combined_ledger_capacity_rejected_before_discard_guard', fixture(Array.from({ length: 18 }, (_, index) => attempt(`historical-${index}.csv`, 'excluded'))), async page => {
    const ownerScope = 'Synthetic unsaved scope that must survive';
    await page.getByLabel('Accounts covered, using public aliases', { exact: true }).fill(ownerScope);
    const incoming = fixture([attempt('incoming-one.csv'), attempt('incoming-two.csv')]);
    incoming.input = csv.replace('110,0', '120,0');
    await choose(page, { name: 'over-capacity-private-draft.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify({ kind: 'n170.private-draft.v1', data: incoming })) });
    await page.getByRole('alert').filter({ hasText: /source|reconciliation|capacity|invalid|limit/i }).first().waitFor();
    assert.equal(await page.getByRole('dialog').count(), 0, 'Invalid combined candidate must fail before the discard decision');
    assert.equal(await observations(page).inputValue(), csv);
    assert.equal(await page.getByLabel('Accounts covered, using public aliases', { exact: true }).inputValue(), ownerScope);
    const stored = await exportedDraft(page, 'after-capacity-rejection-private-draft');
    assert.equal(stored.input, csv);
    for (let index = 0; index < 18; index++) assert(stored.reconciliation.sources.some(item => item.fileName === `historical-${index}.csv`));
    return { original_18_sources_preserved: true, unsaved_scope_preserved: true, no_discard_guard_for_invalid_merge: true };
  });

  await check('source_decision_editor_cannot_follow_replaced_source_index', fixture([attempt('old-unresolved.csv')]), async page => {
    await page.getByRole('button', { name: 'Review source decision', exact: true }).click();
    await page.getByLabel('Private reason and relationship to selected scope', { exact: true }).fill('STALE PRIVATE REASON FOR OLD FILE ONLY');
    await page.getByRole('button', { name: 'Clear workspace', exact: true }).click();
    if (await page.getByRole('dialog').count()) await page.getByRole('button', { name: 'Discard draft changes', exact: true }).click();
    assert.equal(await observations(page).inputValue(), '');
    await choose(page, { name: 'new-unresolved.csv', mimeType: 'text/csv', buffer: Buffer.from(rejected) });
    await waitForAttempt(page, 'new-unresolved.csv');
    assert.equal(await page.getByLabel('Private reason and relationship to selected scope', { exact: true }).count(), 0);
    await page.getByRole('button', { name: 'Review source decision', exact: true }).click();
    assert.equal(await page.getByLabel('Private reason and relationship to selected scope', { exact: true }).inputValue(), '');
    assert.equal(await page.getByRole('button', { name: 'Record source decision', exact: true }).isEnabled(), false);
    return { stale_reason_discarded: true, new_source_requires_new_review: true };
  });

  await check('synthetic_example_switch_preserves_previous_evidence', fixture([attempt('retained-before-example.csv')]), async page => {
    await page.getByRole('button', { name: 'Try a synthetic example', exact: true }).click();
    if (await page.getByRole('dialog').count()) await page.getByRole('button', { name: 'Save draft & continue', exact: true }).click();
    await waitForAttempt(page, 'retained-before-example.csv');
    const stored = await exportedDraft(page, 'after-example-switch-private-draft');
    assert.notEqual(stored.input, csv);
    assert.equal(stored.synthetic, true);
    assert(stored.reconciliation.sources.some(source => source.fileName === 'retained-before-example.csv' && source.disposition === 'unresolved'));
    assert(stored.reconciliation.sources.some(source => source.text === csv && source.disposition === 'unresolved'));
    assert.equal(await page.getByRole('button', { name: 'Review calculation', exact: true }).isEnabled(), false);
    return { rejected_attempt_preserved: true, prior_observations_retained_unresolved: true, calculation_stays_blocked: true };
  });
} finally {
  report.finished_at = new Date().toISOString();
  report.source_sha256_after = await hashes();
  report.sources_changed_during_run = JSON.stringify(report.source_sha256_before) !== JSON.stringify(report.source_sha256_after);
  await writeFile(path.join(out, 'results.json'), `${JSON.stringify(report, null, 2)}\n`);
  await browser.close();
}
if (report.tests.some(result => result.status !== 'passed')) process.exitCode = 1;
