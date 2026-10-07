// Production UI recovery checks. Every key/profile is created by the actual UI.
// Synthetic observations only; only the post-commit refresh fault is injected.
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { inspectContinuityPackage } from '../src/keyContinuity.js';

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const base = process.env.N170_PREVIEW_URL || 'http://127.0.0.1:4190/';
const out = process.env.N170_EVIDENCE_DIR || path.join(root, '../continuity-evidence/ui-recovery');
const observed = ['src/DeviceContinuityPanel.jsx', 'src/OwnerWorkspace.jsx', 'src/keyStore.js', 'src/keyContinuity.js', 'dist/client/index.html'];
const hashes = async () => Object.fromEntries(await Promise.all(observed.map(async file => [file, createHash('sha256').update(await readFile(path.join(root, file))).digest('hex')])));
await mkdir(out, { recursive: true });
const report = {
  started_at: new Date().toISOString(), base, source_sha256_before: await hashes(), tests: [],
  scope: 'Production owner UI in isolated Chromium contexts. All profiles and nonextractable keys are created through the UI from original synthetic observations. IndexedDB is read for lifecycle assertions; a one-shot cursor error models list refresh failure after commit.',
  limitations: ['Agent validation, not an external audit.', 'Injected refresh failure does not reproduce physical disk faults.', 'Chromium only; real hardware transfer and browser/OS restart are not covered.'],
};
const browser = await chromium.launch({ headless: true });
report.browser = await browser.version();
const panel = page => page.locator('.device-continuity');

async function openPanel(page) {
  if ((await panel(page).getAttribute('open')) === null) await panel(page).locator(':scope > summary').click();
}
async function upload(page, label, value, name) {
  await page.getByText(label, { exact: true }).locator('input').setInputFiles({ name, mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(value)) });
}
async function download(page, name, file, scope = page) {
  const event = page.waitForEvent('download');
  await scope.getByRole('button', { name, exact: true }).click();
  const received = await event;
  const target = path.join(out, file);
  await received.saveAs(target);
  return JSON.parse(await readFile(target, 'utf8'));
}
async function seedOwner(page, suffix) {
  await page.getByRole('button', { name: 'Import a file', exact: true }).click();
  const input = page.getByLabel('Date, net asset value, external flow', { exact: true });
  if (!await input.isVisible()) await page.getByText('Or enter observations manually', { exact: true }).click();
  await input.fill('date,nav,external_flow\n2025-03-03,100,0\n2025-03-04,90,0');
  await page.getByLabel('Accounts covered, using public aliases', { exact: true }).fill(`Original fictional account for ${suffix}`);
  await page.getByLabel('External cash activity review', { exact: true }).selectOption('reviewed_no_hidden');
  await page.getByLabel('Timing of every external flow', { exact: true }).selectOption('interval_end');
  await page.getByRole('button', { name: 'Save draft', exact: true }).click();
  await page.getByText(/Private draft saved in this browser/).waitFor();
  await page.getByRole('button', { name: 'Review calculation', exact: true }).click();
  await page.getByRole('heading', { name: 'Review before you sign', exact: true }).waitFor();
  await page.getByLabel('Public profile alias', { exact: true }).fill(`Synthetic UI recovery ${suffix}`);
  await page.getByRole('button', { name: 'Create profile', exact: true }).click();
  await page.getByText(/Profile created and saved/).waitFor();
  await page.getByRole('checkbox', { name: /I reviewed the calculation/ }).check();
  await page.getByRole('button', { name: 'Sign record & save', exact: true }).click();
  await page.getByRole('heading', { name: 'Ready for a thoughtful review.', exact: true }).waitFor();
  await page.getByText('Machine-readable record & retained checkpoint', { exact: true }).click();
  return download(page, 'Download signed JSON', `${suffix}-root-profile.json`);
}
async function createRequest(page, history, file) {
  await openPanel(page);
  await upload(page, 'Choose old-device evidence', history, 'synthetic-old-history.json');
  const result = await download(page, 'Create device-change request', file, panel(page));
  await panel(page).getByText('Pending on this device', { exact: true }).waitFor();
  return result;
}
async function prepareApproval(page, request) {
  await openPanel(page);
  await panel(page).getByRole('button', { name: 'Old device', exact: true }).click();
  await upload(page, 'Choose destination request', request, 'synthetic-destination-request.json');
  await panel(page).getByRole('checkbox', { name: /I compared this destination key code/ }).check();
}
async function approve(page, request, file) {
  await prepareApproval(page, request);
  const result = await download(page, 'Approve and retire this local key', file, panel(page));
  await panel(page).getByText('Committed changes retained here', { exact: true }).waitFor();
  assert.equal((await inspectContinuityPackage(result)).transition_signatures_valid, true);
  return result;
}
async function lifecycle(page) {
  return page.evaluate(() => new Promise((resolve, reject) => {
    const open = indexedDB.open('n170-verify');
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result;
      const transaction = db.transaction(['profiles', 'continuity']);
      let profiles; let states;
      const profileRequest = transaction.objectStore('profiles').getAll();
      const stateRequest = transaction.objectStore('continuity').getAll();
      profileRequest.onsuccess = () => { profiles = profileRequest.result.map(entry => ({ profile_id: entry.profile.profile_id, stamps: entry.profile.stamps.length, key_extractable: entry.privateKey.extractable })); };
      stateRequest.onsuccess = () => { states = stateRequest.result.map(state => ({ lifecycle: state.lifecycle, outgoing_sha256: state.outgoingSha256 || null, pending_sha256: state.requestSha256 || null })); };
      transaction.oncomplete = () => { db.close(); resolve({ profiles, states }); };
      transaction.onabort = () => { db.close(); reject(transaction.error); };
    };
  }));
}
async function check(name, work) {
  const contexts = []; const pages = []; const errors = []; const external = [];
  const started = Date.now();
  const device = async () => {
    const context = await browser.newContext({ acceptDownloads: true, viewport: { width: 1440, height: 1000 } });
    contexts.push(context);
    const page = await context.newPage(); pages.push(page); page.setDefaultTimeout(10000);
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => { if (!request.url().startsWith(base) && !request.url().startsWith('blob:') && !request.url().startsWith('data:')) external.push(request.url()); });
    await page.goto(base);
    await page.getByText('Private draft up to date', { exact: true }).waitFor();
    assert.match(await page.locator('meta[http-equiv="Content-Security-Policy"]').getAttribute('content'), /connect-src 'none'/);
    assert.equal(await page.locator('vite-error-overlay').count(), 0);
    return page;
  };
  try {
    const evidence = await work(device);
    assert.deepEqual(errors, []); assert.deepEqual(external, []);
    for (let index = 0; index < pages.length; index++) await pages[index].screenshot({ path: path.join(out, `${name}-device-${index}.png`), fullPage: true });
    report.tests.push({ name, status: 'passed', elapsed_ms: Date.now() - started, evidence, runtimeErrors: errors, externalRequests: external });
    console.log(`PASS ${name}`);
  } catch (error) {
    for (let index = 0; index < pages.length; index++) {
      await pages[index].screenshot({ path: path.join(out, `${name}-failure-${index}.png`), fullPage: true }).catch(() => {});
      await writeFile(path.join(out, `${name}-failure-${index}.txt`), await pages[index].locator('body').innerText().catch(() => ''));
    }
    report.tests.push({ name, status: 'failed', elapsed_ms: Date.now() - started, error: error.stack, runtimeErrors: errors, externalRequests: external });
    console.log(`FAIL ${name}: ${error.message}`);
  } finally {
    await Promise.all(contexts.map(context => context.close()));
    await writeFile(path.join(out, 'results.json'), `${JSON.stringify(report, null, 2)}\n`);
  }
}

try {
  await check('orphan_approval_discoverable_and_downloadable_after_key_deletion', async device => {
    const old = await device(); const next = await device();
    const history = await seedOwner(old, 'orphan');
    const request = await createRequest(next, history, 'orphan-request.json');
    const completion = await approve(old, request, 'orphan-completion.json');
    // Approval returns the old owner to observations; the retired key remains
    // readable, with deletion available from the calculation/profile screen.
    await old.getByRole('button', { name: 'Review calculation', exact: true }).click();
    await old.getByRole('heading', { name: 'Review before you sign', exact: true }).waitFor();
    await old.getByRole('button', { name: 'Delete local key & records', exact: true }).click();
    await old.getByRole('dialog').getByRole('button', { name: 'Delete local key & records', exact: true }).click();
    await old.getByText('Local key and records deleted. Previously exported evidence remains valid.', { exact: true }).waitFor();
    await old.reload(); await old.getByText(/Saved private draft restored/).waitFor();
    await openPanel(old);
    await panel(old).getByText('Committed changes retained here', { exact: true }).waitFor();
    assert.match(await panel(old).innerText(), /deleted locally/);
    const recovered = await download(old, 'Download committed completion', 'orphan-completion-recovered.json', panel(old));
    assert.deepEqual(recovered, completion);
    const state = await lifecycle(old);
    assert.equal(state.profiles.length, 0);
    assert.equal(state.states[0].lifecycle, 'deleted');
    assert.equal(state.states[0].outgoing_sha256, completion.transitions[0].sha256);
    assert.equal(await old.getByRole('button', { name: 'Open saved profile', exact: true }).count(), 0);
    return { key_deleted_via_ui: true, committed_approval_discovered_without_request_reimport: true, recovered_package_identical: true };
  });

  await check('cancelled_request_and_stale_completion_cannot_activate_any_pending_key', async device => {
    const old = await device(); const next = await device();
    const history = await seedOwner(old, 'cancel');
    const request = await createRequest(next, history, 'cancel-original-request.json');
    const completion = await approve(old, request, 'cancel-already-signed-completion.json');
    await panel(next).getByRole('button', { name: 'Cancel pending request', exact: true }).click();
    await panel(next).getByText(/Pending request cancelled locally/).waitFor();
    const second = await createRequest(next, history, 'cancel-new-pending-request.json');
    assert.notEqual(second.payload.new_profile_id, request.payload.new_profile_id);
    await upload(next, 'Choose signed completion', completion, 'stale-cancelled-completion.json');
    await panel(next).getByRole('button', { name: 'Complete device change', exact: true }).click();
    await panel(next).getByRole('alert').filter({ hasText: /pending local destination|Continuity cannot be established/ }).waitFor();
    const state = await lifecycle(next);
    assert.equal(state.profiles.length, 2);
    assert(state.profiles.every(profile => profile.stamps === 0 && profile.key_extractable === false));
    assert.deepEqual(state.states.map(entry => entry.lifecycle).sort(), ['cancelled', 'pending']);
    const retained = await download(next, 'Download saved request', 'cancel-new-pending-request-retry.json', panel(next));
    assert.deepEqual(retained, second);
    const openButtons = next.getByRole('button', { name: 'Open saved profile', exact: true });
    for (let index = 0; index < await openButtons.count(); index++) assert.equal(await openButtons.nth(index).isEnabled(), false);
    return { cancelled_key_inactive: true, new_pending_request_unchanged: true, stale_valid_completion_refused: true, neither_key_activated: true };
  });

  await check('old_key_loss_before_approval_cannot_establish_continuity', async device => {
    const old = await device(); const next = await device();
    const history = await seedOwner(old, 'lost-before-approval');
    const request = await createRequest(next, history, 'lost-key-pending-request.json');
    await old.getByRole('button', { name: 'Review / correct this period', exact: true }).click();
    await old.getByRole('heading', { name: 'Review before you sign', exact: true }).waitFor();
    await old.getByRole('button', { name: 'Delete local key & records', exact: true }).click();
    await old.getByRole('dialog').getByRole('button', { name: 'Delete local key & records', exact: true }).click();
    await old.getByText('Local key and records deleted. Previously exported evidence remains valid.', { exact: true }).waitFor();
    await old.reload(); await old.getByText(/Saved private draft restored/).waitFor();
    await openPanel(old);
    await panel(old).getByRole('button', { name: 'Old device', exact: true }).click();
    await upload(old, 'Choose destination request', request, 'request-after-old-key-loss.json');
    await panel(old).getByText(/This device has no usable old signing key. Continuity cannot be established through a new approval/).waitFor();
    assert.equal(await panel(old).getByRole('checkbox', { name: /I compared this destination key code/ }).isEnabled(), false);
    assert.equal(await panel(old).getByRole('button', { name: 'Approve and retire this local key', exact: true }).isEnabled(), false);
    assert.equal(await panel(old).getByRole('button', { name: 'Download committed completion', exact: true }).count(), 0);
    let downloads = 0;
    old.on('download', () => downloads++);
    await panel(old).getByRole('button', { name: 'Download saved completion', exact: true }).click();
    await panel(old).getByRole('alert').filter({ hasText: /No committed completion is retained/ }).waitFor();
    assert.equal(downloads, 0);
    const state = await lifecycle(old);
    assert.deepEqual(state, { profiles: [], states: [] });
    const destinationState = await lifecycle(next);
    assert.equal(destinationState.states[0].lifecycle, 'pending');
    return { key_lost_before_approval: true, new_approval_disabled: true, continuity_unavailable_explicit: true, no_completion_invented_or_downloaded: true, destination_stays_pending: true };
  });

  await check('committed_approval_download_survives_postcommit_profile_refresh_failure', async device => {
    const old = await device(); const next = await device();
    const history = await seedOwner(old, 'refresh');
    const request = await createRequest(next, history, 'refresh-request.json');
    await prepareApproval(old, request);
    await old.evaluate(() => {
      const original = IDBObjectStore.prototype.openCursor;
      IDBObjectStore.prototype.openCursor = function (...args) {
        if (this.name === 'profiles' && this.transaction.mode === 'readonly') {
          IDBObjectStore.prototype.openCursor = original;
          window.syntheticPostCommitRefreshFailure = true;
          throw new DOMException('Injected profile list refresh failure after continuity commit', 'UnknownError');
        }
        return original.apply(this, args);
      };
    });
    const completion = await download(old, 'Approve and retire this local key', 'refresh-committed-completion.json', panel(old));
    assert.equal((await inspectContinuityPackage(completion)).transition_signatures_valid, true);
    assert.equal(await old.evaluate(() => window.syntheticPostCommitRefreshFailure), true);
    await panel(old).locator('[role="status"], [role="alert"]').filter({ hasText: /profile list could not refresh/i }).waitFor();
    assert.match(await panel(old).innerText(), /Device change committed|change was committed|committed.*retained/i);
    const state = await lifecycle(old);
    assert.equal(state.states[0].lifecycle, 'retired');
    assert.equal(state.states[0].outgoing_sha256, completion.transitions[0].sha256);
    await panel(old).screenshot({ path: path.join(out, 'postcommit-refresh-warning.png') });
    await old.reload(); await old.getByText(/Saved private draft restored/).waitFor();
    await openPanel(old); await panel(old).getByText('Committed changes retained here', { exact: true }).waitFor();
    assert.deepEqual(await download(old, 'Download committed completion', 'refresh-completion-after-reload.json', panel(old)), completion);
    return { list_refresh_failure_injected: true, completion_downloaded_despite_refresh_failure: true, committed_state_explicit: true, identical_completion_available_after_reload: true };
  });
} finally {
  report.finished_at = new Date().toISOString(); report.source_sha256_after = await hashes();
  report.source_unchanged_during_run = JSON.stringify(report.source_sha256_before) === JSON.stringify(report.source_sha256_after);
  report.summary = { passed: report.tests.filter(test => test.status === 'passed').length, failed: report.tests.filter(test => test.status === 'failed').length };
  await writeFile(path.join(out, 'results.json'), `${JSON.stringify(report, null, 2)}\n`);
  await browser.close();
}
console.log(JSON.stringify({ output: path.join(out, 'results.json'), ...report.summary, source_unchanged_during_run: report.source_unchanged_during_run }));
if (report.summary.failed || !report.source_unchanged_during_run) process.exitCode = 1;
