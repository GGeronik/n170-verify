// Real-browser storage integration harness. No production CSP is disabled.
// Run: node scripts/browser-storage.mjs
// Optional PLAYWRIGHT_MODULE=/path/to/playwright/index.mjs; no dependency install.
import { createServer } from 'node:http';
import { readFile, mkdir, writeFile, access } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const modulePath = process.env.PLAYWRIGHT_MODULE || 'playwright';
const { chromium, firefox, webkit } = await import(modulePath.startsWith('/') ? pathToFileURL(modulePath) : modulePath);
const observedFiles = ['src/keyStore.js', 'src/draftStore.js', 'src/signing.js', 'src/trackRecord.js', 'src/calculator.js', 'src/draftModel.js', 'src/importer.js'];
const sourceHashes = async () => Object.fromEntries(await Promise.all(observedFiles.map(async path => [path, createHash('sha256').update(await readFile(resolve(root, path))).digest('hex')])));
const beforeHashes = await sourceHashes();
const report = {
  started_at: new Date().toISOString(), tool: 'Playwright', playwright_module: modulePath,
  scope: 'Actual browser IndexedDB/WebCrypto integration using current source modules on a separate loopback-only fixture origin. Synthetic data only. Production GUI and CSP are not tested by this harness.',
  routing: 'Browser plugin not available; purpose-built Playwright storage harness explicitly requested.',
  production_csp_modified: false, browsers: [], source_sha256: beforeHashes,
  limitations: ['Playwright WebKit, if available, is not Safari; Safari browser behavior is not established.', 'Storage quota/open errors are injected deterministic faults, not an exhausted physical disk or browser eviction.', 'Reload persistence is tested in one browser context; browser restart, OS reboot, private-mode eviction and storage pressure are not simulated.', 'Held signing capability survival is deliberate WebCrypto behavior; removing IndexedDB data is not external key revocation.', 'This harness tests modules, not user-visible navigation or accessibility.'],
};

const server = createServer(async (req, res) => {
  try {
    const path = new URL(req.url, 'http://127.0.0.1').pathname;
    res.setHeader('Cache-Control', 'no-store');
    if (path === '/') {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.end('<!doctype html><html lang="en"><title>N170 Verify storage test harness</title><body><h1>N170 Verify storage test harness</h1><p>Synthetic data · isolated test origin</p></body></html>');
    } else if (/^\/src\/[A-Za-z0-9_-]+\.js$/.test(path)) {
      res.setHeader('Content-Type', 'text/javascript; charset=utf-8'); res.end(await readFile(resolve(root, path.slice(1))));
    } else { res.statusCode = 404; res.end('Not found'); }
  } catch { res.statusCode = 500; res.end('Fixture module unavailable'); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const url = `http://127.0.0.1:${server.address().port}`;
report.fixture_origin = url;

async function pageIn(context) {
  const page = await context.newPage();
  await page.goto(url);
  await page.evaluate(async () => {
    window.store = await import('/src/keyStore.js');
    window.drafts = await import('/src/draftStore.js');
    window.records = await import('/src/trackRecord.js');
    window.signing = await import('/src/signing.js');
    window.input = 'date,nav,external_flow\n2025-01-01,100,0\n2025-01-02,110,0';
    window.nextInput = 'date,nav,external_flow\n2025-01-02,110,0\n2025-01-03,111,0';
  });
  return page;
}

try {
  for (const [name, type] of Object.entries({ chromium, firefox, webkit })) {
    const result = { type: name, executable: type.executablePath(), tests: [] };
    report.browsers.push(result);
    try { await access(result.executable); }
    catch { result.status = 'not_run'; result.reason = 'Browser binary is not installed; no browser download performed.'; continue; }
    let browser;
    try { browser = await type.launch({ headless: true }); }
    catch (error) { result.status = 'not_run'; result.reason = error.message; continue; }
    result.version = browser.version();
    result.status = 'passed';
    const check = async (name, work) => {
      const context = await browser.newContext(); const start = Date.now();
      try {
        const evidence = await Promise.race([work(context), new Promise((_, reject) => { const timer = setTimeout(() => reject(new Error('Test exceeded 20 seconds')), 20000); timer.unref(); })]);
        result.tests.push({ name, status: 'passed', elapsed_ms: Date.now() - start, evidence });
      } catch (error) { result.status = 'failed'; result.tests.push({ name, status: 'failed', elapsed_ms: Date.now() - start, error: error.stack || error.message }); }
      finally { await context.close(); }
    };

    await check('real_indexeddb_key_roundtrip_and_reload', async context => {
      const page = await pageIn(context);
      const original = await page.evaluate(async () => {
        const entry = await store.createStoredProfile('Synthetic persistence test');
        const next = await records.appendPerformanceStamp(entry.profile, input, 252, entry.signer);
        await store.appendStoredRecord(next);
        return { id: next.profile_id, hash: next.stamps[0].sha256, user_agent: navigator.userAgent };
      });
      await page.reload();
      await page.evaluate(async () => { window.store = await import('/src/keyStore.js'); window.records = await import('/src/trackRecord.js'); });
      const restored = await page.evaluate(async () => {
        const entry = (await store.listStoredProfiles())[0];
        const check = await records.inspectProfile(JSON.stringify(entry.profile));
        const next = await records.appendPerformanceStamp(entry.profile, 'date,nav,external_flow\n2025-01-02,110,0\n2025-01-03,111,0', 252, entry.signer);
        await store.appendStoredRecord(next);
        return { id: entry.profile.profile_id, hash: entry.profile.stamps[0].sha256, checks: check.checks, count_after_append: next.stamps.length };
      });
      assert.equal(restored.id, original.id); assert.equal(restored.hash, original.hash); assert.equal(restored.count_after_append, 2);
      assert.equal(restored.checks.signatures_valid, true); assert.equal(restored.checks.arithmetic_valid, true);
      return { user_agent: original.user_agent, restored_records: 1, newly_signed_after_reload: true, signature_and_arithmetic_valid: true };
    });

    await check('two_tab_competing_appends_commit_only_one_branch', async context => {
      const a = await pageIn(context); const b = await pageIn(context);
      await a.evaluate(async () => { window.entry = await store.createStoredProfile('Synthetic concurrent history'); });
      await b.evaluate(async () => { window.entry = (await store.listStoredProfiles())[0]; });
      await Promise.all([
        a.evaluate(async () => { window.proposal = await records.appendPerformanceStamp(entry.profile, input, 252, entry.signer); }),
        b.evaluate(async () => { window.proposal = await records.appendPerformanceStamp(entry.profile, input.replace('110,0', '105,0'), 252, entry.signer); }),
      ]);
      const outcomes = await Promise.all([a, b].map(page => page.evaluate(async () => {
        try { await store.appendStoredRecord(proposal); return { committed: true, hash: proposal.stamps[0].sha256 }; }
        catch (error) { return { committed: false, code: error.code, message: error.message }; }
      })));
      assert.equal(outcomes.filter(value => value.committed).length, 1);
      assert.equal(outcomes.find(value => !value.committed).code, 'stale');
      const kept = await a.evaluate(async () => (await store.listStoredProfiles())[0].profile);
      assert.equal(kept.stamps.length, 1); assert.equal(kept.stamps[0].sha256, outcomes.find(value => value.committed).hash);
      return { committed: 1, refused: 1, refusal_code: 'stale', stored_records: 1 };
    });

    await check('deletion_does_not_revoke_loaded_crypto_handle_but_blocks_persistence', async context => {
      const a = await pageIn(context); const b = await pageIn(context);
      const id = await a.evaluate(async () => { window.entry = await store.createStoredProfile('Synthetic delete test'); return entry.profile.profile_id; });
      await b.evaluate(async () => { window.entry = (await store.listStoredProfiles())[0]; });
      assert.equal(await a.evaluate(id => store.deleteStoredProfile(id), id), true);
      const afterDelete = await b.evaluate(async () => {
        const bytes = new TextEncoder().encode('Synthetic loaded capability probe');
        const signature = await entry.signer.sign(bytes);
        const valid = await signing.verifySignature(await signing.importVerificationKey(entry.profile.public_key), signature, bytes);
        const proposal = await records.appendPerformanceStamp(entry.profile, input, 252, entry.signer);
        let persist; try { await store.appendStoredRecord(proposal); persist = { committed: true }; } catch (error) { persist = { committed: false, code: error.code }; }
        return { loaded_signature_valid: valid, held_handle_can_make_signed_record: proposal.stamps.length === 1, persist, stored_count: (await store.listStoredProfiles()).length };
      });
      assert.equal(afterDelete.loaded_signature_valid, true); assert.equal(afterDelete.persist.committed, false); assert.equal(afterDelete.persist.code, 'missing'); assert.equal(afterDelete.stored_count, 0);
      return afterDelete;
    });

    await check('nonextractable_key_clone_survives_and_raw_export_is_blocked', async context => {
      const page = await pageIn(context);
      const actual = await page.evaluate(async () => {
        const pair = await signing.generateProfileKey(); const clone = structuredClone(pair.privateKey);
        let rawExport; try { await crypto.subtle.exportKey('pkcs8', clone); rawExport = 'allowed'; } catch (error) { rawExport = error.name; }
        const bytes = new TextEncoder().encode('Synthetic capability clone'); const signer = signing.createSigner(clone, pair.publicKey);
        return { extractable: clone.extractable, raw_export: rawExport, signature_valid: await signing.verifySignature(await signing.importVerificationKey(pair.publicKey), await signer.sign(bytes), bytes) };
      });
      assert.equal(actual.extractable, false); assert.equal(actual.raw_export, 'InvalidAccessError'); assert.equal(actual.signature_valid, true); return actual;
    });

    await check('two_tab_draft_compare_and_swap_and_reload', async context => {
      const a = await pageIn(context); const b = await pageIn(context);
      const outcomes = await Promise.all([a, b].map((page, index) => page.evaluate(async index => {
        try { const saved = await drafts.saveDraft({ source: `Synthetic private draft ${index}` }, 0); return { saved: true, revision: saved.revision, source: saved.data.source }; }
        catch (error) { return { saved: false, message: error.message }; }
      }, index)));
      assert.equal(outcomes.filter(item => item.saved).length, 1); assert.match(outcomes.find(item => !item.saved).message, /Another tab/);
      await a.reload(); const restored = await a.evaluate(async () => (await import('/src/draftStore.js')).readDraft());
      assert.equal(restored.revision, 1); assert.equal(restored.data.source, outcomes.find(item => item.saved).source);
      const next = await a.evaluate(async () => (await import('/src/draftStore.js')).saveDraft({ source: 'Synthetic revised private draft' }, 1));
      assert.equal(next.revision, 2);
      return { initial_saves_committed: 1, competing_save_refused: true, restored_revision: 1, next_revision: 2 };
    });

    await check('persisted_import_success_is_rederived_after_reload', async context => {
      const page = await pageIn(context);
      await page.evaluate(async () => {
        const { createEmptyDraft } = await import('/src/draftModel.js');
        const { ibkrSampleInput, importStatement } = await import('/src/importer.js');
        const trusted = await importStatement(ibkrSampleInput, { currency: 'USD', flowTimingConfirmed: true });
        await drafts.saveDraft({ ...createEmptyDraft(), original: ibkrSampleInput, input: trusted.normalizedCsv,
          importReview: { canCalculate: true, mapping: [{ source: 'Forged authenticated broker' }], source: { authenticated: true } } }, 0);
      });
      await page.reload();
      const actual = await page.evaluate(async () => {
        const { readDraft } = await import('/src/draftStore.js');
        const { hydratePrivateDraft } = await import('/src/draftModel.js');
        const stored = await readDraft();
        const hydrated = await hydratePrivateDraft({ kind: 'n170.private-draft.v1', data: stored.data });
        return { revision: stored.revision, raw_source_retained: hydrated.original === stored.data.original,
          can_calculate: hydrated.importReview.canCalculate, authenticated: hydrated.importReview.source.authenticated,
          flow_review_blocked: hydrated.importReview.exceptions.some(item => item.code === 'flow_activity_review'),
          forged_mapping_retained: JSON.stringify(hydrated.importReview).includes('Forged authenticated broker') };
      });
      assert.equal(actual.revision, 1); assert.equal(actual.raw_source_retained, true);
      assert.equal(actual.can_calculate, false); assert.equal(actual.authenticated, false);
      assert.equal(actual.flow_review_blocked, true); assert.equal(actual.forged_mapping_retained, false);
      return actual;
    });

    await check('storage_open_failure_is_actionable_and_leaves_no_partial_profile', async context => {
      const page = await pageIn(context);
      const actual = await page.evaluate(async () => {
        const original = IDBFactory.prototype.open; const errors = [];
        IDBFactory.prototype.open = function () { throw new DOMException('Injected blocked IndexedDB', 'SecurityError'); };
        try {
          for (const action of [() => store.createStoredProfile('Synthetic refused key'), () => store.listStoredProfiles(), () => drafts.readDraft(), () => drafts.saveDraft({ source: 'Synthetic unsaved input' }, 0)]) {
            try { await action(); errors.push({ unexpectedly_succeeded: true }); } catch (error) { errors.push({ code: error.code || null, message: error.message }); }
          }
        } finally { IDBFactory.prototype.open = original; }
        return { errors, profiles_after_restore: (await store.listStoredProfiles()).length, draft_after_restore: await drafts.readDraft() };
      });
      assert.equal(actual.errors.length, 4); assert.equal(actual.errors.some(item => item.unexpectedly_succeeded), false);
      assert.match(actual.errors[0].message, /browser/); assert.match(actual.errors[2].message, /Export a private draft/);
      assert.equal(actual.profiles_after_restore, 0); assert.equal(actual.draft_after_restore, null); return actual;
    });

    await check('transaction_creation_failure_closes_database_and_explains_recovery', async context => {
      const page = await pageIn(context);
      const actual = await page.evaluate(async () => {
        await drafts.saveDraft({ source: 'Synthetic unchanged draft' }, 0);
        const originalTransaction = IDBDatabase.prototype.transaction;
        const originalClose = IDBDatabase.prototype.close;
        let closeCount = 0; let failure;
        IDBDatabase.prototype.transaction = function () { throw new DOMException('Injected transaction unavailable', 'InvalidStateError'); };
        IDBDatabase.prototype.close = function (...args) { closeCount += 1; return originalClose.apply(this, args); };
        try { await drafts.saveDraft({ source: 'Synthetic refused draft' }, 1); failure = { unexpectedly_succeeded: true }; }
        catch (error) { failure = { message: error.message }; }
        finally { IDBDatabase.prototype.transaction = originalTransaction; IDBDatabase.prototype.close = originalClose; }
        return { failure, connections_closed: closeCount, revision_preserved: (await drafts.readDraft()).revision };
      });
      assert.match(actual.failure.message, /export.*draft/i);
      assert.equal(actual.connections_closed, 1); assert.equal(actual.revision_preserved, 1);
      return actual;
    });

    await check('injected_profile_quota_failure_aborts_without_changing_history', async context => {
      const page = await pageIn(context); const pageErrors = []; page.on('pageerror', error => pageErrors.push(error.message));
      const actual = await page.evaluate(async () => {
        const entry = await store.createStoredProfile('Synthetic quota test');
        const proposal = await records.appendPerformanceStamp(entry.profile, input, 252, entry.signer);
        const original = IDBObjectStore.prototype.put; let failure;
        IDBObjectStore.prototype.put = function () { throw new DOMException('Injected quota exhaustion', 'QuotaExceededError'); };
        try { await store.appendStoredRecord(proposal); failure = { unexpectedly_succeeded: true }; }
        catch (error) { failure = { code: error.code, message: error.message }; }
        finally { IDBObjectStore.prototype.put = original; }
        const kept = (await store.listStoredProfiles())[0].profile;
        await store.appendStoredRecord(proposal);
        return { failure, records_after_failure: kept.stamps.length, records_after_retry: (await store.listStoredProfiles())[0].profile.stamps.length };
      });
      assert.equal(actual.failure.code, 'failed'); assert.equal(actual.records_after_failure, 0); assert.equal(actual.records_after_retry, 1);
      return { ...actual, expected_injected_page_errors: pageErrors };
    });

    await check('injected_draft_quota_failure_preserves_prior_revision', async context => {
      const page = await pageIn(context); const pageErrors = []; page.on('pageerror', error => pageErrors.push(error.message));
      const actual = await page.evaluate(async () => {
        await drafts.saveDraft({ source: 'Synthetic original draft' }, 0);
        const original = IDBObjectStore.prototype.put; let failure;
        IDBObjectStore.prototype.put = function () { throw new DOMException('Injected quota exhaustion', 'QuotaExceededError'); };
        try { await drafts.saveDraft({ source: 'Synthetic attempted replacement' }, 1); failure = { unexpectedly_succeeded: true }; }
        catch (error) { failure = { message: error.message }; }
        finally { IDBObjectStore.prototype.put = original; }
        const kept = await drafts.readDraft(); const retry = await drafts.saveDraft({ source: 'Synthetic retried replacement' }, 1);
        return { failure, revision_after_failure: kept.revision, source_after_failure: kept.data.source, revision_after_retry: retry.revision };
      });
      assert.match(actual.failure.message, /export a private draft/i); assert.equal(actual.revision_after_failure, 1); assert.equal(actual.source_after_failure, 'Synthetic original draft'); assert.equal(actual.revision_after_retry, 2);
      return { ...actual, expected_injected_page_errors: pageErrors };
    });
    await browser.close();
  }
} finally { await new Promise(resolve => server.close(resolve)); }
report.completed_at = new Date().toISOString();
report.source_unchanged_during_run = JSON.stringify(beforeHashes) === JSON.stringify(await sourceHashes());
report.summary = { browsers_run: report.browsers.filter(b => b.status !== 'not_run').length, tests_passed: report.browsers.flatMap(b => b.tests).filter(t => t.status === 'passed').length, tests_failed: report.browsers.flatMap(b => b.tests).filter(t => t.status === 'failed').length, unavailable_browsers: report.browsers.filter(b => b.status === 'not_run').map(b => b.type) };
const output = resolve(process.env.N170_EVIDENCE_DIR || resolve(root, 'docs/verification'), 'storage-results.json');
await mkdir(dirname(output), { recursive: true }); await writeFile(output, JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ output, ...report.summary, source_unchanged_during_run: report.source_unchanged_during_run }, null, 2));
if (report.summary.tests_failed || !report.summary.browsers_run || !report.source_unchanged_during_run) process.exitCode = 1;
