// Real IndexedDB/WebCrypto lifecycle checks on an isolated loopback fixture.
// Synthetic inputs only. This does not test the production UI or CSP.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const out = process.env.N170_EVIDENCE_DIR || path.join(root, '../continuity-evidence/storage');
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const observed = ['src/keyStore.js', 'src/keyContinuity.js', 'src/trackRecord.js', 'src/signing.js'];
const hashes = async () => Object.fromEntries(await Promise.all(observed.map(async file => [file, createHash('sha256').update(await readFile(path.join(root, file))).digest('hex')])));
await mkdir(out, { recursive: true });
const report = {
  started_at: new Date().toISOString(), source_sha256_before: await hashes(), tests: [],
  scope: 'Real Chromium IndexedDB and WebCrypto; separate browser contexts represent devices and same-context pages represent competing tabs. Original synthetic data only. No production UI, CSP, publication, identity, broker authentication, external timestamp or recovery claim.',
  limitations: ['Agent validation, not an external audit.', 'Storage errors are injected, not physical disk or browser eviction failures.', 'Device contexts are isolated within one Chromium process; OS restart and other browser engines are not covered.'],
};
const server = createServer(async (request, response) => {
  try {
    const pathname = new URL(request.url, 'http://127.0.0.1').pathname;
    response.setHeader('Cache-Control', 'no-store');
    if (pathname === '/') { response.setHeader('Content-Type', 'text/html; charset=utf-8'); response.end('<!doctype html><title>Synthetic continuity storage fixture</title><h1>Synthetic continuity storage checks</h1>'); }
    else if (/^\/src\/[A-Za-z0-9_-]+\.js$/.test(pathname)) { response.setHeader('Content-Type', 'text/javascript'); response.end(await readFile(path.join(root, pathname.slice(1)))); }
    else { response.statusCode = 404; response.end('Not found'); }
  } catch { response.statusCode = 500; response.end('Fixture source unavailable'); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}`;
report.fixture_origin = base;
const browser = await chromium.launch({ headless: true });
report.browser = await browser.version();

async function load(page) {
  await page.goto(base);
  await page.evaluate(async () => {
    window.store = await import('/src/keyStore.js');
    window.records = await import('/src/trackRecord.js');
    window.protocol = await import('/src/keyContinuity.js');
    window.signing = await import('/src/signing.js');
    window.syntheticCsv = (start, end, close = 90) => `date,nav,external_flow\n${start},100,0\n${end},${close},0`;
  });
}
async function seed(page) {
  return page.evaluate(async () => {
    window.owner = await store.createStoredProfile('Synthetic continuity account');
    const profile = await records.appendPerformanceStamp(owner.profile, syntheticCsv('2025-01-01', '2025-01-02'), 252, owner.signer, { synthetic: true });
    await store.appendStoredRecord(profile);
    owner.profile = profile;
    return profile;
  });
}
async function destination(page, history) {
  return page.evaluate(async history => {
    window.destination = await store.createStoredTransitionRequest(history);
    return { request: destination.request, profile: destination.profile, lifecycle: destination.lifecycle };
  }, history);
}
const approve = (page, request) => page.evaluate(request => store.approveStoredTransitionRequest(request), request);
const complete = (page, completion) => page.evaluate(async completion => {
  const entry = await store.completeStoredTransition(completion);
  return { profile: entry.profile, lifecycle: entry.lifecycle, continuity: entry.continuity };
}, completion);
const outcome = promise => promise.then(value => ({ ok: true, value }), error => ({ ok: false, error: error.message }));
function flipS(signature) {
  const bytes = Buffer.from(signature, 'base64url');
  const order = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
  const flipped = (order - BigInt(`0x${bytes.subarray(32).toString('hex')}`)).toString(16).padStart(64, '0');
  return Buffer.concat([bytes.subarray(0, 32), Buffer.from(flipped, 'hex')]).toString('base64url');
}
async function check(name, work) {
  const contexts = [];
  const pageErrors = [];
  const started = Date.now();
  const newPage = async existing => {
    const context = existing || await browser.newContext();
    if (!existing) contexts.push(context);
    const page = await context.newPage();
    page.on('pageerror', error => pageErrors.push(error.message));
    await load(page);
    return page;
  };
  try {
    const evidence = await work(newPage);
    assert.deepEqual(pageErrors, [], 'No uncaught application errors');
    report.tests.push({ name, status: 'passed', elapsed_ms: Date.now() - started, evidence });
    console.log(`PASS ${name}`);
  } catch (error) {
    report.tests.push({ name, status: 'failed', elapsed_ms: Date.now() - started, error: error.stack, pageErrors });
    console.log(`FAIL ${name}: ${error.message}`);
  } finally {
    await Promise.all(contexts.map(context => context.close()));
    await writeFile(path.join(out, 'results.json'), `${JSON.stringify(report, null, 2)}\n`);
  }
}

try {
  await check('legacy_v1_upgrade_preserves_exact_profile_and_nonextractable_key', async pageIn => {
    const page = await pageIn();
    const expected = await page.evaluate(async () => {
      const pair = await signing.generateProfileKey();
      const signer = signing.createSigner(pair.privateKey, pair.publicKey);
      let profile = await records.createProfile('Synthetic legacy migration', signer);
      profile = await records.appendPerformanceStamp(profile, syntheticCsv('2025-01-01', '2025-01-02'), 252, signer);
      const db = await new Promise((resolve, reject) => { const request = indexedDB.open('n170-verify', 1); request.onupgradeneeded = () => request.result.createObjectStore('profiles'); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
      await new Promise((resolve, reject) => { const tx = db.transaction('profiles', 'readwrite'); tx.objectStore('profiles').put({ privateKey: pair.privateKey, profile }, profile.profile_id); tx.oncomplete = resolve; tx.onabort = () => reject(tx.error); });
      db.close(); return profile;
    });
    const actual = await page.evaluate(async () => {
      const entry = (await store.listStoredProfiles())[0];
      const next = await records.appendPerformanceStamp(entry.profile, syntheticCsv('2025-01-02', '2025-01-03', 95), 252, entry.signer);
      await store.appendStoredRecord(next);
      return { before: entry.profile, lifecycle: entry.lifecycle, continuity: entry.continuity, count: (await store.listStoredProfiles())[0].profile.stamps.length };
    });
    assert.deepEqual(actual.before, expected); assert.equal(actual.lifecycle, 'active'); assert.equal(actual.continuity, null); assert.equal(actual.count, 2);
    return { profile_unchanged_by_upgrade: true, lifecycle: 'active', continued_signing: true };
  });

  await check('two_device_request_commit_reload_complete_and_signed_loss', async pageIn => {
    const old = await pageIn(); const next = await pageIn(); const profile = await seed(old); const proposed = await destination(next, profile);
    assert.equal(proposed.lifecycle, 'pending');
    const pending = await next.evaluate(async () => {
      const entry = (await store.listStoredProfiles())[0];
      const attempted = await records.appendPerformanceStamp(entry.profile, syntheticCsv('2025-01-02', '2025-01-03'), 252, entry.signer);
      let code; try { await store.appendStoredRecord(attempted); } catch (error) { code = error.code; }
      const db = await new Promise(resolve => { const r = indexedDB.open('n170-verify', 2); r.onsuccess = () => resolve(r.result); });
      const raw = await new Promise(resolve => { const r = db.transaction('profiles').objectStore('profiles').get(entry.profile.profile_id); r.onsuccess = () => resolve(r.result); }); db.close();
      let extraction; try { await crypto.subtle.exportKey('pkcs8', raw.privateKey); extraction = 'allowed'; } catch (error) { extraction = error.name; }
      return { code, extractable: raw.privateKey.extractable, extraction, request: await store.getStoredTransitionRequest(entry.profile.profile_id) };
    });
    assert.equal(pending.code, 'inactive'); assert.equal(pending.extractable, false); assert.equal(pending.extraction, 'InvalidAccessError'); assert.deepEqual(pending.request, proposed.request);
    const completion = await approve(old, proposed.request);
    await load(old); await load(next);
    const retired = await old.evaluate(async () => (await store.listStoredProfiles())[0].lifecycle); assert.equal(retired, 'retired');
    const activated = await complete(next, completion); assert.equal(activated.lifecycle, 'active'); assert.equal(activated.continuity.boundary, '2025-01-02');
    const evidence = await next.evaluate(async () => {
      const entry = (await store.listStoredProfiles())[0];
      const signed = await records.appendPerformanceStamp(entry.profile, syntheticCsv('2025-01-02', '2025-01-03', 80), 252, entry.signer, { synthetic: true });
      await store.appendStoredRecord(signed);
      const exported = await store.getStoredEvidence(entry.profile.profile_id);
      const checked = await protocol.inspectContinuityPackage(exported);
      return { exported, valid: checked.transition_signatures_valid, return_e8: checked.currentProfile.stamps[0].payload.metrics.total_return_twr_e8 };
    });
    assert.equal(evidence.valid, true); assert.equal(evidence.return_e8, -20_000_000); assert.equal(evidence.exported.profiles.length, 2);
    await writeFile(path.join(out, 'two-device-completion.json'), `${JSON.stringify(evidence.exported, null, 2)}\n`);
    return { pending_append_refused: true, private_key_nonextractable: true, completed_after_reload: true, destination_loss_e8: -20_000_000 };
  });

  await check('retry_identity_ignores_signature_malleability_and_does_not_rollback', async pageIn => {
    const old = await pageIn(); const next = await pageIn(); const profile = await seed(old); const proposed = await destination(next, profile);
    const completion = await approve(old, proposed.request);
    const variedRequest = structuredClone(proposed.request); variedRequest.new_signature = flipS(variedRequest.new_signature);
    assert.deepEqual(await approve(old, variedRequest), completion);
    const otherTab = await pageIn(next.context());
    const outcomes = await Promise.all([complete(next, completion), complete(otherTab, completion)]);
    assert(outcomes.every(result => result.lifecycle === 'active'));
    const variedCompletion = structuredClone(completion);
    variedCompletion.transitions[0].new_signature = flipS(variedCompletion.transitions[0].new_signature);
    variedCompletion.transitions[0].old_signature = flipS(variedCompletion.transitions[0].old_signature);
    await complete(next, variedCompletion);
    await next.evaluate(async () => { const entry = (await store.listStoredProfiles())[0]; const signed = await records.appendPerformanceStamp(entry.profile, syntheticCsv('2025-01-02', '2025-01-03'), 252, entry.signer); await store.appendStoredRecord(signed); });
    const retry = await complete(otherTab, completion);
    assert.equal(retry.profile.stamps.length, 1); assert.equal(retry.lifecycle, 'active');
    return { concurrent_duplicate_completion_idempotent: true, equivalent_signatures_same_identity: true, later_record_preserved: true };
  });

  await check('four_transitions_keep_full_chain_and_fifth_is_rejected', async pageIn => {
    let current = await pageIn(); let history = await seed(current); const ids = [history.profile_id]; const priorPages = [current]; const completed = [];
    for (let edge = 0; edge < 4; edge++) {
      const next = await pageIn(); const proposed = await destination(next, history);
      assert.equal(proposed.request.payload.previous_transition_sha256, edge ? history.transitions.at(-1).sha256 : null);
      const completion = await approve(current, proposed.request); await complete(next, completion);
      completed.push(completion); ids.push(proposed.profile.profile_id); priorPages.push(next);
      const day = edge + 2;
      history = await next.evaluate(async day => {
        const entry = (await store.listStoredProfiles())[0];
        const csv = syntheticCsv(`2025-01-${String(day).padStart(2, '0')}`, `2025-01-${String(day + 1).padStart(2, '0')}`, 90 + day);
        const signed = await records.appendPerformanceStamp(entry.profile, csv, 252, entry.signer); await store.appendStoredRecord(signed);
        return store.getStoredEvidence(entry.profile.profile_id);
      }, day);
      assert.equal(history.transitions.length, edge + 1); assert.equal(history.profiles.length, edge + 2);
      current = next;
    }
    assert.deepEqual(history.profiles.map(profile => profile.profile_id), ids);
    const fresh = await pageIn(); const failed = await outcome(destination(fresh, history)); assert.equal(failed.ok, false); assert.match(failed.error, /four transitions|unsupported/);
    assert.equal(await fresh.evaluate(async () => (await store.listStoredProfiles()).length), 0);
    const repeatedPriorCompletion = await complete(priorPages[1], completed[0]); assert.equal(repeatedPriorCompletion.lifecycle, 'retired');
    await writeFile(path.join(out, 'four-transition-chain.json'), `${JSON.stringify(history, null, 2)}\n`);
    return { transitions: 4, ordered_profiles: 5, fifth_refused_before_storage: true, old_completion_cannot_reactivate_retired_key: true };
  });

  await check('append_versus_transition_commits_exactly_one', async pageIn => {
    const old = await pageIn(); const competing = await pageIn(old.context()); const next = await pageIn(); const profile = await seed(old); const proposed = await destination(next, profile);
    const append = await old.evaluate(async () => { const entry = (await store.listStoredProfiles())[0]; return records.appendPerformanceStamp(entry.profile, syntheticCsv('2025-01-02', '2025-01-03'), 252, entry.signer); });
    const outcomes = await Promise.all([
      old.evaluate(async value => { try { await store.appendStoredRecord(value); return { ok: true, kind: 'append' }; } catch (error) { return { ok: false, kind: 'append', code: error.code }; } }, append),
      competing.evaluate(async request => { try { await store.approveStoredTransitionRequest(request); return { ok: true, kind: 'transition' }; } catch (error) { return { ok: false, kind: 'transition', code: error.code }; } }, proposed.request),
    ]);
    assert.equal(outcomes.filter(result => result.ok).length, 1);
    const kept = await old.evaluate(async () => { const entry = (await store.listStoredProfiles())[0]; return { lifecycle: entry.lifecycle, count: entry.profile.stamps.length, outgoing: !!entry.continuity?.outgoingPackage }; });
    const winner = outcomes.find(result => result.ok).kind;
    assert.deepEqual(kept, winner === 'append' ? { lifecycle: 'active', count: 2, outgoing: false } : { lifecycle: 'retired', count: 1, outgoing: true });
    return { outcomes, winner };
  });

  await check('competing_destinations_commit_only_one_and_identical_retry_survives', async pageIn => {
    const old = await pageIn(); const oldTab = await pageIn(old.context()); const a = await pageIn(); const b = await pageIn(); const profile = await seed(old);
    const first = await destination(a, profile); const second = await destination(b, profile);
    const outcomes = await Promise.all([outcome(approve(old, first.request)), outcome(approve(oldTab, second.request))]);
    assert.equal(outcomes.filter(result => result.ok).length, 1);
    const winner = outcomes[0].ok ? 0 : 1; const request = winner ? second.request : first.request;
    const retry = await approve(old, request); assert.deepEqual(retry, outcomes[winner].value);
    const stored = await old.evaluate(id => store.getStoredEvidence(id), profile.profile_id);
    assert.equal(stored.profiles.at(-1).profile_id, request.payload.new_profile_id);
    return { committed_destinations: 1, conflicting_destinations_refused: 1, committed_result_available_for_retry: true };
  });

  await check('transaction_failures_leave_no_partial_pending_or_retirement', async pageIn => {
    const old = await pageIn(); const next = await pageIn(); const profile = await seed(old);
    const creation = await next.evaluate(async history => {
      const original = IDBObjectStore.prototype.add; let code;
      IDBObjectStore.prototype.add = function (...args) { if (this.name === 'continuity') throw new DOMException('Injected continuity add failure', 'QuotaExceededError'); return original.apply(this, args); };
      try { await store.createStoredTransitionRequest(history); } catch (error) { code = error.code; } finally { IDBObjectStore.prototype.add = original; }
      return { code, profiles: (await store.listStoredProfiles()).length, states: (await store.listStoredContinuity()).length };
    }, profile);
    assert.deepEqual(creation, { code: 'failed', profiles: 0, states: 0 });
    const proposed = await destination(next, profile);
    const retirement = await old.evaluate(async request => {
      const original = IDBObjectStore.prototype.put; let code;
      IDBObjectStore.prototype.put = function (...args) { if (this.name === 'continuity') throw new DOMException('Injected continuity put failure', 'QuotaExceededError'); return original.apply(this, args); };
      try { await store.approveStoredTransitionRequest(request); } catch (error) { code = error.code; } finally { IDBObjectStore.prototype.put = original; }
      const entry = (await store.listStoredProfiles())[0]; return { code, lifecycle: entry.lifecycle, evidence: await store.getStoredEvidence(entry.profile.profile_id) };
    }, proposed.request);
    assert.equal(retirement.code, 'failed'); assert.equal(retirement.lifecycle, 'active'); assert.deepEqual(retirement.evidence, profile);
    const completion = await approve(old, proposed.request); assert.equal(completion.transitions.length, 1);
    return { pending_key_and_state_rolled_back_together: true, uncommitted_certificate_not_exported: true, old_key_remained_active_until_successful_retry: true };
  });

  await check('completion_failure_rolls_back_profile_and_lifecycle_together', async pageIn => {
    const old = await pageIn(); const next = await pageIn(); const proposed = await destination(next, await seed(old)); const completion = await approve(old, proposed.request);
    const actual = await next.evaluate(async completion => {
      const original = IDBObjectStore.prototype.put; let code;
      IDBObjectStore.prototype.put = function (...args) { if (this.name === 'continuity') throw new DOMException('Injected finalization failure after profile put', 'QuotaExceededError'); return original.apply(this, args); };
      try { await store.completeStoredTransition(completion); } catch (error) { code = error.code; } finally { IDBObjectStore.prototype.put = original; }
      const entry = (await store.listStoredProfiles())[0]; return { code, lifecycle: entry.lifecycle, stamps: entry.profile.stamps.length, completion: entry.continuity.completionPackage };
    }, completion);
    assert.deepEqual(actual, { code: 'failed', lifecycle: 'pending', stamps: 0, completion: null });
    assert.equal((await complete(next, completion)).lifecycle, 'active');
    return { failed_finalization_kept_pending: true, key_survived_for_exact_retry: true };
  });

  await check('effective_boundary_uses_latest_performance_not_final_correction_event', async pageIn => {
    const old = await pageIn(); const next = await pageIn(); await seed(old);
    const profile = await old.evaluate(async () => {
      let entry = (await store.listStoredProfiles())[0];
      let profile = await records.appendPerformanceStamp(entry.profile, syntheticCsv('2025-02-01', '2025-02-02', 110), 252, entry.signer); await store.appendStoredRecord(profile);
      profile = await records.appendCorrectionStamp(profile, 1, syntheticCsv('2025-01-01', '2025-01-02', 95), 252, entry.signer, { reason: 'Synthetic correction of the earlier segment.' }); await store.appendStoredRecord(profile); return profile;
    });
    const proposed = await destination(next, profile); const completion = await approve(old, proposed.request); const active = await complete(next, completion);
    assert.equal(proposed.request.payload.old_checkpoint.end, '2025-01-02'); assert.equal(active.continuity.boundary, '2025-02-02');
    const boundary = await next.evaluate(async () => {
      const entry = (await store.listStoredProfiles())[0];
      const tooEarly = await records.appendPerformanceStamp(entry.profile, syntheticCsv('2025-01-03', '2025-01-04'), 252, entry.signer);
      let code; try { await store.appendStoredRecord(tooEarly); } catch (error) { code = error.code; }
      const countAfterRefusal = (await store.listStoredProfiles())[0].profile.stamps.length;
      let proper = await records.appendPerformanceStamp(entry.profile, syntheticCsv('2025-02-02', '2025-02-03'), 252, entry.signer); await store.appendStoredRecord(proper);
      proper = await records.appendCorrectionStamp(proper, 1, syntheticCsv('2025-02-02', '2025-02-03', 92), 252, entry.signer, { reason: 'Synthetic destination correction.' }); await store.appendStoredRecord(proper);
      return { code, countAfterRefusal, finalCount: proper.stamps.length, valid: (await protocol.inspectContinuityPackage(await store.getStoredEvidence(entry.profile.profile_id))).transition_signatures_valid };
    });
    assert.deepEqual(boundary, { code: 'boundary', countAfterRefusal: 0, finalCount: 2, valid: true });
    return { checkpoint_end: '2025-01-02', effective_boundary: '2025-02-02', overlap_rejected_atomically: true, destination_correction_supported: true };
  });

  await check('deleted_old_key_retains_committed_completion_and_retry_without_resigning', async pageIn => {
    const old = await pageIn(); const next = await pageIn(); const profile = await seed(old); const proposed = await destination(next, profile); const completion = await approve(old, proposed.request);
    assert.equal(await old.evaluate(id => store.deleteStoredProfile(id), profile.profile_id), true);
    await load(old);
    const recovered = await approve(old, proposed.request); assert.deepEqual(recovered, completion);
    const retained = await old.evaluate(async id => ({ count: (await store.listStoredProfiles()).length, states: await store.listStoredContinuity(), evidence: await store.getStoredEvidence(id) }), profile.profile_id);
    assert.equal(retained.count, 0); assert.equal(retained.states[0].lifecycle, 'deleted'); assert.deepEqual(retained.evidence, completion); assert.deepEqual(retained.states[0].outgoingPackage, completion);
    assert.equal((await complete(next, recovered)).lifecycle, 'active');
    return { deleted_key_not_recovered: true, committed_evidence_discoverable_without_request_file: true, identical_retry_requires_no_signature: true };
  });

  await check('missing_old_or_pending_key_and_cancelled_requests_cannot_complete', async pageIn => {
    const old = await pageIn(); const next = await pageIn(); const profile = await seed(old); const proposed = await destination(next, profile);
    await old.evaluate(id => store.deleteStoredProfile(id), profile.profile_id);
    const missing = await outcome(approve(old, proposed.request)); assert.equal(missing.ok, false); assert.match(missing.error, /no longer kept/);
    // A held old signer still signs: deletion/retirement is local policy, not revocation.
    const completion = await old.evaluate(async request => (await protocol.approveTransitionRequest(request, owner.signer)).completionPackage, proposed.request);
    await next.evaluate(id => store.deleteStoredProfile(id), proposed.profile.profile_id);
    assert.equal((await outcome(complete(next, completion))).ok, false);
    assert.equal(await next.evaluate(async () => (await store.listStoredProfiles()).length), 0);
    const cancelled = await pageIn(); const cancelRequest = await destination(cancelled, profile);
    const cancelCompletion = await old.evaluate(async request => (await protocol.approveTransitionRequest(request, owner.signer)).completionPackage, cancelRequest.request);
    assert.equal(await cancelled.evaluate(id => store.cancelStoredTransition(id), cancelRequest.profile.profile_id), true);
    assert.equal((await outcome(complete(cancelled, cancelCompletion))).ok, false);
    const metadata = await cancelled.evaluate(async id => ({ state: await store.readStoredContinuity(id), request: await store.getStoredTransitionRequest(id) }), cancelRequest.profile.profile_id);
    assert.equal(metadata.state.lifecycle, 'cancelled'); assert.deepEqual(metadata.request, cancelRequest.request);
    return { lost_old_key_blocks_local_approval: true, held_key_is_not_revoked: true, deleted_pending_key_not_recoverable: true, cancellation_keeps_request_but_prevents_activation: true };
  });

  await check('stale_completion_and_omitted_incoming_chain_are_rejected', async pageIn => {
    const old = await pageIn(); const next = await pageIn(); const profile = await seed(old); const proposed = await destination(next, profile);
    const alternate = await next.evaluate(async history => protocol.createTransitionRequest(history, destination.profile, destination.signer), profile);
    const alteredCompletion = await old.evaluate(async request => (await protocol.approveTransitionRequest(request, owner.signer)).completionPackage, alternate);
    assert.equal((await outcome(complete(next, alteredCompletion))).ok, false);
    const proper = await approve(old, proposed.request); await complete(next, proper);
    const flat = await next.evaluate(async () => { const entry = (await store.listStoredProfiles())[0]; const profile = await records.appendPerformanceStamp(entry.profile, syntheticCsv('2025-01-02', '2025-01-03'), 252, entry.signer); await store.appendStoredRecord(profile); return profile; });
    const third = await pageIn(); const missingHistory = await destination(third, flat);
    assert.equal((await outcome(approve(next, missingHistory.request))).ok, false);
    assert.equal(await next.evaluate(async () => (await store.listStoredProfiles())[0].lifecycle), 'active');
    return { wrong_pending_challenge_refused: true, existing_signed_incoming_chain_cannot_be_dropped: true };
  });

  await check('blocked_upgrade_rejects_and_closes_delayed_upgrade_before_retry', async pageIn => {
    const page = await pageIn();
    const actual = await page.evaluate(async () => {
      const held = await new Promise((resolve, reject) => { const request = indexedDB.open('n170-verify', 1); request.onupgradeneeded = () => request.result.createObjectStore('profiles'); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
      held.onversionchange = () => {}; // Model another old tab refusing to close.
      let code; try { await store.listStoredProfiles(); } catch (error) { code = error.code; }
      held.close();
      const versionAfterRejectedRequest = await new Promise((resolve, reject) => { const request = indexedDB.open('n170-verify'); request.onsuccess = () => { const version = request.result.version; request.result.close(); resolve(version); }; request.onerror = () => reject(request.error); });
      const retry = await store.listStoredProfiles();
      const versionAfterRetry = await new Promise(resolve => { const request = indexedDB.open('n170-verify'); request.onsuccess = () => { const version = request.result.version; request.result.close(); resolve(version); }; });
      return { code, versionAfterRejectedRequest, versionAfterRetry, retryCount: retry.length };
    });
    assert.deepEqual(actual, { code: 'busy', versionAfterRejectedRequest: 1, versionAfterRetry: 2, retryCount: 0 });
    return actual;
  });

  await check('delete_all_keys_preserves_completed_public_evidence', async pageIn => {
    const old = await pageIn(); const next = await pageIn(); const profile = await seed(old); const proposed = await destination(next, profile); const completion = await approve(old, proposed.request); await complete(next, completion);
    const actual = await next.evaluate(async id => { const removed = await store.deleteAllStoredProfiles(); return { removed, count: (await store.listStoredProfiles()).length, continuity: await store.readStoredContinuity(id), evidence: await store.getStoredEvidence(id) }; }, proposed.profile.profile_id);
    assert.equal(actual.removed, 1); assert.equal(actual.count, 0); assert.equal(actual.continuity.lifecycle, 'deleted'); assert.deepEqual(actual.evidence, completion);
    assert.equal((await outcome(complete(next, completion))).ok, false);
    return { keys_removed: 1, committed_package_retained: true, no_key_recovery_on_reimport: true };
  });
} finally {
  report.finished_at = new Date().toISOString(); report.source_sha256_after = await hashes();
  report.source_unchanged_during_run = JSON.stringify(report.source_sha256_before) === JSON.stringify(report.source_sha256_after);
  report.summary = { passed: report.tests.filter(test => test.status === 'passed').length, failed: report.tests.filter(test => test.status === 'failed').length };
  await writeFile(path.join(out, 'results.json'), `${JSON.stringify(report, null, 2)}\n`);
  await browser.close(); await new Promise(resolve => server.close(resolve));
}
console.log(JSON.stringify({ output: path.join(out, 'results.json'), ...report.summary, source_unchanged_during_run: report.source_unchanged_during_run }));
if (report.summary.failed || !report.source_unchanged_during_run) process.exitCode = 1;
