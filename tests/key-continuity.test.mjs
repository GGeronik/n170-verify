import test from 'node:test';
import assert from 'node:assert/strict';
import { generateProfileKey, createSigner, encodeBase64Url, decodeBase64Url, sha256Hex, formatKeyCode } from '../src/signing.js';
import { createProfile, appendPerformanceStamp, appendCorrectionStamp, canonicalPayload, inspectProfile, publishedFingerprint } from '../src/trackRecord.js';
import { calculateRecordMetrics } from '../src/calculator.js';
import { CONTINUITY_SCHEMA, TRANSITION_REQUEST_SCHEMA, MAX_CONTINUITY_CHARACTERS, MAX_REQUEST_CHARACTERS, parseContinuityJSON, checkpointOf, effectiveEnd, canonicalTransitionPayload, transitionPayloadBytes, transitionSignatureBytes, inspectTransitionCertificate, inspectContinuityHistory, createTransitionRequest, inspectTransitionRequest, approveTransitionRequest, buildContinuityPackage, inspectContinuityPackage, compareContinuity } from '../src/keyContinuity.js';

const clone = value => structuredClone(value);
const csv = (start = '2026-01-01', end = '2026-01-02', nav = '90') => `date,nav,external_flow\n${start},100,0\n${end},${nav},0`;
const challenge = encodeBase64Url(Uint8Array.from({ length: 32 }, (_, index) => index));
async function key(alias = 'Synthetic continuity owner') {
  const generated = await generateProfileKey(); const signer = createSigner(generated.privateKey, generated.publicKey);
  return { signer, profile: await createProfile(alias, signer) };
}
async function first() {
  const old = await key(), next = await key(); old.profile = await appendPerformanceStamp(old.profile, csv(), 252, old.signer);
  const request = await createTransitionRequest(old.profile, next.profile, next.signer, challenge);
  const completion = await approveTransitionRequest(request, old.signer);
  return { old, next, request, completion, package: completion.package };
}
async function extend(pack, signer, start = '2026-01-02', end = '2026-01-03', nav = '110') {
  const result = clone(pack); result.profiles[result.profiles.length - 1] = await appendPerformanceStamp(result.profiles.at(-1), csv(start, end, nav), 252, signer); return result;
}
async function second() {
  const f = await first(); const prior = await extend(f.package, f.next.signer); const last = await key();
  const request = await createTransitionRequest(prior, last.profile, last.signer, challenge);
  const completed = await approveTransitionRequest(request, f.next.signer);
  return { ...f, prior, last, repeated: completed.package };
}
function equivalentSignature(text) {
  const bytes = decodeBase64Url(text, 64); const order = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
  const s = BigInt(`0x${Array.from(bytes.slice(32), byte => byte.toString(16).padStart(2, '0')).join('')}`);
  const other = (order - s).toString(16).padStart(64, '0'); bytes.set(Uint8Array.from(other.match(/../g), value => parseInt(value, 16)), 32); return encodeBase64Url(bytes);
}

test('request carries full checked old history, canonical challenge and new-role signature', async () => {
  const f = await first(); const checked = await inspectTransitionRequest(JSON.stringify(f.request));
  assert.equal(f.request.schema_version, TRANSITION_REQUEST_SCHEMA); assert.deepEqual(f.request.history, f.old.profile);
  assert.equal(checked.new_signature_valid, true); assert.equal(checked.sha256, f.completion.certificate.sha256);
  assert.deepEqual(checked.newProfile, f.next.profile); assert.equal(f.request.payload.previous_transition_sha256, null);
  assert.deepEqual(Object.keys(f.request), ['schema_version', 'payload', 'new_signature', 'history']);
});

test('completed first transition has distinct valid signatures and no implied independent anchor', async () => {
  const f = await first(); const checked = await inspectContinuityPackage(f.package);
  assert.equal(checked.transition_signatures_valid, true); assert.equal(checked.anchor_status, 'not_supplied');
  assert.equal(checked.currentProfile.stamps.length, 0); assert.equal(checked.merged_metrics, false);
  assert.equal(checked.checks.provider_authenticated, false); assert.equal(checked.checks.independent_timestamp, false);
  assert.deepEqual(await inspectTransitionCertificate(f.completion.certificate), f.completion.certificate);
  assert.equal(f.completion.package, f.completion.completionPackage);
});

test('canonical payload order and role domains are exact and previous digest is last', async () => {
  const f = await first(); const p = f.request.payload;
  assert.deepEqual(Object.keys(canonicalTransitionPayload(p)), ['schema_version', 'serialization_version', 'purpose', 'old_profile_id', 'old_public_key', 'old_display_name', 'old_checkpoint', 'new_profile_id', 'new_public_key', 'new_display_name', 'challenge', 'previous_transition_sha256']);
  const text = JSON.stringify(canonicalTransitionPayload(p));
  assert.equal(new TextDecoder().decode(transitionPayloadBytes(p)), text);
  assert.equal(new TextDecoder().decode(transitionSignatureBytes(p, 'old')), `n170.verify.key-transition.old.v1\n${text}`);
  assert.equal(new TextDecoder().decode(transitionSignatureBytes(p, 'new')), `n170.verify.key-transition.new.v1\n${text}`);
  assert.equal(await sha256Hex(transitionPayloadBytes(p)), f.completion.certificate.sha256);
});

test('root profile, full-id checkpoint and legacy fingerprint anchor exactly the old final head', async () => {
  const f = await first();
  for (const options of [{ anchorProfile: f.old.profile }, { anchorCheckpoint: { profile_id: f.old.profile.profile_id, ...checkpointOf(f.old.profile) } }, { anchorCheckpoint: publishedFingerprint(f.old.profile) }]) {
    const checked = await inspectContinuityPackage(f.package, options);
    assert.equal(checked.anchor_status, 'matched'); assert.equal(checked.root_key_anchor_status, 'matched');
    assert.equal(checked.perEdge[0].history_anchor, 'exact'); assert.equal(checked.perEdge[0].key_anchor, 'direct');
  }
});

test('legacy fingerprint case and surrounding whitespace normalize identically to the old checker', async () => {
  const f = await first();
  const uppercase = ` \n${publishedFingerprint(f.old.profile).toUpperCase()}\r\n `;
  const legacy = await inspectProfile(JSON.stringify(f.old.profile), { publishedFingerprints: uppercase });
  assert.equal(legacy.checks.checkpoint.checked, true);
  const continuity = await inspectContinuityPackage(f.package, { anchorCheckpoint: uppercase });
  assert.equal(continuity.anchor_status, 'matched');
  assert.equal(continuity.perEdge[0].history_anchor, 'exact');
  assert.deepEqual(continuity.anchor.details[0].checkpoint, checkpointOf(f.old.profile));
});

test('repeated transitions bind prior digest and preserve all segments without merging returns', async () => {
  const f = await second(); const checked = await inspectContinuityPackage(f.repeated);
  assert.equal(checked.profiles.length, 3); assert.equal(checked.transitions.length, 2);
  assert.equal(checked.transitions[1].payload.previous_transition_sha256, checked.transitions[0].sha256);
  assert.equal(checked.profiles[0].stamps[0].payload.metrics.total_return_twr_e8, -10000000);
  assert.equal(checked.profiles[1].stamps[0].payload.metrics.total_return_twr_e8, 10000000);
  assert.equal(checked.merged_metrics, false);
});

test('root-only repeated-chain anchor remains partial despite inherited signing-key authority', async () => {
  const f = await second(); const checked = await inspectContinuityPackage(f.repeated, { anchorProfile: f.old.profile });
  assert.equal(checked.anchor_status, 'partial'); assert.equal(checked.root_key_anchor_status, 'matched');
  assert.deepEqual(checked.perEdge.map(edge => [edge.key_anchor, edge.history_anchor]), [['direct', 'exact'], ['inherited', 'not_retained']]);
});

test('a previously retained package anchors a new outgoing head only when it already retained that exact head', async () => {
  const f = await second();
  const exact = await inspectContinuityPackage(f.repeated, { previous: f.prior }); assert.equal(exact.anchor_status, 'matched');
  const partial = await inspectContinuityPackage(f.repeated, { previous: f.package }); assert.equal(partial.anchor_status, 'partial');
  assert.equal(partial.perEdge[1].history_anchor, 'not_retained');
  const later = await extend(f.prior, f.next.signer, '2026-01-03', '2026-01-04'); const key3 = await key();
  const p = (await approveTransitionRequest(await createTransitionRequest(later, key3.profile, key3.signer), f.next.signer)).package;
  const prefix = await inspectContinuityPackage(p, { previous: f.prior }); assert.equal(prefix.anchor_status, 'partial'); assert.equal(prefix.perEdge[1].history_anchor, 'prefix_only');
});

test('matching earlier root checkpoint stays partial; retained longer root conflicts', async () => {
  const f = await first(); const oldPrefix = f.old.profile;
  const oldLong = await appendPerformanceStamp(oldPrefix, csv('2026-01-02', '2026-01-03'), 252, f.old.signer);
  const pack = (await approveTransitionRequest(await createTransitionRequest(oldLong, f.next.profile, f.next.signer), f.old.signer)).package;
  assert.equal((await inspectContinuityPackage(pack, { anchorProfile: oldPrefix })).anchor_status, 'partial');
  assert.equal((await inspectContinuityPackage(pack, { anchorCheckpoint: publishedFingerprint(oldPrefix) })).perEdge[0].history_anchor, 'prefix_only');
  assert.equal((await inspectContinuityPackage(f.package, { anchorProfile: oldLong })).anchor_status, 'conflict');
});

test('expected key code is root-scoped and does not independently retain history', async () => {
  const f = await first(); const checked = await inspectContinuityPackage(f.package, { expectedKeyCode: formatKeyCode(f.old.profile.profile_id) });
  assert.equal(checked.anchor_status, 'partial'); assert.equal(checked.root_key_anchor_status, 'matched');
  const wrong = await inspectContinuityPackage(f.package, { expectedKeyCode: formatKeyCode(f.next.profile.profile_id) });
  assert.equal(wrong.anchor_status, 'conflict'); assert.equal(wrong.transition_signatures_valid, true);
});

test('early-period correction checkpoint does not move the outgoing effective boundary backwards', async () => {
  const f = await first(); let old = await appendPerformanceStamp(f.old.profile, csv('2026-01-02', '2026-01-03'), 252, f.old.signer);
  old = await appendCorrectionStamp(old, 1, csv('2026-01-01', '2026-01-02', '95'), 252, f.old.signer, { reason: 'Synthetic correction' });
  assert.equal(checkpointOf(old).end, '2026-01-02'); assert.equal(effectiveEnd(old), '2026-01-03');
  const certificate = (await approveTransitionRequest(await createTransitionRequest(old, f.next.profile, f.next.signer), f.old.signer)).certificate;
  const overlap = await appendPerformanceStamp(f.next.profile, csv('2026-01-02', '2026-01-04'), 252, f.next.signer);
  await assert.rejects(buildContinuityPackage(old, overlap, certificate), /effective performance end/);
  const supported = await appendPerformanceStamp(f.next.profile, csv('2026-01-04', '2026-01-05'), 252, f.next.signer);
  const inspected = await inspectContinuityPackage(await buildContinuityPackage(old, supported, certificate));
  assert.deepEqual(inspected.perEdge[0].gap, { edge: 0, start: '2026-01-03', end: '2026-01-04', kind: 'between_keys' });
});

test('destination corrections stay valid inside their own unchanged segment', async () => {
  const f = await first(); const pack = await extend(f.package, f.next.signer);
  pack.profiles[1] = await appendCorrectionStamp(pack.profiles[1], 1, csv('2026-01-02', '2026-01-03', '95'), 252, f.next.signer, { reason: 'Synthetic revised valuation' });
  const checked = await inspectContinuityPackage(pack); assert.equal(checked.profileInspections[1].summary.correction_count, 1);
  assert.equal((await compareContinuity(f.package, pack)).status, 'extended');
});

test('equivalent high/low-S certificate and record signatures retain identity and comparison', async () => {
  const f = await first(); const other = clone(f.package);
  other.transitions[0].old_signature = equivalentSignature(other.transitions[0].old_signature);
  other.transitions[0].new_signature = equivalentSignature(other.transitions[0].new_signature);
  other.profiles[0].stamps[0].signature = equivalentSignature(other.profiles[0].stamps[0].signature);
  assert.equal((await inspectContinuityPackage(other)).transitions[0].sha256, f.package.transitions[0].sha256);
  assert.equal((await compareContinuity(f.package, other)).status, 'identical');
});

test('same-key terminal extension compares as extension; truncation and fork remain conflicts', async () => {
  const f = await first(); const a = await extend(f.package, f.next.signer); const b = await extend(f.package, f.next.signer, '2026-01-02', '2026-01-03', '85');
  assert.equal((await compareContinuity(f.package, a)).status, 'extended');
  assert.equal((await compareContinuity(a, f.package)).status, 'conflict');
  assert.equal((await compareContinuity(a, b)).status, 'conflict');
});

test('competing destinations and different retirement checkpoints are explicit conflicts', async () => {
  const f = await first(); const alternative = await key();
  const other = (await approveTransitionRequest(await createTransitionRequest(f.old.profile, alternative.profile, alternative.signer), f.old.signer)).package;
  const checked = await inspectContinuityPackage(other, { previous: f.package }); assert.equal(checked.anchor_status, 'conflict'); assert.ok(checked.conflicts.some(c => c.code === 'competing_transition'));
  const later = await appendPerformanceStamp(f.old.profile, csv('2026-01-02', '2026-01-03'), 252, f.old.signer);
  const otherHead = (await approveTransitionRequest(await createTransitionRequest(later, f.next.profile, f.next.signer), f.old.signer)).package;
  assert.equal((await compareContinuity(f.package, otherHead)).status, 'conflict');
});

test('four repeated transitions succeed; fifth and key loops are rejected', async () => {
  const root = await key(); root.profile = await appendPerformanceStamp(root.profile, csv(), 252, root.signer);
  let history = root.profile; let signer = root.signer;
  for (let edge = 0; edge < 4; edge += 1) {
    const dest = await key(); history = (await approveTransitionRequest(await createTransitionRequest(history, dest.profile, dest.signer), signer)).package; signer = dest.signer;
    const day = edge + 2; history = await extend(history, signer, `2026-01-0${day}`, `2026-01-0${day + 1}`);
  }
  assert.equal((await inspectContinuityPackage(history)).transitions.length, 4);
  const fifth = await key(); await assert.rejects(createTransitionRequest(history, fifth.profile, fifth.signer), /four transitions/);
  const f = await second(); const earlierEmpty = { ...f.old.profile, stamps: [] };
  await assert.rejects(createTransitionRequest(f.prior, earlierEmpty, f.old.signer), /earlier key/);
});

test('empty outgoing profile, nonempty destination and different alias cannot request transfer', async () => {
  const old = await key(), next = await key(); await assert.rejects(createTransitionRequest(old.profile, next.profile, next.signer), /at least one/);
  old.profile = await appendPerformanceStamp(old.profile, csv(), 252, old.signer);
  const nonempty = await appendPerformanceStamp(next.profile, csv(), 252, next.signer); await assert.rejects(createTransitionRequest(old.profile, nonempty, next.signer), /empty v4/);
  const renamed = await key('Different synthetic alias'); await assert.rejects(createTransitionRequest(old.profile, renamed.profile, renamed.signer), /same valid public alias/);
  await assert.rejects(createTransitionRequest(old.profile, { ...old.profile, stamps: [] }, old.signer), /earlier key/);
});

test('missing and swapped role signatures are rejected before approval or completion', async () => {
  const f = await first(); const missing = clone(f.package); delete missing.transitions[0].old_signature;
  await assert.rejects(inspectContinuityPackage(missing), /missing or unsupported/);
  const swapped = clone(f.package); swapped.transitions[0].new_signature = swapped.transitions[0].old_signature;
  await assert.rejects(inspectContinuityPackage(swapped), /signature is invalid/);
  const badRequest = clone(f.request); badRequest.new_signature = f.completion.certificate.old_signature;
  await assert.rejects(inspectTransitionRequest(badRequest), /signature is invalid/);
  await assert.rejects(approveTransitionRequest(f.request, f.next.signer), /outgoing signing key/);
});

test('payload, old head, history link and profile tampering cannot be laundered through envelopes', async () => {
  const f = await second();
  for (const mutate of [p => { p.transitions[0].payload.challenge = encodeBase64Url(new Uint8Array(32)); }, p => { p.transitions[0].payload.old_checkpoint.sha256 = '0'.repeat(64); }, p => { p.transitions[1].payload.previous_transition_sha256 = null; }, p => { p.profiles[0].stamps[0].payload.relative_returns[0].return_e8 = 0; }]) {
    const p = clone(f.repeated); mutate(p); await assert.rejects(inspectContinuityPackage(p));
  }
  const swapped = clone(f.repeated); [swapped.profiles[0], swapped.profiles[1]] = [swapped.profiles[1], swapped.profiles[0]]; await assert.rejects(inspectContinuityPackage(swapped));
  const truncated = clone(f.request); truncated.history.stamps = []; await assert.rejects(inspectTransitionRequest(truncated), /complete outgoing/);
});

test('request schema is never accepted as completed evidence, unknown schema never dispatches', async () => {
  const f = await first(); await assert.rejects(inspectContinuityPackage(f.request));
  await assert.rejects(inspectContinuityHistory({ schema_version: 'n170.verify.future.v99' }), /unsupported/);
  const p = clone(f.package); p.provider_authenticated = true; await assert.rejects(inspectContinuityPackage(p), /unsupported fields/);
  assert.equal((await inspectContinuityHistory(f.old.profile)).profiles.length, 1);
});

test('duplicate escaped fields and nonplain numeric spellings are rejected across nested history', async () => {
  const f = await first(); const text = JSON.stringify(f.request);
  await assert.rejects(inspectTransitionRequest(text.replace('"purpose":"device_change"', '"purpose":"device_change","purpo\\u0073e":"device_change"')), /repeats a field/);
  await assert.rejects(inspectTransitionRequest(text.replace('"sequence":1', '"sequence":1.0')), /plain safe integers/);
  await assert.rejects(inspectTransitionRequest(text.replace('"sequence":1', '"sequence":1e0')), /plain safe integers/);
  assert.throws(() => parseContinuityJSON('{"n":-0}'), /plain safe integers/);
  assert.throws(() => parseContinuityJSON('{"n":9007199254740993}'), /plain safe integers/);
});

test('challenge encoding, nesting and total limits fail closed', async () => {
  const f = await first(); await assert.rejects(createTransitionRequest(f.old.profile, f.next.profile, f.next.signer, `${challenge}=`), /32 bytes/);
  assert.throws(() => parseContinuityJSON(`${'['.repeat(33)}0${']'.repeat(33)}`), /nesting limit/);
  assert.throws(() => parseContinuityJSON(' '.repeat(MAX_CONTINUITY_CHARACTERS + 1)), /at most/);
  await assert.rejects(inspectTransitionRequest(' '.repeat(MAX_REQUEST_CHARACTERS + 1)), /at most/);
});

test('invalid, wrong-key and conflicting independent anchor options remain explicit', async () => {
  const f = await first(); await assert.rejects(inspectContinuityPackage(f.package, { anchorProfile: f.old.profile, anchorCheckpoint: publishedFingerprint(f.old.profile) }), /not both/);
  const wrong = { profile_id: f.next.profile.profile_id, ...checkpointOf(f.old.profile) };
  assert.equal((await inspectContinuityPackage(f.package, { anchorCheckpoint: wrong })).anchor_status, 'conflict');
  await assert.rejects(inspectContinuityPackage(f.package, { anchorCheckpoint: { ...wrong, source_authenticated: true } }), /unsupported fields/);
  await assert.rejects(inspectContinuityPackage(f.package, { expectedKeyCode: 'not a code' }), /invalid format/);
});

test('legacy v3 signed loss root transitions to v4 without modifying its record bytes', async () => {
  const old = await key(), next = await key(); const modern = await appendPerformanceStamp(old.profile, csv(), 252, old.signer);
  const p = { ...modern.stamps[0].payload, schema_version: 'n170.verify.performance-stamp.v3', calculation_version: '1.0.0' };
  delete p.serialization_version; delete p.event_type; delete p.correction; delete p.provenance;
  p.metrics = calculateRecordMetrics(p.relative_returns.map(row => row.return_e8), p.periods_per_year);
  const payload = canonicalPayload(p); const bytes = new TextEncoder().encode(JSON.stringify(payload));
  const signedBytes = new TextEncoder().encode(`n170.verify.stamp-signature.v3\n${JSON.stringify(payload)}`);
  const legacy = { ...old.profile, schema_version: 'n170.verify.track-record.v3', stamps: [{ payload, sha256: await sha256Hex(bytes), signature: await old.signer.sign(signedBytes) }] };
  await inspectProfile(JSON.stringify(legacy));
  const pack = (await approveTransitionRequest(await createTransitionRequest(legacy, next.profile, next.signer), old.signer)).package;
  assert.deepEqual(pack.profiles[0], legacy); assert.equal(pack.profiles[1].schema_version, 'n170.verify.track-record.v4');
  assert.equal((await inspectContinuityPackage(pack, { anchorProfile: legacy })).anchor_status, 'matched');
});
