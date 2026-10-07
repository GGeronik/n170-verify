// Original synthetic controls authored independently with Node's crypto API.
// This test file never uses browser code to construct a key, record or certificate.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { verifyEvidence } from '../scripts/verify-record.mjs';
import { verifyContinuity, compareContinuity } from '../scripts/verify-continuity.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const json = value => JSON.stringify(value);
const copy = value => JSON.parse(json(value));
const alias = 'Original synthetic continuity controls';
const keyCode = profile => profile.profile_id.slice(0, 20).match(/.{4}/g).join('-');
const lastCheckpoint = profile => { const stamp = profile.stamps.at(-1); return { sequence: stamp.payload.sequence, end: stamp.payload.period.end, sha256: stamp.sha256 }; };
const fullCheckpoint = profile => ({ profile_id: profile.profile_id, ...lastCheckpoint(profile) });
const fingerprint = profile => { const point = lastCheckpoint(profile); return `n170-verify key=${keyCode(profile)} record=${point.sequence} end=${point.end} sha256=${point.sha256}`; };

function owner(version = 4) {
  const keys = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = keys.publicKey.export({ format: 'jwk' });
  const publicBytes = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
  return { privateKey: keys.privateKey, profile: { schema_version: `n170.verify.track-record.v${version}`, profile_id: hash(Buffer.concat([Buffer.from('n170.verify.profile-key.v3\n'), publicBytes])), display_name: alias, public_key: publicBytes.toString('base64url'), stamps: [] } };
}

function signed(privateKey, domain, bytes) {
  return sign('sha256', Buffer.concat([Buffer.from(domain), bytes]), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
}

function append(who, profile, start, end, units, { version = 4, target = null } = {}) {
  // Every original control has a single return interval. Expected metrics are
  // therefore the literal return, no annualized volatility, and min(0, return).
  const sequence = profile.stamps.length + 1;
  const payload = {
    schema_version: `n170.verify.performance-stamp.v${version}`, calculation_version: version === 4 ? '2.0.0' : '1.0.0',
    sequence, profile_id: profile.profile_id, display_name: profile.display_name, previous_sha256: profile.stamps.at(-1)?.sha256 ?? null,
    source_kind: 'self_reported', provider_authenticated: false, independent_timestamp: false,
    period: { start, end }, periods_per_year: 365, relative_returns: [{ start, end, return_e8: units }],
    coverage: { nav_observations: 2, return_observations: 1, external_cash_flow_count: 0 },
    metrics: { total_return_twr_e8: units, annualized_volatility_e8: null, max_drawdown_e8: Math.min(0, units) },
  };
  if (version === 4) Object.assign(payload, {
    serialization_version: '1.0.0', event_type: target === null ? 'performance' : 'correction',
    correction: target === null ? null : { target_sequence: target, target_sha256: profile.stamps[target - 1].sha256, reason: 'Original synthetic correction control' },
    provenance: { kind: 'manual', format: 'Original synthetic test', original_sha256: null, source_sha256: null, normalized_sha256: null,
      mapping: [], account_scope: 'Original synthetic account', currency: 'USD', completeness: 'not_established', corrections: [], reviewed: true },
  });
  const bytes = Buffer.from(json(payload));
  return { ...copy(profile), schema_version: `n170.verify.track-record.v${version}`, stamps: [...copy(profile.stamps), {
    payload, sha256: hash(bytes), signature: signed(who.privateKey, `n170.verify.stamp-signature.v${version}\n`, bytes),
  }] };
}

function certificate(oldOwner, oldProfile, newOwner, newProfile, previous = null, overrides = {}) {
  const payload = {
    schema_version: 'n170.verify.key-transition.v1', serialization_version: '1.0.0', purpose: 'device_change',
    old_profile_id: oldProfile.profile_id, old_public_key: oldProfile.public_key, old_display_name: oldProfile.display_name,
    old_checkpoint: lastCheckpoint(oldProfile), new_profile_id: newProfile.profile_id, new_public_key: newProfile.public_key,
    new_display_name: newProfile.display_name, challenge: randomBytes(32).toString('base64url'), previous_transition_sha256: previous,
    ...overrides,
  };
  const bytes = Buffer.from(json(payload));
  return { payload, sha256: hash(bytes), old_signature: signed(oldOwner.privateKey, 'n170.verify.key-transition.old.v1\n', bytes), new_signature: signed(newOwner.privateKey, 'n170.verify.key-transition.new.v1\n', bytes) };
}

function packet(profiles, transitions) { return { schema_version: 'n170.verify.continuity-package.v1', profiles, transitions }; }

const rootOwner = owner(), middleOwner = owner(), currentOwner = owner();
const rootFirst = append(rootOwner, rootOwner.profile, '2026-01-01', '2026-01-02', -10000000);
const rootSecond = append(rootOwner, rootFirst, '2026-01-02', '2026-01-03', 20000000);
// Last event ends Jan 2; the effective latest period ends Jan 3.
const root = append(rootOwner, rootSecond, '2026-01-01', '2026-01-02', -5000000, { target: 1 });
const middleFirst = append(middleOwner, middleOwner.profile, '2026-01-03', '2026-01-04', -2000000);
const middle = append(middleOwner, middleFirst, '2026-01-04', '2026-01-05', 1000000);
const current = append(currentOwner, currentOwner.profile, '2026-01-05', '2026-01-06', -3000000);
const firstCertificate = certificate(rootOwner, root, middleOwner, middle);
const secondCertificate = certificate(middleOwner, middle, currentOwner, current, firstCertificate.sha256);
const firstPackage = packet([root, middle], [firstCertificate]);
const prefixPackage = packet([root, middleFirst], [firstCertificate]);
const emptyDestination = packet([root, middleOwner.profile], [firstCertificate]);
const secondPackage = packet([root, middle, current], [firstCertificate, secondCertificate]);

if (process.env.N170_CONTINUITY_FIXTURE_DIR) {
  const directory = resolve(process.env.N170_CONTINUITY_FIXTURE_DIR);
  mkdirSync(directory, { recursive: true });
  const evidence = { synthetic: true, authoring_method: 'Independent Node crypto; no browser producer', root, root_prefix: rootFirst, one_edge: firstPackage, one_edge_prefix: prefixPackage, two_edges: secondPackage };
  writeFileSync(join(directory, 'independent-synthetic-fixtures.json'), JSON.stringify(evidence, null, 2) + '\n');
}

test('independently signed original profiles pass the unchanged verifier and preserve loss/correction numbers', () => {
  for (const profile of [root, middle, current]) assert.equal(verifyEvidence(json(profile)).signatures_valid, true);
  assert.equal(root.stamps[0].payload.metrics.total_return_twr_e8, -10000000);
  assert.equal(root.stamps[2].payload.metrics.total_return_twr_e8, -5000000);
  assert.equal(root.stamps.at(-1).payload.period.end, '2026-01-02');
});

test('valid one-edge evidence without an external reference remains unanchored', () => {
  const result = verifyContinuity(json(firstPackage));
  assert.equal(result.transition_signatures_valid, true);
  assert.equal(result.anchor_status, 'not_supplied');
  assert.equal(result.exit_code, 2);
  assert.equal(result.perEdge[0].history_anchor, 'not_retained');
  assert.equal(result.recipient_acceptance, 'not_determined');
  assert.equal(result.source_authenticated, false);
});

test('exact independently supplied root profile and checkpoint anchor a single edge', () => {
  for (const options of [ { anchorProfile: json(root) }, { anchorCheckpoint: json(fullCheckpoint(root)) }, { anchorCheckpoint: fingerprint(root) } ]) {
    const result = verifyContinuity(json(firstPackage), options);
    assert.equal(result.anchor_status, 'matched'); assert.equal(result.exit_code, 0);
    assert.equal(result.perEdge[0].history_anchor, 'exact');
    assert.equal(result.perEdge[0].unretained_old_events, 0);
  }
});

test('matching root prefix anchors only retained events, including when supplied as a checkpoint', () => {
  for (const options of [{ anchorProfile: json(rootFirst) }, { anchorCheckpoint: json(fullCheckpoint(rootFirst)) }, { anchorCheckpoint: fingerprint(rootFirst) }]) {
    const result = verifyContinuity(json(firstPackage), options);
    assert.equal(result.anchor_status, 'partial'); assert.equal(result.exit_code, 2);
    assert.equal(result.perEdge[0].history_anchor, 'prefix_only');
    assert.equal(result.perEdge[0].retained_sequence, 1);
    assert.equal(result.perEdge[0].unretained_old_events, 2);
  }
});

test('an empty retained root profile anchors a key but none of its later events', () => {
  const result = verifyContinuity(json(firstPackage), { anchorProfile: json(rootOwner.profile) });
  assert.equal(result.anchor_status, 'partial');
  assert.equal(result.perEdge[0].retained_sequence, 0);
  assert.equal(result.perEdge[0].history_anchor, 'not_retained');
  assert.equal(result.perEdge[0].unretained_old_events, 3);
});

test('root-only anchoring never silently anchors a later outgoing history', () => {
  const result = verifyContinuity(json(secondPackage), { anchorProfile: json(root) });
  assert.equal(result.root_key_anchor_status, 'matched');
  assert.equal(result.anchor_status, 'partial'); assert.equal(result.exit_code, 2);
  assert.deepEqual(result.perEdge.map(edge => edge.key_anchor), ['direct', 'inherited']);
  assert.deepEqual(result.perEdge.map(edge => edge.history_anchor), ['exact', 'not_retained']);
});

test('retained one-edge package after middle records exactly anchors the second outgoing head', () => {
  const result = verifyContinuity(json(secondPackage), { previous: json(firstPackage) });
  assert.equal(result.anchor_status, 'matched'); assert.equal(result.exit_code, 0);
  assert.deepEqual(result.perEdge.map(edge => edge.history_anchor), ['exact', 'exact']);
  assert.equal(result.comparison.status, 'extended');
});

test('a retained prefix or empty destination does not independently anchor later middle events', () => {
  for (const prior of [prefixPackage, emptyDestination]) {
    const result = verifyContinuity(json(secondPackage), { previous: json(prior) });
    assert.equal(result.anchor_status, 'partial'); assert.equal(result.exit_code, 2);
    assert.equal(result.perEdge[0].history_anchor, 'exact');
    assert.equal(result.perEdge[1].history_anchor, prior.profiles[1].stamps.length ? 'prefix_only' : 'not_retained');
    assert.equal(result.perEdge[1].retained_sequence, prior.profiles[1].stamps.length);
  }
});

test('identical retained chain and current-key extensions preserve all exact outgoing anchors', () => {
  const extended = append(currentOwner, current, '2026-01-06', '2026-01-07', 2000000);
  for (const profile of [current, extended]) {
    const result = verifyContinuity(json(packet([root, middle, profile], [firstCertificate, secondCertificate])), { previous: json(secondPackage) });
    assert.equal(result.anchor_status, 'matched'); assert.equal(result.exit_code, 0);
    assert.ok(result.perEdge.every(edge => edge.history_anchor === 'exact'));
  }
});

test('a retained previous single root profile has explicit prefix or exact semantics', () => {
  assert.equal(verifyContinuity(json(firstPackage), { previous: json(root) }).anchor_status, 'matched');
  assert.equal(verifyContinuity(json(firstPackage), { previous: json(rootFirst) }).anchor_status, 'partial');
  assert.equal(verifyContinuity(json(secondPackage), { previous: json(root) }).anchor_status, 'partial');
});

test('a later destination correction is local and never merges segment metrics', () => {
  const corrected = append(currentOwner, current, '2026-01-05', '2026-01-06', -4000000, { target: 1 });
  const result = verifyContinuity(json(packet([root, middle, corrected], [firstCertificate, secondCertificate])), { previous: json(secondPackage) });
  assert.equal(result.anchor_status, 'matched');
  assert.equal(result.segments.length, 3);
  assert.equal(Object.hasOwn(result, 'metrics'), false);
  assert.equal(result.package.profiles[2].stamps[1].payload.metrics.total_return_twr_e8, -4000000);
});

test('empty final destination permits continuity but establishes no new performance', () => {
  const result = verifyContinuity(json(emptyDestination), { anchorProfile: json(root) });
  assert.equal(result.exit_code, 0); assert.equal(result.segments.at(-1).records, 0);
  assert.equal(result.perEdge[0].new_first_start, null); assert.equal(result.perEdge[0].gap_days, null);
});

test('effective performance boundary, not older final correction end, governs the next segment', () => {
  const good = verifyContinuity(json(firstPackage));
  assert.equal(good.perEdge[0].old_checkpoint.end, '2026-01-02');
  assert.equal(good.perEdge[0].effective_old_end, '2026-01-03');
  assert.equal(good.perEdge[0].gap_days, 0);
  const overlapping = append(middleOwner, middleOwner.profile, '2026-01-02', '2026-01-03', -1000000);
  assert.throws(() => verifyContinuity(json(packet([root, overlapping], [firstCertificate]))), /overlaps/);
  const delayed = append(middleOwner, middleOwner.profile, '2026-01-05', '2026-01-06', 1000000);
  assert.equal(verifyContinuity(json(packet([root, delayed], [firstCertificate]))).perEdge[0].gap_days, 2);
});

test('legacy v3 loss-containing root remains byte-preserved in v3 to v4 continuity', () => {
  const legacyOwner = owner(3);
  const legacy = append(legacyOwner, legacyOwner.profile, '2025-12-30', '2025-12-31', -10000000, { version: 3 });
  const cert = certificate(legacyOwner, legacy, middleOwner, middle);
  const result = verifyContinuity(json(packet([legacy, middle], [cert])), { anchorProfile: json(legacy) });
  assert.equal(result.anchor_status, 'matched');
  assert.equal(json(result.package.profiles[0]), json(legacy));
  assert.equal(result.package.profiles[0].stamps[0].payload.calculation_version, '1.0.0');
});

test('mixed legacy-v3 and current-v4 event history remains compatible without rewriting old events', () => {
  const mixedOwner = owner(3);
  const legacy = append(mixedOwner, mixedOwner.profile, '2025-12-29', '2025-12-30', -10000000, { version: 3 });
  const mixed = append(mixedOwner, legacy, '2025-12-30', '2025-12-31', 10000000);
  const cert = certificate(mixedOwner, mixed, middleOwner, middle);
  const result = verifyContinuity(json(packet([mixed, middle], [cert])), { anchorProfile: json(mixed) });
  assert.equal(result.exit_code, 0);
  assert.equal(json(result.package.profiles[0].stamps[0]), json(legacy.stamps[0]));
});

test('every destination must be v4 even when it has no performance events', () => {
  const destination = owner(3);
  const cert = certificate(rootOwner, root, destination, destination.profile);
  assert.throws(() => verifyContinuity(json(packet([root, destination.profile], [cert]))), /destination.*v4/i);
});

test('four transitions are supported with per-edge retention; a fifth is rejected', async () => {
  const fourthOwner = owner(), fifthOwner = owner(), sixthOwner = owner();
  const fourth = append(fourthOwner, fourthOwner.profile, '2026-01-06', '2026-01-07', 1000000);
  const thirdCert = certificate(currentOwner, current, fourthOwner, fourth, secondCertificate.sha256);
  const fourthCert = certificate(fourthOwner, fourth, fifthOwner, fifthOwner.profile, thirdCert.sha256);
  const prior = packet([root, middle, current, fourth], [firstCertificate, secondCertificate, thirdCert]);
  const four = packet([...prior.profiles, fifthOwner.profile], [...prior.transitions, fourthCert]);
  const checked = verifyContinuity(json(four), { previous: json(prior) });
  assert.equal(checked.exit_code, 0); assert.equal(checked.perEdge.length, 4);
  assert.ok(checked.perEdge.every(edge => edge.history_anchor === 'exact'));
  const partial = verifyContinuity(json(four), { previous: json(secondPackage) });
  assert.equal(partial.anchor_status, 'partial');
  assert.deepEqual(partial.perEdge.map(edge => edge.history_anchor), ['exact', 'exact', 'exact', 'not_retained']);
  const fifth = append(fifthOwner, fifthOwner.profile, '2026-01-07', '2026-01-08', 1000000);
  const fifthCert = certificate(fifthOwner, fifth, sixthOwner, sixthOwner.profile, fourthCert.sha256);
  const five = packet([root, middle, current, fourth, fifth, sixthOwner.profile], [...four.transitions, fifthCert]);
  assert.throws(() => verifyContinuity(json(five)), /five|four/);
  const { inspectContinuityPackage } = await import('../src/keyContinuity.js');
  assert.equal((await inspectContinuityPackage(json(four), { previous: json(prior) })).anchor_status, 'matched');
  assert.equal((await inspectContinuityPackage(json(four), { previous: json(secondPackage) })).anchor_status, 'partial');
  await assert.rejects(inspectContinuityPackage(json(five)), /four|five/);
});

test('old expected key addresses the root only, never the current new key', () => {
  const matched = verifyContinuity(json(firstPackage), { expectedKeyCode: keyCode(root) });
  assert.equal(matched.root_key_anchor_status, 'matched'); assert.equal(matched.anchor_status, 'partial');
  const mismatch = verifyContinuity(json(firstPackage), { expectedKeyCode: keyCode(middle) });
  assert.equal(mismatch.anchor_status, 'conflict'); assert.equal(mismatch.exit_code, 2);
  assert.ok(mismatch.conflicts.some(item => item.code === 'expected_root_key_mismatch'));
});

test('wrong-key checkpoints, newer retained heads and signed forks are conflicts', () => {
  const newer = append(rootOwner, root, '2026-01-03', '2026-01-04', 1000000);
  const fork = append(rootOwner, rootFirst, '2026-01-02', '2026-01-03', 1000000);
  for (const options of [ { anchorProfile: json(newer) }, { anchorProfile: json(fork) }, { anchorProfile: json(middle) }, { anchorCheckpoint: json(fullCheckpoint(middle)) } ]) {
    const result = verifyContinuity(json(firstPackage), options);
    assert.equal(result.anchor_status, 'conflict'); assert.equal(result.exit_code, 2);
  }
});

test('multiple conflicting reference inputs cannot be overridden by one matching reference', () => {
  const result = verifyContinuity(json(secondPackage), { previous: json(firstPackage), anchorProfile: json(middle) });
  assert.equal(result.anchor_status, 'conflict'); assert.equal(result.exit_code, 2);
});

test('competing destinations or a substituted certificate remain visible conflicts', () => {
  const rival = owner();
  const rivalProfile = append(rival, rival.profile, '2026-01-03', '2026-01-04', -1000000);
  const destinationConflict = packet([root, rivalProfile], [certificate(rootOwner, root, rival, rivalProfile)]);
  const certificateConflict = packet([root, middle], [certificate(rootOwner, root, middleOwner, middle)]);
  for (const currentPacket of [destinationConflict, certificateConflict]) {
    assert.equal(compareContinuity(json(firstPackage), json(currentPacket)).status, 'conflict');
    const result = verifyContinuity(json(currentPacket), { previous: json(firstPackage) });
    assert.equal(result.anchor_status, 'conflict'); assert.equal(result.exit_code, 2);
  }
});

test('competing transitions from different old checkpoints are conflicts even when both are signed', () => {
  const priorHeadCertificate = certificate(rootOwner, rootSecond, middleOwner, middle);
  const earlier = packet([rootSecond, middle], [priorHeadCertificate]);
  assert.equal(verifyContinuity(json(earlier)).transition_signatures_valid, true);
  const result = verifyContinuity(json(firstPackage), { previous: json(earlier) });
  assert.equal(result.anchor_status, 'conflict');
  assert.ok(result.conflicts.some(item => item.code === 'competing_transition'));
});

test('new-key truncation, fork and entire-chain truncation conflict with retained evidence', () => {
  const forkedCurrent = append(currentOwner, currentOwner.profile, '2026-01-05', '2026-01-06', -5000000);
  for (const bad of [
    packet([root, middle, currentOwner.profile], [firstCertificate, secondCertificate]),
    packet([root, middle, forkedCurrent], [firstCertificate, secondCertificate]), firstPackage,
  ]) assert.equal(verifyContinuity(json(bad), { previous: json(secondPackage) }).anchor_status, 'conflict');
});

test('ECDSA high/low-S equivalents retain payload identity and comparison result', () => {
  const order = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
  const equivalent = copy(secondPackage);
  for (const cert of equivalent.transitions) for (const field of ['old_signature', 'new_signature']) {
    const bytes = Buffer.from(cert[field], 'base64url');
    const other = order - BigInt(`0x${bytes.subarray(32).toString('hex')}`);
    Buffer.from(other.toString(16).padStart(64, '0'), 'hex').copy(bytes, 32);
    cert[field] = bytes.toString('base64url');
  }
  assert.equal(compareContinuity(json(secondPackage), json(equivalent)).status, 'identical');
  const result = verifyContinuity(json(equivalent), { previous: json(secondPackage) });
  assert.equal(result.anchor_status, 'matched');
  assert.deepEqual(result.perEdge.map(edge => edge.certificate_sha256), secondPackage.transitions.map(cert => cert.sha256));
});

test('JSON field order is irrelevant; canonical payload order is fixed', () => {
  const reordered = copy(firstPackage);
  reordered.transitions[0].payload = Object.fromEntries(Object.entries(reordered.transitions[0].payload).reverse());
  assert.equal(verifyContinuity(json(reordered), { anchorProfile: json(root) }).exit_code, 0);
});

for (const [name, mutate] of [
  ['missing signature', p => { delete p.transitions[0].old_signature; }],
  ['missing new signature', p => { delete p.transitions[0].new_signature; }],
  ['wrong-role signature', p => { p.transitions[0].old_signature = p.transitions[0].new_signature; }],
  ['wrong new-role signature', p => { p.transitions[0].new_signature = p.transitions[0].old_signature; }],
  ['altered challenge', p => { p.transitions[0].payload.challenge = randomBytes(32).toString('base64url'); }],
  ['noncanonical challenge', p => { p.transitions[0].payload.challenge += '='; }],
  ['altered old key', p => { p.transitions[0].payload.old_public_key = middle.public_key; }],
  ['altered alias', p => { p.transitions[0].payload.new_display_name = 'Different alias'; }],
  ['altered old checkpoint', p => { p.transitions[0].payload.old_checkpoint.sha256 = 'a'.repeat(64); }],
  ['unsupported provenance claim', p => { p.transitions[0].payload.provider_authenticated = true; }],
  ['unsupported independent time', p => { p.transitions[0].payload.timestamp = '2026-01-03T00:00:00Z'; }],
  ['truncated sealed old profile', p => { p.profiles[0] = rootFirst; }],
  ['swapped profiles', p => { p.profiles.reverse(); }],
  ['duplicate keys loop', p => { p.profiles[1] = p.profiles[0]; }],
  ['forged completion schema', p => { p.schema_version = 'n170.verify.key-transition-request.v1'; }],
]) {
  test(`malformed or cryptographically invalid evidence rejects: ${name}`, () => {
    const bad = copy(firstPackage); mutate(bad);
    assert.throws(() => verifyContinuity(json(bad)));
  });
}

test('a correctly signed certificate still cannot authorize a same-key transition or changed alias', () => {
  const sameKey = certificate(rootOwner, root, rootOwner, root);
  assert.throws(() => verifyContinuity(json(packet([root, root], [sameKey]))), /Duplicate|loop|Same/);
  const other = owner(); const altered = { ...other.profile, display_name: 'Different original synthetic alias' };
  const changed = certificate(rootOwner, root, other, altered);
  assert.throws(() => verifyContinuity(json(packet([root, altered], [changed]))), /Aliases|alias/);
});

test('signing with the right key but wrong domain never completes the transition', () => {
  const bad = copy(firstPackage), bytes = Buffer.from(json(bad.transitions[0].payload));
  bad.transitions[0].old_signature = signed(rootOwner.privateKey, 'n170.verify.key-transition.new.v1\n', bytes);
  assert.throws(() => verifyContinuity(json(bad)), /signature/);
});

test('later certificates must bind the exact previous payload digest', () => {
  const bad = copy(secondPackage);
  bad.transitions[1] = certificate(middleOwner, middle, currentOwner, current, 'a'.repeat(64));
  assert.throws(() => verifyContinuity(json(bad)), /Previous transition/);
  const firstBad = copy(firstPackage);
  firstBad.transitions[0] = certificate(rootOwner, root, middleOwner, middle, firstCertificate.sha256);
  assert.throws(() => verifyContinuity(json(firstBad)), /Previous transition/);
});

test('cross-segment corrections cannot target the previous key history', () => {
  const invalid = copy(currentOwner.profile);
  const forged = append(currentOwner, { ...invalid, stamps: [root.stamps[0]] }, '2026-01-01', '2026-01-02', -1000000, { target: 1 });
  forged.stamps.shift();
  assert.throws(() => verifyContinuity(json(packet([root, middle, forged], [firstCertificate, secondCertificate]))));
});

test('transition request and unsigned new-key-only request are never accepted as completion', () => {
  const request = { schema_version: 'n170.verify.key-transition-request.v1', payload: firstCertificate.payload, new_signature: firstCertificate.new_signature, history: root };
  assert.throws(() => verifyContinuity(json(request)), /fields|request|schema/);
});

test('escaped duplicate fields and non-plain integers reject before signature checking', () => {
  const text = json(firstPackage);
  const duplicate = text.replace('"challenge":', `"chall\\u0065nge":"${firstCertificate.payload.challenge}","challenge":`);
  assert.throws(() => verifyContinuity(duplicate), /Duplicate/);
  assert.throws(() => verifyContinuity(text.replace('"sequence":1', '"sequence":1e0')), /Noncanonical/);
  assert.throws(() => verifyContinuity(text.replace('"return_e8":-10000000', '"return_e8":-0')), /Noncanonical/);
  assert.throws(() => verifyContinuity(text.replace('"sequence":1', '"sequence":9007199254740992')), /unsafe/);
});

test('profile, certificate, package, nesting and transition-count limits reject', () => {
  const largeCert = copy(firstPackage); largeCert.transitions[0].padding = 'x'.repeat(8193);
  assert.throws(() => verifyContinuity(json(largeCert)), /8,192/);
  const largeProfile = copy(firstPackage); largeProfile.profiles[0].display_name = 'x'.repeat(500001);
  assert.throws(() => verifyContinuity(json(largeProfile)), /500,000/);
  assert.throws(() => verifyContinuity(json(firstPackage) + ' '.repeat(2600000)), /character limit/);
  const deep = '{"nested":'.repeat(33) + 'null' + '}'.repeat(33);
  assert.throws(() => verifyContinuity(deep), /nesting/);
  const count = copy(firstPackage); count.profiles = new Array(6).fill(root); count.transitions = new Array(5).fill(firstCertificate);
  assert.throws(() => verifyContinuity(json(count)), /five|four/);
});

test('HTML extraction is inert, bounded and rejects duplicate attachments', () => {
  const marker = '<script id="n170-evidence" type="application/json">';
  const html = `<!doctype html><script>throw new Error('must not execute')</script>${marker}${json(firstPackage)}</script>`;
  assert.equal(verifyContinuity(html, { anchorProfile: json(root) }).exit_code, 0);
  assert.throws(() => verifyContinuity(html + `${marker}{}</script>`), /ambiguous/);
  assert.throws(() => verifyContinuity(html + ' '.repeat(2000000)), /HTML/);
});

test('production continuity review HTML preserves complete evidence and dispatches retained HTML/profile references', async () => {
  const { buildContinuityReviewPackage, buildReviewPackage, buildEvidenceReviewPackage, inspectReviewPackage, extractReviewEvidence } = await import('../src/reviewPackage.js');
  const currentHTML = await buildContinuityReviewPackage(secondPackage);
  const previousHTML = await buildEvidenceReviewPackage(firstPackage);
  assert.deepEqual(JSON.parse(extractReviewEvidence(currentHTML)), secondPackage);
  assert.equal(verifyContinuity(currentHTML, { previous: previousHTML }).anchor_status, 'matched');
  assert.equal((await inspectReviewPackage(currentHTML, { previousProfile: previousHTML })).anchor_status, 'matched');
  const rootHTML = await buildReviewPackage(root);
  assert.equal((await inspectReviewPackage(previousHTML, { previousProfile: rootHTML })).anchor_status, 'matched');
  assert.equal((await inspectReviewPackage(currentHTML, { previousProfile: rootHTML })).anchor_status, 'partial');
  await assert.rejects(inspectReviewPackage(json(current), { previousProfile: previousHTML }), /omit|complete continuity|retained/);
  assert.throws(() => extractReviewEvidence(json(root) + ' '.repeat(500001)), /500,000|profile|size/);
  const extraTrust = { ...secondPackage, accepted: true };
  await assert.rejects(inspectReviewPackage(json(extraTrust)), /field|evidence|supported/i);
});

test('static continuity review explicitly discloses a delayed new-segment boundary gap', async () => {
  const { buildContinuityReviewPackage, inspectReviewPackage } = await import('../src/reviewPackage.js');
  const delayed = append(middleOwner, middleOwner.profile, '2026-01-05', '2026-01-06', 1000000);
  const withGap = packet([root, delayed], [firstCertificate]);
  const html = await buildContinuityReviewPackage(withGap);
  const checked = await inspectReviewPackage(html);
  assert.deepEqual(checked.gaps.map(gap => ({ start: gap.start, end: gap.end })), [{ start: '2026-01-03', end: '2026-01-05' }]);
  assert.match(html, /gap/i, 'The readable export must explicitly identify the gap, not rely on recipients inferring it from separate dates.');
  assert.ok(html.includes('2026-01-03')); assert.ok(html.includes('2026-01-05'));
});

test('malformed anchor objects reject and profile/checkpoint options are mutually exclusive', () => {
  assert.throws(() => verifyContinuity(json(firstPackage), { anchorProfile: json(root), anchorCheckpoint: fingerprint(root) }), /mutually exclusive/);
  assert.throws(() => verifyContinuity(json(firstPackage), { anchorCheckpoint: json({ ...fullCheckpoint(root), trusted: true }) }), /fields/);
  assert.throws(() => verifyContinuity(json(firstPackage), { expectedKeyCode: root.profile_id }), /five groups/);
});

test('unchanged legacy fingerprint case normalization agrees between browser and independent verifier', async () => {
  const { inspectContinuityPackage } = await import('../src/keyContinuity.js');
  const options = { anchorCheckpoint: fingerprint(root).toUpperCase() };
  assert.equal(verifyContinuity(json(firstPackage), options).anchor_status, 'matched');
  assert.equal((await inspectContinuityPackage(json(firstPackage), options)).anchor_status, 'matched');
});

test('valid Unicode provenance demonstrates character limits are distinct from file byte limits', async () => {
  const owners = [owner(), owner(), owner()];
  let day = 1;
  const profiles = owners.map(who => {
    let profile = who.profile;
    for (let event = 0; event < 5; event += 1) {
      const start = `2026-03-${String(day++).padStart(2, '0')}`, end = `2026-03-${String(day).padStart(2, '0')}`;
      profile = append(who, profile, start, end, 1000000);
      const stamp = profile.stamps.at(-1);
      stamp.payload.provenance.corrections = Array.from({ length: 100 }, (_, row) => ({ row, field: '\u754c'.repeat(80), reason: '\u754c'.repeat(500), previous_sha256: '0'.repeat(64), replacement_sha256: '1'.repeat(64) }));
      const bytes = Buffer.from(json(stamp.payload));
      stamp.sha256 = hash(bytes); stamp.signature = signed(who.privateKey, 'n170.verify.stamp-signature.v4\n', bytes);
    }
    assert.ok(json(profile).length <= 500000);
    return profile;
  });
  const first = certificate(owners[0], profiles[0], owners[1], profiles[1]);
  const second = certificate(owners[1], profiles[1], owners[2], profiles[2], first.sha256);
  const text = json(packet(profiles, [first, second]));
  assert.ok(text.length < 2600000);
  assert.ok(Buffer.byteLength(text, 'utf8') > 2600000, 'A valid UTF-8 file can exceed the old UI byte guard.');
  assert.equal(verifyContinuity(text).anchor_status, 'not_supplied');
  const { inspectContinuityPackage } = await import('../src/keyContinuity.js');
  assert.equal((await inspectContinuityPackage(text)).anchor_status, 'not_supplied');
});

test('CLI distinguishes all anchored, partial/unanchored/conflict and malformed evidence', () => {
  const directory = mkdtempSync(join(tmpdir(), 'n170-independent-continuity-'));
  try {
    const write = (name, value) => { const path = join(directory, name); writeFileSync(path, typeof value === 'string' ? value : json(value)); return path; };
    const first = write('first.json', firstPackage), second = write('second.json', secondPackage), prior = write('prefix.json', prefixPackage);
    const rootPath = write('root.json', root), middlePath = write('middle.json', middle), checkpointPath = write('checkpoint.txt', fingerprint(root));
    const malformed = copy(firstPackage); delete malformed.transitions[0].old_signature;
    const invalid = write('malformed.json', malformed);
    const script = fileURLToPath(new URL('../scripts/verify-continuity.mjs', import.meta.url));
    for (const [args, status] of [
      [[first], 2], [[first, '--anchor-profile', rootPath], 0], [[first, '--anchor-checkpoint', checkpointPath], 0],
      [[second, '--anchor-profile', rootPath], 2], [[second, first], 0], [[second, prior], 2],
      [[first, '--anchor-profile', middlePath], 2], [[first, '--expected-key-code', keyCode(middle)], 2],
      [[invalid], 1], [[first, '--anchor-profile', rootPath, '--anchor-checkpoint', checkpointPath], 1],
    ]) {
      const result = spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' });
      assert.equal(result.status, status, `${args.join(' ')}\n${result.stderr}\n${result.stdout}`);
      if (status !== 1) assert.equal(JSON.parse(result.stdout).exit_code, status);
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('the independent verifier imports no browser or producer continuity implementation', () => {
  const source = readFileSync(new URL('../scripts/verify-continuity.mjs', import.meta.url), 'utf8');
  const imports = [...source.matchAll(/from\s+['"]([^'"]+)['"]/g)].map(match => match[1]);
  assert.ok(imports.every(path => path.startsWith('node:') || path === './verify-record.mjs'));
  assert.doesNotMatch(source, /import\s*\(/);
});

test('CLI rejects malformed UTF-8 instead of substituting a signed replacement character', () => {
  const directory = mkdtempSync(join(tmpdir(), 'n170-independent-utf8-'));
  try {
    const a = owner(), b = owner();
    a.profile.display_name = b.profile.display_name = 'Original synthetic \ufffd alias';
    const old = append(a, a.profile, '2026-02-01', '2026-02-02', -1000000);
    const evidence = packet([old, b.profile], [certificate(a, old, b, b.profile)]);
    const valid = join(directory, 'valid.json'), malformed = join(directory, 'malformed.json');
    const rootFile = join(directory, 'root.json'), malformedRoot = join(directory, 'malformed-root.json');
    const invalidEncoding = value => Buffer.concat(json(value).split('\ufffd').flatMap((part, index) => index ? [Buffer.from([0xff]), Buffer.from(part)] : [Buffer.from(part)]));
    writeFileSync(valid, json(evidence)); writeFileSync(malformed, invalidEncoding(evidence));
    writeFileSync(rootFile, json(old)); writeFileSync(malformedRoot, invalidEncoding(old));
    assert.equal(invalidEncoding(evidence).toString('utf8'), json(evidence), 'Lossy decoding would create the legitimately signed text.');
    assert.throws(() => new TextDecoder('utf-8', { fatal: true }).decode(invalidEncoding(evidence)), /encoded|encoding/i);
    const script = fileURLToPath(new URL('../scripts/verify-continuity.mjs', import.meta.url));
    for (const [args, status] of [[[valid], 2], [[valid, '--anchor-profile', rootFile], 0], [[malformed], 1], [[valid, '--anchor-profile', malformedRoot], 1], [[valid, malformedRoot], 1]]) {
      const result = spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' });
      assert.equal(result.status, status, `${args.join(' ')}\n${result.stderr}\n${result.stdout}`);
      if (status === 1) assert.match(result.stderr, /UTF-8|encoding|encoded/i);
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('browser and independent verifier agree on separately authored retention controls', async () => {
  // The producer is imported only for a differential check, never for fixture
  // construction or by the independent verifier.
  const { inspectContinuityPackage } = await import('../src/keyContinuity.js');
  for (const [evidence, options, expected] of [
    [firstPackage, {}, 'not_supplied'], [firstPackage, { anchorProfile: json(root) }, 'matched'],
    [firstPackage, { anchorProfile: json(rootFirst) }, 'partial'], [secondPackage, { anchorProfile: json(root) }, 'partial'],
    [secondPackage, { previous: json(firstPackage) }, 'matched'], [secondPackage, { previous: json(prefixPackage) }, 'partial'],
    [firstPackage, { anchorProfile: json(rootOwner.profile) }, 'partial'],
    [secondPackage, { previous: json(emptyDestination) }, 'partial'],
    [firstPackage, { previous: json(root) }, 'matched'],
    [firstPackage, { expectedKeyCode: keyCode(middle) }, 'conflict'],
  ]) {
    const independent = verifyContinuity(json(evidence), options);
    const browser = await inspectContinuityPackage(json(evidence), options);
    assert.equal(independent.anchor_status, expected);
    assert.equal(browser.anchor_status, expected);
    assert.deepEqual(browser.perEdge.map(edge => edge.history_anchor), independent.perEdge.map(edge => edge.history_anchor));
  }
});

// Track 3 independently reported a checkpoint-input limit mismatch. These
// controls retain complete raw whitespace in both fingerprint and JSON syntax.
for (const syntax of ['fingerprint', 'json']) {
  for (const length of [8192, 8193, 20000, 20001]) {
    test(`retained ${syntax} checkpoint ${length}-character boundary agrees across browser, Node API and CLI`, async () => {
      const { inspectContinuityPackage } = await import('../src/keyContinuity.js');
      const anchor = (syntax === 'fingerprint' ? fingerprint(root) : json(fullCheckpoint(root))).padEnd(length, ' ');
      assert.equal(anchor.length, length);
      const permitted = length <= 20000;
      const options = { anchorCheckpoint: anchor };
      if (permitted) {
        assert.equal((await inspectContinuityPackage(firstPackage, options)).anchor_status, 'matched');
        assert.equal(verifyContinuity(json(firstPackage), options).anchor_status, 'matched');
      } else {
        await assert.rejects(inspectContinuityPackage(firstPackage, options));
        assert.throws(() => verifyContinuity(json(firstPackage), options));
      }
      const folder = mkdtempSync(join(tmpdir(), 'n170-checkpoint-boundary-'));
      try {
        const currentPath = join(folder, 'current.json'), checkpointPath = join(folder, 'checkpoint.txt');
        writeFileSync(currentPath, json(firstPackage)); writeFileSync(checkpointPath, anchor);
        const result = spawnSync(process.execPath, [fileURLToPath(new URL('../scripts/verify-continuity.mjs', import.meta.url)), currentPath, '--anchor-checkpoint', checkpointPath], { encoding: 'utf8' });
        assert.equal(result.status, permitted ? 0 : 1, result.stdout + result.stderr);
        if (permitted) assert.equal(JSON.parse(result.stdout).anchor_status, 'matched');
      } finally { rmSync(folder, { recursive: true, force: true }); }
    });
  }
}
