// Additive key relationships. Legacy profile schemas/calculations stay frozen.
// Nothing here changes storage, retires keys, publishes, or establishes identity.
import { inspectProfile, compareProfiles, effectiveStamps, isValidDisplayName, PROFILE_SCHEMA, LEGACY_PROFILE_SCHEMA, MAX_PROFILE_CHARACTERS } from './trackRecord.js';
import { encodeBase64Url, decodeBase64Url, isPublicKeyText, isSignatureText, keyIdFromPublicKey, formatKeyCode, importVerificationKey, verifySignature, sha256Hex } from './signing.js';

export const CONTINUITY_SCHEMA = 'n170.verify.continuity-package.v1';
export const TRANSITION_SCHEMA = 'n170.verify.key-transition.v1';
export const TRANSITION_REQUEST_SCHEMA = 'n170.verify.key-transition-request.v1';
export const MAX_TRANSITIONS = 4;
export const MAX_PROFILES = 5;
export const MAX_CONTINUITY_CHARACTERS = 2600000;
export const MAX_REQUEST_CHARACTERS = 2100000;
export const MAX_TRANSITION_CHARACTERS = 8192;
export const MAX_CONTINUITY_DEPTH = 32;
const encoder = new TextEncoder();
const hex = /^[a-f0-9]{64}$/;
const profileSchemas = [PROFILE_SCHEMA, LEGACY_PROFILE_SCHEMA];
const fields = ['schema_version', 'serialization_version', 'purpose', 'old_profile_id', 'old_public_key', 'old_display_name', 'old_checkpoint', 'new_profile_id', 'new_public_key', 'new_display_name', 'challenge', 'previous_transition_sha256'];
const date = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString().slice(0, 10) === value;
const clone = value => JSON.parse(JSON.stringify(value));
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const fail = (message, code = 'invalid_continuity') => { throw Object.assign(new Error(message), { code }); };
const require = (condition, message, code) => { if (!condition) fail(message, code); };
const exact = (value, keys) => require(value !== null && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(k => Object.hasOwn(value, k)), 'Continuity evidence contains missing or unsupported fields.');

// Inspect raw JSON before reserializing nested profiles. Escaped duplicate names
// and alternative integer spellings must not disappear during JSON.parse.
export function parseContinuityJSON(text, maximum = MAX_CONTINUITY_CHARACTERS) {
  require(typeof text === 'string' && text.length <= maximum, `Use continuity evidence of at most ${maximum.toLocaleString('en-US')} characters.`, 'continuity_size');
  let value;
  try { value = JSON.parse(text); } catch { fail('Continuity evidence is not valid JSON.'); }
  const stack = []; let index = 0;
  while (index < text.length) {
    const c = text[index];
    if (c === '"') {
      let end = index + 1;
      while (end < text.length && text[end] !== '"') end += text[end] === '\\' ? 2 : 1;
      const token = text.slice(index, end + 1); index = end + 1;
      let next = index; while (next < text.length && /[\t\n\r ]/.test(text[next])) next += 1;
      if (stack.at(-1) && text[next] === ':') {
        const name = JSON.parse(token);
        require(!stack.at(-1).has(name), 'Continuity evidence repeats a field name, including an escaped spelling.', 'duplicate_field');
        stack.at(-1).add(name);
      }
      continue;
    }
    if (c === '-' || /[0-9]/.test(c)) {
      let end = index + 1; while (end < text.length && /[0-9+\-.eE]/.test(text[end])) end += 1;
      const token = text.slice(index, end);
      require(/^(?:0|-?[1-9][0-9]*)$/.test(token) && Number.isSafeInteger(Number(token)), 'Continuity numbers must be plain safe integers.', 'invalid_number');
      index = end; continue;
    }
    if (c === '{') stack.push(new Set()); else if (c === '[') stack.push(null); else if (c === '}' || c === ']') stack.pop();
    require(stack.length <= MAX_CONTINUITY_DEPTH, 'Continuity evidence exceeds the nesting limit.', 'continuity_depth');
    index += 1;
  }
  return value;
}
function read(value, maximum = MAX_CONTINUITY_CHARACTERS) {
  if (typeof value === 'string') return parseContinuityJSON(value, maximum);
  let text; try { text = JSON.stringify(value); } catch { fail('Continuity evidence must be JSON text or a JSON-compatible object.'); }
  return parseContinuityJSON(text, maximum);
}
function checkpointValid(value) {
  exact(value, ['sequence', 'end', 'sha256']);
  require(Number.isSafeInteger(value.sequence) && value.sequence >= 1 && value.sequence <= 120 && date(value.end) && typeof value.sha256 === 'string' && hex.test(value.sha256), 'The transition checkpoint is invalid.');
}
export function checkpointOf(profile) {
  const stamp = profile?.stamps?.at(-1);
  return stamp ? { sequence: stamp.payload.sequence, end: stamp.payload.period.end, sha256: stamp.sha256 } : null;
}
export function effectiveEnd(profile) { return effectiveStamps(profile).at(-1)?.payload.period.end ?? null; }
function validatePayload(p) {
  exact(p, fields);
  require(p.schema_version === TRANSITION_SCHEMA && p.serialization_version === '1.0.0' && p.purpose === 'device_change', 'The key-transition payload schema or purpose is unsupported.');
  require(typeof p.old_profile_id === 'string' && hex.test(p.old_profile_id) && typeof p.new_profile_id === 'string' && hex.test(p.new_profile_id) && isPublicKeyText(p.old_public_key) && isPublicKeyText(p.new_public_key), 'The transition profile keys or IDs are invalid.');
  require(p.old_profile_id !== p.new_profile_id && p.old_public_key !== p.new_public_key, 'A key transition must use a different destination key.', 'same_key_transition');
  require(isValidDisplayName(p.old_display_name) && p.old_display_name === p.new_display_name, 'A key transition must retain the same valid public alias.');
  checkpointValid(p.old_checkpoint);
  require(decodeBase64Url(p.challenge, 32) !== null, 'The destination challenge must be canonical base64url for exactly 32 bytes.');
  require(p.previous_transition_sha256 === null || (typeof p.previous_transition_sha256 === 'string' && hex.test(p.previous_transition_sha256)), 'The previous transition digest is invalid.');
}
export function canonicalTransitionPayload(p) {
  validatePayload(p);
  return { schema_version: p.schema_version, serialization_version: p.serialization_version, purpose: p.purpose, old_profile_id: p.old_profile_id, old_public_key: p.old_public_key, old_display_name: p.old_display_name,
    old_checkpoint: { sequence: p.old_checkpoint.sequence, end: p.old_checkpoint.end, sha256: p.old_checkpoint.sha256 },
    new_profile_id: p.new_profile_id, new_public_key: p.new_public_key, new_display_name: p.new_display_name, challenge: p.challenge, previous_transition_sha256: p.previous_transition_sha256 };
}
export function transitionPayloadBytes(payload) { return encoder.encode(JSON.stringify(canonicalTransitionPayload(payload))); }
export function transitionSignatureBytes(payload, role) {
  require(role === 'old' || role === 'new', 'The transition signature role must be old or new.');
  const domain = encoder.encode(`n170.verify.key-transition.${role}.v1\n`); const bytes = transitionPayloadBytes(payload);
  const result = new Uint8Array(domain.length + bytes.length); result.set(domain); result.set(bytes, domain.length); return result;
}
async function verifyPayloadKeys(payload) {
  require(await keyIdFromPublicKey(payload.old_public_key) === payload.old_profile_id && await keyIdFromPublicKey(payload.new_public_key) === payload.new_profile_id, 'A transition profile ID does not match its public key.');
  const keys = await Promise.all([importVerificationKey(payload.old_public_key), importVerificationKey(payload.new_public_key)]);
  require(keys.every(Boolean), 'A transition public key is not a valid P-256 point.'); return keys;
}
export async function inspectTransitionCertificate(value) {
  const cert = read(value, MAX_TRANSITION_CHARACTERS); exact(cert, ['payload', 'sha256', 'old_signature', 'new_signature']);
  const payload = canonicalTransitionPayload(cert.payload); const keys = await verifyPayloadKeys(payload);
  const digest = await sha256Hex(transitionPayloadBytes(payload));
  require(cert.sha256 === digest, 'The transition payload digest does not match.', 'transition_hash');
  require(isSignatureText(cert.old_signature) && isSignatureText(cert.new_signature), 'Both transition signatures are required.');
  const [oldValid, newValid] = await Promise.all([verifySignature(keys[0], cert.old_signature, transitionSignatureBytes(payload, 'old')), verifySignature(keys[1], cert.new_signature, transitionSignatureBytes(payload, 'new'))]);
  require(oldValid && newValid, 'A role-separated transition signature is invalid.', 'transition_signature');
  return { payload, sha256: digest, old_signature: cert.old_signature, new_signature: cert.new_signature };
}
function matchingOld(payload, profile, previousDigest) {
  require(payload.old_profile_id === profile.profile_id && payload.old_public_key === profile.public_key && payload.old_display_name === profile.display_name, 'The transition does not describe the supplied outgoing profile.');
  require(checkpointOf(profile) !== null && same(payload.old_checkpoint, checkpointOf(profile)), 'The transition checkpoint must match the complete outgoing profile final event.', 'transition_checkpoint');
  require(payload.previous_transition_sha256 === previousDigest, 'The previous transition digest does not match the supplied history.', 'transition_history');
}
function matchingNew(payload, profile) {
  require(profile.schema_version === PROFILE_SCHEMA && payload.new_profile_id === profile.profile_id && payload.new_public_key === profile.public_key && payload.new_display_name === profile.display_name, 'The transition destination must be the supplied v4 profile with the same alias.');
}
function emptyDestination(payload) {
  return { schema_version: PROFILE_SCHEMA, profile_id: payload.new_profile_id, display_name: payload.new_display_name, public_key: payload.new_public_key, stamps: [] };
}

// Full cryptographic validation without recipient decisions or recursive anchors.
async function corePackage(value) {
  const p = read(value); exact(p, ['schema_version', 'profiles', 'transitions']);
  require(p.schema_version === CONTINUITY_SCHEMA, 'This is not a supported continuity package. A request is not completed continuity.', 'continuity_schema');
  require(Array.isArray(p.profiles) && Array.isArray(p.transitions) && p.transitions.length >= 1 && p.transitions.length <= MAX_TRANSITIONS && p.profiles.length === p.transitions.length + 1, 'A continuity package needs one to four edges and two to five ordered profiles.', 'continuity_count');
  const profileInspections = await Promise.all(p.profiles.map(profile => inspectProfile(JSON.stringify(profile))));
  const profiles = profileInspections.map(result => result.profile);
  require(new Set(profiles.map(profile => profile.profile_id)).size === profiles.length && new Set(profiles.map(profile => profile.public_key)).size === profiles.length, 'A continuity chain cannot reuse profile keys or contain a loop.', 'continuity_loop');
  require(profiles.every(profile => profile.display_name === profiles[0].display_name), 'Every continuity segment must retain the same public alias.');
  const transitions = []; const perEdge = []; const gaps = [];
  for (let index = 0; index < p.transitions.length; index += 1) {
    const certificate = await inspectTransitionCertificate(p.transitions[index]);
    const old = profiles[index], next = profiles[index + 1];
    matchingOld(certificate.payload, old, transitions.at(-1)?.sha256 ?? null); matchingNew(certificate.payload, next);
    const boundary = effectiveEnd(old); const first = next.stamps.find(stamp => stamp.payload.event_type !== 'correction');
    require(boundary !== null, 'Every outgoing segment must contain performance history.');
    require(!first || first.payload.period.start >= boundary, 'The new segment overlaps the outgoing segment effective performance end.', 'transition_overlap');
    const gap = first && first.payload.period.start > boundary ? { edge: index, start: boundary, end: first.payload.period.start, kind: 'between_keys' } : null;
    if (gap) gaps.push(gap);
    transitions.push(certificate);
    perEdge.push({ edge: index, sha256: certificate.sha256, old_profile_id: old.profile_id, new_profile_id: next.profile_id, old_key_code: formatKeyCode(old.profile_id), new_key_code: formatKeyCode(next.profile_id), checkpoint: checkpointOf(old), effective_end: boundary, first_new_performance: first?.payload.period.start ?? null, gap, transition_signatures_valid: true, key_anchor: 'unanchored', history_anchor: 'not_retained' });
  }
  profileInspections.forEach((inspection, segment) => inspection.summary.gaps.forEach(gap => gaps.push({ ...gap, segment, kind: 'within_segment' })));
  const pack = { schema_version: CONTINUITY_SCHEMA, profiles, transitions };
  return { package: pack, history: pack, profiles, transitions, profileInspections, currentProfile: profiles.at(-1), perEdge, gaps };
}
export async function inspectContinuityHistory(value) {
  const history = read(value);
  if (history?.schema_version === CONTINUITY_SCHEMA) return corePackage(history);
  require(profileSchemas.includes(history?.schema_version), 'Choose a checked legacy profile or complete continuity package; other schemas are unsupported.', 'continuity_schema');
  const inspected = await inspectProfile(JSON.stringify(history));
  return { history: inspected.profile, profiles: [inspected.profile], transitions: [], currentProfile: inspected.profile, profileInspections: [inspected], perEdge: [], gaps: inspected.summary.gaps };
}
export async function createTransitionRequest(history, newProfile, newSigner, challenge) {
  const old = await inspectContinuityHistory(history); const next = (await inspectProfile(typeof newProfile === 'string' ? newProfile : JSON.stringify(newProfile))).profile;
  require(old.transitions.length < MAX_TRANSITIONS, 'This chain already has four transitions. A further transfer is unsupported.', 'continuity_count');
  require(next.schema_version === PROFILE_SCHEMA && next.stamps.length === 0, 'A new device-change destination must be an empty v4 profile.');
  require(newSigner?.publicKey === next.public_key && typeof newSigner.sign === 'function', 'The destination signing key is unavailable.');
  require(!old.profiles.some(profile => profile.profile_id === next.profile_id || profile.public_key === next.public_key), 'A transition cannot return to an earlier key.', 'continuity_loop');
  require(checkpointOf(old.currentProfile) !== null, 'The outgoing profile needs at least one signed event.');
  if (challenge === undefined) challenge = encodeBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(32)));
  const payload = canonicalTransitionPayload({ schema_version: TRANSITION_SCHEMA, serialization_version: '1.0.0', purpose: 'device_change', old_profile_id: old.currentProfile.profile_id, old_public_key: old.currentProfile.public_key, old_display_name: old.currentProfile.display_name, old_checkpoint: checkpointOf(old.currentProfile), new_profile_id: next.profile_id, new_public_key: next.public_key, new_display_name: next.display_name, challenge, previous_transition_sha256: old.transitions.at(-1)?.sha256 ?? null });
  const request = { schema_version: TRANSITION_REQUEST_SCHEMA, payload, new_signature: await newSigner.sign(transitionSignatureBytes(payload, 'new')), history: old.history };
  return (await inspectTransitionRequest(request)).request;
}
export async function inspectTransitionRequest(value) {
  const r = read(value, MAX_REQUEST_CHARACTERS); exact(r, ['schema_version', 'payload', 'new_signature', 'history']);
  require(r.schema_version === TRANSITION_REQUEST_SCHEMA, 'This is not a supported device-change request.', 'continuity_schema');
  require(JSON.stringify({ payload: r.payload, new_signature: r.new_signature }).length <= MAX_TRANSITION_CHARACTERS, 'The transition request payload exceeds its size limit.', 'continuity_size');
  const payload = canonicalTransitionPayload(r.payload); const historyInspection = await inspectContinuityHistory(r.history);
  require(historyInspection.transitions.length < MAX_TRANSITIONS, 'A request would exceed four transitions.', 'continuity_count');
  matchingOld(payload, historyInspection.currentProfile, historyInspection.transitions.at(-1)?.sha256 ?? null);
  require(!historyInspection.profiles.some(profile => profile.profile_id === payload.new_profile_id || profile.public_key === payload.new_public_key), 'A transition cannot reuse a prior chain key.', 'continuity_loop');
  const keys = await verifyPayloadKeys(payload);
  require(isSignatureText(r.new_signature) && await verifySignature(keys[1], r.new_signature, transitionSignatureBytes(payload, 'new')), 'The destination request signature is invalid.', 'transition_signature');
  const newProfile = emptyDestination(payload); await inspectProfile(JSON.stringify(newProfile));
  const request = { schema_version: TRANSITION_REQUEST_SCHEMA, payload, new_signature: r.new_signature, history: historyInspection.history };
  return { request, payload, sha256: await sha256Hex(transitionPayloadBytes(payload)), history: historyInspection.history, historyInspection, oldProfile: historyInspection.currentProfile, newProfile, new_signature_valid: true };
}
export async function buildContinuityPackage(history, newProfile, certificate) {
  const prior = await inspectContinuityHistory(history);
  const pack = { schema_version: CONTINUITY_SCHEMA, profiles: [...prior.profiles, newProfile], transitions: [...prior.transitions, certificate] };
  return (await corePackage(pack)).package;
}
export async function approveTransitionRequest(value, oldSigner) {
  const checked = await inspectTransitionRequest(value);
  require(oldSigner?.publicKey === checked.oldProfile.public_key && typeof oldSigner.sign === 'function', 'The outgoing signing key is unavailable. Continuity cannot be established.');
  const certificate = { payload: checked.payload, sha256: checked.sha256, old_signature: await oldSigner.sign(transitionSignatureBytes(checked.payload, 'old')), new_signature: checked.request.new_signature };
  const pack = await buildContinuityPackage(checked.history, checked.newProfile, certificate);
  return { certificate, package: pack, completionPackage: pack };
}

const conflict = (code, message, extra = {}) => ({ code, message, ...extra });
async function compareHistories(previous, current) {
  const conflicts = []; const segmentComparisons = [];
  const commonEdges = Math.min(previous.transitions.length, current.transitions.length);
  for (let i = 0; i < commonEdges; i += 1) if (previous.transitions[i].sha256 !== current.transitions[i].sha256) conflicts.push(conflict('competing_transition', 'A previously retained transition payload differs, including its destination, checkpoint, challenge or earlier transition history.', { edge: i }));
  if (current.transitions.length < previous.transitions.length) conflicts.push(conflict('truncated_transition_history', 'The current copy removes retained transitions.'));
  if (previous.profiles[0].profile_id !== current.profiles[0].profile_id) conflicts.push(conflict('root_replacement', 'The current chain starts from a different root key.'));
  for (let index = 0; index < Math.min(previous.profiles.length, current.profiles.length); index += 1) {
    const comparison = await compareProfiles(JSON.stringify(previous.profiles[index]), JSON.stringify(current.profiles[index]));
    segmentComparisons.push({ segment: index, ...comparison });
    if (!['identical', 'extended'].includes(comparison.status)) conflicts.push(conflict('segment_history_conflict', `Segment ${index + 1} is ${comparison.status} relative to the retained copy.`, { segment: index, status: comparison.status }));
    if (index < previous.transitions.length && comparison.status !== 'identical') conflicts.push(conflict('sealed_segment_changed', 'A segment that was already closed by a retained transition changed.', { segment: index }));
  }
  const identical = !conflicts.length && previous.transitions.length === current.transitions.length && segmentComparisons.every(segment => segment.status === 'identical');
  return { status: conflicts.length ? 'conflict' : identical ? 'identical' : 'extended', conflicts, segment_comparisons: segmentComparisons, previous_transitions: previous.transitions.length, current_transitions: current.transitions.length, merged_metrics: false };
}
export async function compareContinuity(previous, current) { return compareHistories(await inspectContinuityHistory(previous), await inspectContinuityHistory(current)); }

function parseAnchorCheckpoint(value) {
  if (typeof value === 'string' && value.trimStart().startsWith('{')) value = read(value, 20000);
  if (typeof value === 'string') {
    require(value.length <= 20000, 'The retained checkpoint exceeds the supported size.');
    const match = /^n170-verify key=([a-f0-9]{4}(?:-[a-f0-9]{4}){4}) record=([1-9][0-9]{0,2}) end=([0-9]{4}-[0-9]{2}-[0-9]{2}) sha256=([a-f0-9]{64})$/.exec(value.trim().toLowerCase());
    require(match !== null, 'Use one unchanged N170 fingerprint line or the documented checkpoint object.');
    const checkpoint = { sequence: Number(match[2]), end: match[3], sha256: match[4] }; checkpointValid(checkpoint);
    return { checkpoint, key_code: match[1], profile_id: null };
  }
  const anchor = read(value, 20000); exact(anchor, ['profile_id', 'sequence', 'end', 'sha256']);
  require(typeof anchor.profile_id === 'string' && hex.test(anchor.profile_id), 'A retained checkpoint needs a full root profile ID.');
  const checkpoint = { sequence: anchor.sequence, end: anchor.end, sha256: anchor.sha256 }; checkpointValid(checkpoint);
  return { checkpoint, profile_id: anchor.profile_id, key_code: formatKeyCode(anchor.profile_id) };
}
export async function inspectContinuityPackage(value, options = {}) {
  require(options !== null && typeof options === 'object' && !Array.isArray(options), 'Continuity inspection options are invalid.');
  require(Object.keys(options).every(key => ['anchorProfile', 'anchorCheckpoint', 'previous', 'expectedKeyCode'].includes(key)), 'Continuity inspection options contain an unsupported field.');
  const core = await corePackage(value); const root = core.profiles[0]; const conflicts = []; const anchorDetails = [];
  const suppliedProfile = options.anchorProfile !== undefined && options.anchorProfile !== null && options.anchorProfile !== '';
  const suppliedCheckpoint = options.anchorCheckpoint !== undefined && options.anchorCheckpoint !== null && options.anchorCheckpoint !== '';
  require(!(suppliedProfile && suppliedCheckpoint), 'Supply either a retained root profile or root checkpoint, not both.');
  let supplied = false; let rootKeyMatched = false; let directRoot = false;
  const expected = options.expectedKeyCode ?? '';
  require(typeof expected === 'string' && (expected.trim() === '' || /^[a-f0-9]{4}(?:-[a-f0-9]{4}){4}$/.test(expected.trim().toLowerCase())), 'The expected root key code has an invalid format.');
  if (expected.trim()) {
    supplied = true;
    if (expected.trim().toLowerCase() !== formatKeyCode(root.profile_id)) conflicts.push(conflict('expected_root_key_mismatch', 'The expected key code does not match the root key. It is never substituted with the destination key.'));
    else { rootKeyMatched = true; directRoot = true; }
  }
  if (suppliedProfile) {
    supplied = true;
    const retained = await inspectProfile(typeof options.anchorProfile === 'string' ? options.anchorProfile : JSON.stringify(options.anchorProfile));
    const comparison = await compareProfiles(JSON.stringify(retained.profile), JSON.stringify(root));
    anchorDetails.push({ source: 'root_profile', comparison });
    if (['identical', 'extended'].includes(comparison.status)) {
      rootKeyMatched = true; directRoot = true;
      core.perEdge[0].history_anchor = comparison.status === 'identical' ? 'exact' : retained.profile.stamps.length ? 'prefix_only' : 'not_retained';
    } else conflicts.push(conflict('root_profile_conflict', 'The supplied root history is longer, conflicting, or belongs to a different key.', { status: comparison.status }));
  }
  if (suppliedCheckpoint) {
    supplied = true; const retained = parseAnchorCheckpoint(options.anchorCheckpoint);
    const event = root.stamps[retained.checkpoint.sequence - 1];
    const matches = retained.key_code === formatKeyCode(root.profile_id) && (!retained.profile_id || retained.profile_id === root.profile_id) && event && event.sha256 === retained.checkpoint.sha256 && event.payload.period.end === retained.checkpoint.end;
    if (matches) { rootKeyMatched = true; directRoot = true; core.perEdge[0].history_anchor = retained.checkpoint.sequence === root.stamps.length ? 'exact' : 'prefix_only'; }
    else conflicts.push(conflict('root_checkpoint_conflict', 'The root profile does not match the independently supplied checkpoint.'));
    anchorDetails.push({ source: 'root_checkpoint', ...retained, matched: !!matches });
  }
  let comparison = null;
  if (options.previous !== undefined && options.previous !== null && options.previous !== '') {
    supplied = true; const previous = await inspectContinuityHistory(options.previous); comparison = await compareHistories(previous, core);
    anchorDetails.push({ source: 'retained_history', comparison }); conflicts.push(...comparison.conflicts);
    if (comparison.status !== 'conflict') {
      rootKeyMatched = true; directRoot = true;
      for (let i = 0; i < Math.min(core.perEdge.length, previous.profiles.length); i += 1) {
        const segment = comparison.segment_comparisons[i];
        const status = segment.status === 'identical' ? 'exact' : previous.profiles[i].stamps.length ? 'prefix_only' : 'not_retained';
        if (core.perEdge[i].history_anchor !== 'exact') core.perEdge[i].history_anchor = status;
      }
    }
  }
  core.perEdge.forEach((edge, i) => { edge.key_anchor = rootKeyMatched && !conflicts.length ? i === 0 && directRoot ? 'direct' : 'inherited' : 'unanchored'; });
  const status = conflicts.length ? 'conflict' : !supplied ? 'not_supplied' : core.perEdge.every(edge => edge.history_anchor === 'exact') ? 'matched' : 'partial';
  const rootKeyStatus = conflicts.some(item => ['root_replacement', 'root_profile_conflict', 'root_checkpoint_conflict', 'expected_root_key_mismatch'].includes(item.code)) ? 'conflict' : rootKeyMatched ? 'matched' : 'not_supplied';
  return { ...core, profile: core.currentProfile, transition_signatures_valid: true, anchor_status: status, root_key_anchor_status: rootKeyStatus,
    anchor: { status, root_key_anchor_status: rootKeyStatus, details: anchorDetails, embedded_checkpoint_is_prior_evidence: false }, conflicts, comparison,
    checks: { schema_valid: true, arithmetic_valid: true, chain_valid: true, signatures_valid: true, transition_signatures_valid: true, anchor_status: status, provider_authenticated: false, independent_timestamp: false, identity_established: false, cryptographic_revocation: false },
    acceptance: { recipient_decision_required: true, recipient_acceptance_asserted: false }, merged_metrics: false };
}
