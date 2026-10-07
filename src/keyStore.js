// Browser-local key lifecycle. Nonextractable keys never move between devices.
// Continuity evidence is separate from unchanged signed profile objects.
import { createSigner, generateProfileKey } from './signing.js';
import { createProfile, extendsByOneRecord, inspectProfile } from './trackRecord.js';
import {
  createTransitionRequest, inspectTransitionRequest, approveTransitionRequest,
  inspectContinuityPackage, inspectContinuityHistory, effectiveEnd, MAX_TRANSITIONS,
} from './keyContinuity.js';

const DATABASE = 'n170-verify';
const STORE = 'profiles';
const CONTINUITY = 'continuity';
const VERSION = 2;
const profileIdPattern = /^[a-f0-9]{64}$/;
const MESSAGES = {
  unavailable: "This browser can't keep signed profiles here. Private browsing or blocked site data can prevent it.",
  busy: 'Browser storage is busy. Close other N170 Verify tabs and try again.',
  failed: 'Browser storage failed, so nothing was changed. Try again.',
  stale: "This profile changed in another tab, so the new record wasn't kept.",
  missing: "This profile is no longer kept in this browser, so the new record wasn't kept.",
  inactive: 'This local key is pending, retired, cancelled or deleted. It cannot append records or authorize another transition.',
  conflict: 'The transition conflicts with the current local history or a previously committed destination. No lifecycle change was saved.',
  pending: 'This completion does not match an available pending local destination key and request. Continuity cannot be established here.',
  boundary: 'The new segment must start on or after the previous segment’s effective end date. Nothing was saved.',
  limit: 'This continuity chain already has four transitions. Further transitions are unsupported.',
};
const clone = value => value == null ? value : JSON.parse(JSON.stringify(value));
const storageError = code => Object.assign(new Error(MESSAGES[code] || MESSAGES.failed), { code });

function openDatabase() {
  return new Promise((resolve, reject) => {
    let request;
    let settled = false;
    const rejectOnce = code => { if (!settled) { settled = true; reject(storageError(code)); } };
    try { request = globalThis.indexedDB.open(DATABASE, VERSION); }
    catch { rejectOnce('unavailable'); return; }
    request.onupgradeneeded = () => {
      // A blocked request can later wake after its caller already received an
      // error. It must not retain a connection or silently run a late upgrade.
      if (settled) { request.transaction.abort(); request.result.close(); return; }
      if (!request.result.objectStoreNames.contains(STORE)) request.result.createObjectStore(STORE);
      if (!request.result.objectStoreNames.contains(CONTINUITY)) request.result.createObjectStore(CONTINUITY);
    };
    request.onsuccess = () => {
      const database = request.result;
      if (settled) { database.close(); return; }
      settled = true;
      database.onversionchange = () => database.close();
      resolve(database);
    };
    request.onerror = () => rejectOnce('unavailable');
    request.onblocked = () => rejectOnce('busy');
  });
}

// Every mutation locks both stores. Crypto happens before this transaction;
// synchronous comparisons inside it decide whether that proposal may commit.
async function transact(mode, body) {
  const database = await openDatabase();
  return new Promise((resolve, reject) => {
    let transaction;
    let result;
    let failure = 'failed';
    const fail = code => {
      failure = code || 'failed';
      try { transaction.abort(); } catch { database.close(); reject(storageError(failure)); }
    };
    const protect = callback => (...args) => { try { callback(...args); } catch { fail('failed'); } };
    try {
      transaction = database.transaction([STORE, CONTINUITY], mode);
      transaction.oncomplete = () => { database.close(); resolve(result); };
      transaction.onabort = () => { database.close(); reject(storageError(failure)); };
      body(transaction.objectStore(STORE), transaction.objectStore(CONTINUITY), value => { result = value; }, fail, protect);
    } catch { if (transaction) fail('failed'); else { database.close(); reject(storageError('failed')); } }
  });
}

function pair(profiles, continuity, profileId, callback, protect) {
  let raw; let state; let remaining = 2;
  const done = () => { if (--remaining === 0) callback(raw, state); };
  const profileRequest = profiles.get(profileId);
  const stateRequest = continuity.get(profileId);
  profileRequest.onsuccess = protect(() => { raw = profileRequest.result; done(); });
  stateRequest.onsuccess = protect(() => { state = stateRequest.result; done(); });
}

function publicContinuity(state) {
  if (!state) return null;
  return clone({
    request: state.outgoingRequest || state.request || null,
    completionPackage: state.outgoingPackage || state.completionPackage || null,
    incomingPackage: state.incomingPackage || null,
    outgoingPackage: state.outgoingPackage || null,
    boundary: state.boundary || null,
    transitionCount: (state.outgoingPackage || state.incomingPackage)?.transitions?.length || 0,
  });
}

function readEntry(key, value, state) {
  const profile = value?.profile;
  if (typeof key !== 'string' || !profileIdPattern.test(key) || profile?.profile_id !== key
    || typeof profile.display_name !== 'string' || !Array.isArray(profile.stamps)) return null;
  try {
    return { profile, signer: createSigner(value.privateKey, profile.public_key), lifecycle: state?.lifecycle || 'active', continuity: publicContinuity(state) };
  } catch { return null; }
}

function requestPersistentStorage() {
  try { Promise.resolve(globalThis.navigator?.storage?.persist?.()).catch(() => {}); } catch { /* Optional browser support. */ }
}

// Identity is independent of equivalent ECDSA signature encodings. Both sides
// have been checked cryptographically before these transaction-local comparisons.
function profileIdentity(profile) {
  return [profile?.schema_version, profile?.profile_id, profile?.public_key, profile?.display_name,
    profile?.stamps?.length, profile?.stamps?.at(-1)?.sha256 || null];
}
function sameProfile(left, right) { return JSON.stringify(profileIdentity(left)) === JSON.stringify(profileIdentity(right)); }
function historyIdentity(history) {
  const profiles = history?.profiles || [history];
  return JSON.stringify({ profiles: profiles.map(profileIdentity), transitions: (history?.transitions || []).map(item => item.sha256) });
}
function incomingEvidence(profile, state) {
  if (!state?.incomingPackage) return profile;
  return { ...state.incomingPackage, profiles: [...state.incomingPackage.profiles.slice(0, -1), profile] };
}
function evidenceFor(raw, state) {
  return state?.outgoingPackage || (raw?.profile ? incomingEvidence(raw.profile, state) : state?.incomingPackage || state?.profileSnapshot || null);
}
async function snapshot(profileId) {
  return transact('readonly', (profiles, continuity, finish, _fail, protect) => {
    pair(profiles, continuity, profileId, (raw, state) => finish({ raw, state }), protect);
  });
}

export async function createStoredProfile(alias) {
  const { privateKey, publicKey } = await generateProfileKey();
  const signer = createSigner(privateKey, publicKey);
  const profile = await createProfile(alias, signer);
  await transact('readwrite', profiles => profiles.add({ privateKey, profile }, profile.profile_id));
  requestPersistentStorage();
  return { profile, signer, lifecycle: 'active', continuity: null };
}

export async function listStoredProfiles() {
  return transact('readonly', (profiles, continuity, finish, _fail, protect) => {
    const entries = [];
    const request = profiles.openCursor();
    request.onsuccess = protect(() => {
      const cursor = request.result;
      if (!cursor) { finish(entries.sort((a, b) => a.profile.display_name.localeCompare(b.profile.display_name))); return; }
      const metadata = continuity.get(cursor.key);
      metadata.onsuccess = protect(() => {
        const entry = readEntry(cursor.key, cursor.value, metadata.result);
        if (entry) entries.push(entry);
        cursor.continue();
      });
    });
  });
}

export async function readStoredContinuity(profileId) {
  const { state } = await snapshot(profileId);
  return state ? { profileId, lifecycle: state.lifecycle, ...publicContinuity(state) } : null;
}

export async function listStoredContinuity() {
  return transact('readonly', (_profiles, continuity, finish, _fail, protect) => {
    const entries = [];
    const request = continuity.openCursor();
    request.onsuccess = protect(() => {
      const cursor = request.result;
      if (!cursor) { finish(entries); return; }
      entries.push({ profileId: cursor.key, lifecycle: cursor.value.lifecycle, ...publicContinuity(cursor.value) });
      cursor.continue();
    });
  });
}

export async function getStoredTransitionRequest(profileId) {
  const { state } = await snapshot(profileId);
  const request = state?.outgoingRequest || state?.request;
  if (!request) throw storageError('pending');
  return clone(request);
}

export async function getStoredEvidence(profileId) {
  const { raw, state } = await snapshot(profileId);
  const evidence = evidenceFor(raw, state);
  if (!evidence) throw storageError('missing');
  const checked = await inspectContinuityHistory(evidence);
  return checked.history;
}

export async function appendStoredRecord(value) {
  const { profile: next } = await inspectProfile(JSON.stringify(value));
  await transact('readwrite', (profiles, continuity, _finish, fail, protect) => {
    pair(profiles, continuity, next.profile_id, (raw, state) => {
      const entry = readEntry(next.profile_id, raw, state);
      if (!entry) { fail('missing'); return; }
      if (entry.lifecycle !== 'active' || state?.outgoingPackage) { fail('inactive'); return; }
      if (!extendsByOneRecord(entry.profile, next)) { fail('stale'); return; }
      const firstPerformance = next.stamps.find(stamp => stamp.payload.event_type !== 'correction');
      if (state?.boundary && firstPerformance && firstPerformance.payload.period.start < state.boundary) { fail('boundary'); return; }
      profiles.put({ privateKey: raw.privateKey, profile: next }, next.profile_id);
      if (state) continuity.put({ ...state, profileSnapshot: next, incomingPackage: state.incomingPackage ? incomingEvidence(next, state) : null }, next.profile_id);
    }, protect);
  });
}

export async function createStoredTransitionRequest(history) {
  const checked = await inspectContinuityHistory(history);
  if (checked.transitions.length >= MAX_TRANSITIONS) throw storageError('limit');
  const { privateKey, publicKey } = await generateProfileKey();
  const signer = createSigner(privateKey, publicKey);
  const profile = await createProfile(checked.currentProfile.display_name, signer);
  const request = await createTransitionRequest(checked.history, profile, signer);
  const inspected = await inspectTransitionRequest(request);
  const state = {
    lifecycle: 'pending', request: inspected.request, requestSha256: inspected.sha256,
    boundary: effectiveEnd(checked.currentProfile), profileSnapshot: profile,
    incomingPackage: null, completionPackage: null, outgoingPackage: null,
  };
  await transact('readwrite', (profiles, continuity) => {
    profiles.add({ privateKey, profile }, profile.profile_id);
    continuity.add(state, profile.profile_id);
  });
  requestPersistentStorage();
  return { profile, signer, lifecycle: 'pending', request: clone(inspected.request), continuity: publicContinuity(state) };
}

export async function approveStoredTransitionRequest(value) {
  const checked = await inspectTransitionRequest(value);
  const id = checked.oldProfile.profile_id;
  const before = await snapshot(id);
  if (before.state?.outgoingPackage) {
    if (before.state.outgoingSha256 !== checked.sha256) throw storageError('conflict');
    return (await inspectContinuityPackage(before.state.outgoingPackage)).package;
  }
  const entry = readEntry(id, before.raw, before.state);
  if (!entry) throw storageError('missing');
  if (entry.lifecycle !== 'active') throw storageError('inactive');
  if (!sameProfile(entry.profile, checked.oldProfile)
    || historyIdentity(incomingEvidence(entry.profile, before.state)) !== historyIdentity(checked.history)) throw storageError('conflict');
  const approved = await approveTransitionRequest(checked.request, entry.signer);
  const completion = approved.completionPackage;
  return transact('readwrite', (profiles, continuity, finish, fail, protect) => {
    pair(profiles, continuity, id, (raw, state) => {
      if (state?.outgoingPackage) {
        if (state.outgoingSha256 !== checked.sha256) { fail('conflict'); return; }
        finish(clone(state.outgoingPackage)); return;
      }
      const current = readEntry(id, raw, state);
      if (!current) { fail('missing'); return; }
      if (current.lifecycle !== 'active') { fail('inactive'); return; }
      if (!sameProfile(current.profile, checked.oldProfile)
        || historyIdentity(incomingEvidence(current.profile, state)) !== historyIdentity(checked.history)) { fail('stale'); return; }
      continuity.put({ ...state, lifecycle: 'retired', profileSnapshot: current.profile,
        outgoingRequest: checked.request, outgoingSha256: checked.sha256, outgoingPackage: completion }, id);
      finish(clone(completion));
    }, protect);
  });
}

export async function completeStoredTransition(value) {
  const checked = await inspectContinuityPackage(value);
  const completion = checked.package;
  const next = checked.currentProfile;
  const certificate = checked.transitions.at(-1);
  return transact('readwrite', (profiles, continuity, finish, fail, protect) => {
    pair(profiles, continuity, next.profile_id, (raw, state) => {
      const current = readEntry(next.profile_id, raw, state);
      if (!current) { fail('pending'); return; }
      if (state?.completionPackage) {
        if (historyIdentity(state.completionPackage) !== historyIdentity(completion)) { fail('conflict'); return; }
        // A retry returns the current lifecycle and never rolls back records or
        // reactivates a profile already retired by a subsequent transition.
        finish(current); return;
      }
      if (current.lifecycle !== 'pending' || !state?.request || state.requestSha256 !== certificate.sha256
        || !sameProfile(current.profile, next) || next.stamps.length !== 0) { fail('pending'); return; }
      const requestedHistory = state.request.history;
      const suppliedHistory = completion.profiles.length === 2 ? completion.profiles[0]
        : { ...completion, profiles: completion.profiles.slice(0, -1), transitions: completion.transitions.slice(0, -1) };
      if (historyIdentity(requestedHistory) !== historyIdentity(suppliedHistory)) { fail('conflict'); return; }
      const active = { ...state, lifecycle: 'active', incomingPackage: completion, completionPackage: completion,
        profileSnapshot: next, boundary: effectiveEnd(completion.profiles.at(-2)) };
      profiles.put({ privateKey: raw.privateKey, profile: next }, next.profile_id);
      continuity.put(active, next.profile_id);
      finish(readEntry(next.profile_id, { ...raw, profile: next }, active));
    }, protect);
  });
}

export async function cancelStoredTransition(profileId) {
  return transact('readwrite', (profiles, continuity, finish, fail, protect) => {
    pair(profiles, continuity, profileId, (raw, state) => {
      if (state?.lifecycle === 'cancelled') { finish(false); return; }
      if (!raw || state?.lifecycle !== 'pending' || state.completionPackage) { fail('pending'); return; }
      continuity.put({ ...state, lifecycle: 'cancelled' }, profileId);
      finish(true);
    }, protect);
  });
}

// Deleting a key cannot revoke already exported evidence. Committed transition
// packages remain locally recoverable; a missing pending key cannot complete.
export async function deleteStoredProfile(profileId) {
  return transact('readwrite', (profiles, continuity, finish, _fail, protect) => {
    pair(profiles, continuity, profileId, (raw, state) => {
      finish(raw !== undefined);
      if (raw === undefined) return;
      profiles.delete(profileId);
      if (state) continuity.put({ ...state, lifecycle: 'deleted', profileSnapshot: raw.profile,
        incomingPackage: state.incomingPackage ? incomingEvidence(raw.profile, state) : null }, profileId);
    }, protect);
  });
}

export async function deleteAllStoredProfiles() {
  return transact('readwrite', (profiles, continuity, finish, _fail, protect) => {
    let count = 0;
    const request = profiles.openCursor();
    request.onsuccess = protect(() => {
      const cursor = request.result;
      if (!cursor) { finish(count); return; }
      const metadata = continuity.get(cursor.key);
      metadata.onsuccess = protect(() => {
        const state = metadata.result;
        if (state) continuity.put({ ...state, lifecycle: 'deleted', profileSnapshot: cursor.value.profile,
          incomingPackage: state.incomingPackage ? incomingEvidence(cursor.value.profile, state) : null }, cursor.key);
        cursor.delete(); count++; cursor.continue();
      });
    });
  });
}
