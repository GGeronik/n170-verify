#!/usr/bin/env node
// Independent continuity implementation. Only Node standard-library modules and
// the existing independent record verifier are used. No imports from src/.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { verifyEvidence, compareEvidence } from './verify-record.mjs';

const SCHEMA = 'n170.verify.continuity-package.v1';
const CERTIFICATE = 'n170.verify.key-transition.v1';
const PACKAGE_LIMIT = 2600000;
const PROFILE_LIMIT = 500000;
const CERTIFICATE_LIMIT = 8192;
const HTML_LIMIT = 2000000;
const CHECKPOINT_LIMIT = 20000;
const FIELDS = ['schema_version', 'serialization_version', 'purpose', 'old_profile_id', 'old_public_key', 'old_display_name', 'old_checkpoint', 'new_profile_id', 'new_public_key', 'new_display_name', 'challenge', 'previous_transition_sha256'];
const hash = value => createHash('sha256').update(value).digest('hex');
const check = (condition, message) => { if (!condition) throw new Error(message || 'Invalid continuity evidence'); };
const exact = (value, fields, name) => check(value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field)), `Invalid ${name || 'object'} fields`);
const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const date = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString().slice(0, 10) === value;
const pick = (value, fields) => Object.fromEntries(fields.map(field => [field, value[field]]));
const code = profile => profile.profile_id.slice(0, 20).match(/.{4}/g).join('-');
const serialized = value => JSON.stringify(value);
const head = profile => {
  const last = profile.stamps.at(-1);
  return last ? { sequence: last.payload.sequence, end: last.payload.period.end, sha256: last.sha256 } : null;
};

function base64(value, size) {
  check(typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value), 'Invalid base64url encoding');
  const bytes = Buffer.from(value, 'base64url');
  check(bytes.length === size && bytes.toString('base64url') === value, 'Noncanonical base64url encoding or wrong byte length');
  return bytes;
}

function strictJson(text, maximum) {
  check(typeof text === 'string' && text.length <= maximum, 'JSON exceeds its character limit');
  const tokens = text.match(/"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null|[{}\[\]:,]/g) || [];
  const scopes = [];
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    if (token === '{' || token === '[') {
      scopes.push(token === '{' ? new Set() : null);
      check(scopes.length <= 32, 'Excessive JSON nesting');
    } else if (token === '}' || token === ']') scopes.pop();
    else if (token[0] === '"' && tokens[i + 1] === ':') {
      const key = JSON.parse(token), scope = scopes.at(-1);
      check(scope && !scope.has(key), 'Duplicate object field');
      scope.add(key);
    } else if (/^[-0-9]/.test(token)) {
      check(/^(0|-?[1-9][0-9]*)$/.test(token) && Number.isSafeInteger(Number(token)), 'Noncanonical or unsafe number');
    }
  }
  return JSON.parse(text);
}

function extract(input) {
  check(typeof input === 'string', 'Supply JSON or an inert HTML review package as text');
  if (input.trimStart().startsWith('{')) return strictJson(input, PACKAGE_LIMIT);
  check(input.length <= HTML_LIMIT, 'HTML exceeds 2,000,000 characters; use JSON');
  const marker = '<script id="n170-evidence" type="application/json">';
  const parts = input.split(marker);
  check(parts.length === 2, 'Missing or ambiguous evidence attachment');
  const end = parts[1].indexOf('</script>');
  check(end >= 0, 'Incomplete evidence attachment');
  return strictJson(parts[1].slice(0, end), PACKAGE_LIMIT);
}

function effectiveEnd(profile) {
  // The unchanged profile verifier has already checked each correction's exact
  // target period. Corrections never move the latest performance boundary.
  return profile.stamps.filter(stamp => stamp.payload.event_type !== 'correction').at(-1)?.payload.period.end ?? null;
}

function canonicalPayload(payload) {
  const result = pick(payload, FIELDS);
  result.old_checkpoint = pick(payload.old_checkpoint, ['sequence', 'end', 'sha256']);
  return Buffer.from(serialized(result));
}

function publicKey(value) {
  const bytes = base64(value, 65);
  check(bytes[0] === 4, 'Public key must be an uncompressed P-256 point');
  return createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256', x: bytes.subarray(1, 33).toString('base64url'), y: bytes.subarray(33).toString('base64url') } });
}

function verifiedPackage(input) {
  const packet = extract(input);
  exact(packet, ['schema_version', 'profiles', 'transitions'], 'continuity package');
  check(packet.schema_version === SCHEMA, 'Unsupported package schema; a request is not completed continuity');
  check(Array.isArray(packet.profiles) && packet.profiles.length >= 2 && packet.profiles.length <= 5, 'A package needs two to five profiles');
  check(Array.isArray(packet.transitions) && packet.transitions.length >= 1 && packet.transitions.length <= 4 && packet.transitions.length + 1 === packet.profiles.length, 'A package needs one to four ordered transitions');
  const profiles = packet.profiles.map((profile, index) => {
    const text = serialized(profile);
    check(text.length <= PROFILE_LIMIT, 'An embedded profile exceeds 500,000 characters');
    const result = verifyEvidence(text);
    if (index) check(profile.schema_version === 'n170.verify.track-record.v4', 'Every destination profile must use v4');
    return result;
  });
  check(new Set(packet.profiles.map(profile => profile.profile_id)).size === packet.profiles.length, 'Duplicate profile identity or key loop');
  check(new Set(packet.profiles.map(profile => profile.public_key)).size === packet.profiles.length, 'Duplicate public key or key loop');
  check(packet.profiles.every(profile => profile.display_name === packet.profiles[0].display_name), 'Aliases must match across the chain');
  const perEdge = packet.transitions.map((certificate, index) => {
    check(serialized(certificate).length <= CERTIFICATE_LIMIT, 'Certificate exceeds 8,192 characters');
    exact(certificate, ['payload', 'sha256', 'old_signature', 'new_signature'], 'certificate');
    const payload = certificate.payload;
    exact(payload, FIELDS, 'transition payload');
    check(payload.schema_version === CERTIFICATE && payload.serialization_version === '1.0.0' && payload.purpose === 'device_change', 'Unsupported transition version or purpose');
    const oldProfile = packet.profiles[index], newProfile = packet.profiles[index + 1];
    check(oldProfile.stamps.length > 0, 'Every outgoing profile needs a complete nonempty history');
    for (const [role, profile] of [['old', oldProfile], ['new', newProfile]]) {
      check(payload[`${role}_profile_id`] === profile.profile_id && payload[`${role}_public_key`] === profile.public_key && payload[`${role}_display_name`] === profile.display_name, 'Certificate identity does not match its adjacent profile');
    }
    check(payload.old_profile_id !== payload.new_profile_id, 'Same-key transition is unsupported');
    exact(payload.old_checkpoint, ['sequence', 'end', 'sha256'], 'old checkpoint');
    const checkpoint = payload.old_checkpoint, expected = head(oldProfile);
    check(Number.isSafeInteger(checkpoint.sequence) && checkpoint.sequence >= 1 && checkpoint.sequence <= 120 && date(checkpoint.end) && hex(checkpoint.sha256), 'Invalid old checkpoint');
    check(checkpoint.sequence === expected.sequence && checkpoint.end === expected.end && checkpoint.sha256 === expected.sha256, 'Transition must commit to the complete supplied old head');
    base64(payload.challenge, 32);
    check(payload.previous_transition_sha256 === (index ? packet.transitions[index - 1].sha256 : null), 'Previous transition digest mismatch');
    const bytes = canonicalPayload(payload);
    check(hex(certificate.sha256) && certificate.sha256 === hash(bytes), 'Transition payload hash mismatch');
    for (const role of ['old', 'new']) {
      const signed = Buffer.concat([Buffer.from(`n170.verify.key-transition.${role}.v1\n`), bytes]);
      check(verify('sha256', signed, { key: publicKey(payload[`${role}_public_key`]), dsaEncoding: 'ieee-p1363' }, base64(certificate[`${role}_signature`], 64)), `${role} transition signature mismatch`);
    }
    const oldEnd = effectiveEnd(oldProfile);
    const first = newProfile.stamps.find(stamp => stamp.payload.event_type !== 'correction')?.payload.period.start ?? null;
    check(first === null || first >= oldEnd, 'New performance overlaps the effective old performance period');
    return {
      index, certificate_sha256: certificate.sha256, old_profile_id: oldProfile.profile_id, new_profile_id: newProfile.profile_id,
      old_checkpoint: checkpoint, effective_old_end: oldEnd, new_first_start: first,
      gap_days: first === null ? null : (Date.parse(first) - Date.parse(oldEnd)) / 86400000,
      key_anchor: 'unanchored', history_anchor: 'not_retained', retained_sequence: null, unretained_old_events: oldProfile.stamps.length,
    };
  });
  return { package: packet, profileChecks: profiles, perEdge };
}

function verifiedHistory(input) {
  const parsed = extract(input);
  if (parsed?.schema_version === SCHEMA) return verifiedPackage(input);
  check(['n170.verify.track-record.v3', 'n170.verify.track-record.v4'].includes(parsed?.schema_version), 'A previous reference must be a supported profile or complete continuity package');
  const result = verifyEvidence(input);
  // Internal comparison representation only. This is never accepted or emitted
  // as a zero-transition wire package.
  return { package: { profiles: [result.profile], transitions: [] }, profileChecks: [result], perEdge: [] };
}

function compareChecked(previous, current) {
  const prior = previous.package, next = current.package, conflicts = [];
  const shared = Math.min(prior.transitions.length, next.transitions.length);
  if (prior.profiles[0].profile_id !== next.profiles[0].profile_id || prior.profiles[0].display_name !== next.profiles[0].display_name) conflicts.push({ code: 'root_replacement', message: 'The retained chain has a different root key or alias.' });
  if (next.transitions.length < prior.transitions.length) conflicts.push({ code: 'chain_truncated', message: 'The current package omits previously retained transitions.' });
  for (let index = 0; index < shared; index += 1) {
    if (prior.transitions[index].sha256 !== next.transitions[index].sha256) conflicts.push({ code: 'competing_transition', edge: index, message: 'A retained transition payload differs, including its old checkpoint or destination.' });
    const comparison = compareEvidence(serialized(prior.profiles[index]), serialized(next.profiles[index]));
    if (comparison.status !== 'identical') conflicts.push({ code: 'sealed_history_changed', edge: index, status: comparison.status, message: 'An already sealed segment differs from the retained history.' });
  }
  let terminal = null;
  if (prior.transitions.length < next.profiles.length) {
    terminal = compareEvidence(serialized(prior.profiles.at(-1)), serialized(next.profiles[prior.transitions.length]));
    if (!['identical', 'extended'].includes(terminal.status)) conflicts.push({ code: 'terminal_history_conflict', segment: prior.transitions.length, status: terminal.status, message: 'The previously current segment was replaced, truncated or forked.' });
  }
  return {
    status: conflicts.length ? 'conflict' : next.transitions.length > prior.transitions.length || terminal?.status === 'extended' ? 'extended' : 'identical',
    extension_kind: conflicts.length ? null : next.transitions.length > prior.transitions.length ? 'additional_transitions' : terminal?.status === 'extended' ? 'current_segment_records' : null,
    shared_transitions: shared, previous_transition_count: prior.transitions.length, current_transition_count: next.transitions.length,
    terminal_comparison: terminal, conflicts, merged_metrics: false,
  };
}

export function compareContinuity(previous, current) {
  return compareChecked(verifiedHistory(previous), verifiedPackage(current));
}

function parseCheckpoint(input) {
  check(typeof input === 'string' && input.length <= CHECKPOINT_LIMIT, 'Supply a checkpoint of at most 20,000 characters');
  if (input.trimStart().startsWith('{')) {
    const value = strictJson(input, CHECKPOINT_LIMIT);
    exact(value, ['profile_id', 'sequence', 'end', 'sha256'], 'anchor checkpoint');
    check(hex(value.profile_id) && Number.isSafeInteger(value.sequence) && value.sequence >= 1 && value.sequence <= 120 && date(value.end) && hex(value.sha256), 'Invalid anchor checkpoint');
    return { ...value, key_code: null, syntax: 'full_profile_id' };
  }
  const match = /^n170-verify key=([a-f0-9]{4}(?:-[a-f0-9]{4}){4}) record=([1-9][0-9]*) end=(\d{4}-\d{2}-\d{2}) sha256=([a-f0-9]{64})$/.exec(input.trim().toLowerCase());
  check(match && Number(match[2]) <= 120 && date(match[3]), 'Invalid legacy checkpoint fingerprint');
  return { profile_id: null, key_code: match[1], sequence: Number(match[2]), end: match[3], sha256: match[4], syntax: 'legacy_80_bit_key_code' };
}

export function verifyContinuity(input, options = {}) {
  check(options && typeof options === 'object' && !Array.isArray(options), 'Invalid verifier options');
  check(!(options.anchorProfile !== undefined && options.anchorCheckpoint !== undefined), 'Profile and checkpoint anchors are mutually exclusive');
  const checked = verifiedPackage(input), packet = checked.package, root = packet.profiles[0];
  const conflicts = [], anchors = [], perEdge = checked.perEdge;
  let keyMatched = false, comparison = null;
  const retain = (index, sequence, source) => {
    const edge = perEdge[index];
    if (!edge) return;
    if (edge.retained_sequence === null || sequence > edge.retained_sequence) {
      edge.retained_sequence = sequence;
      edge.history_anchor = sequence === packet.profiles[index].stamps.length ? 'exact' : sequence ? 'prefix_only' : 'not_retained';
      edge.unretained_old_events = packet.profiles[index].stamps.length - sequence;
    }
    anchors.push({ edge: index, source, retained_sequence: sequence });
  };
  if (options.expectedKeyCode !== undefined) {
    check(typeof options.expectedKeyCode === 'string', 'Expected key code must be text');
    const expected = options.expectedKeyCode.trim().toLowerCase();
    check(/^[a-f0-9]{4}(?:-[a-f0-9]{4}){4}$/.test(expected), 'Expected key code needs five groups of four hexadecimal characters');
    if (expected !== code(root)) conflicts.push({ code: 'expected_root_key_mismatch', message: 'The expected old/root key does not match the root. It is never substituted with the current key.' });
    else keyMatched = true;
  }
  if (options.anchorProfile !== undefined) {
    const anchor = verifyEvidence(options.anchorProfile).profile;
    const match = compareEvidence(serialized(anchor), serialized(root));
    if (!['identical', 'extended'].includes(match.status)) conflicts.push({ code: 'root_profile_anchor_conflict', status: match.status, message: 'The retained root copy is newer, conflicting, or belongs to another key or alias.' });
    else { keyMatched = true; retain(0, anchor.stamps.length, 'independently_supplied_root_profile'); }
  }
  if (options.anchorCheckpoint !== undefined) {
    const anchor = parseCheckpoint(options.anchorCheckpoint), event = root.stamps[anchor.sequence - 1];
    if ((anchor.profile_id !== null ? anchor.profile_id !== root.profile_id : anchor.key_code !== code(root)) || !event || event.sha256 !== anchor.sha256 || event.payload.period.end !== anchor.end) conflicts.push({ code: 'root_checkpoint_anchor_conflict', message: 'The retained checkpoint does not match the root segment.' });
    else { keyMatched = true; retain(0, anchor.sequence, `independently_supplied_checkpoint:${anchor.syntax}`); }
  }
  if (options.previous !== undefined) {
    const previous = verifiedHistory(options.previous);
    comparison = compareChecked(previous, checked);
    conflicts.push(...comparison.conflicts);
    if (comparison.status !== 'conflict') keyMatched = true;
    for (let index = 0; comparison.status !== 'conflict' && index < perEdge.length; index += 1) {
      if (index < previous.package.transitions.length) {
        if (packet.transitions[index].sha256 === previous.package.transitions[index].sha256 && compareEvidence(serialized(previous.package.profiles[index]), serialized(packet.profiles[index])).status === 'identical') retain(index, previous.package.profiles[index].stamps.length, 'independently_supplied_previous_package');
      } else if (index === previous.package.transitions.length) {
        const prior = previous.package.profiles[index], next = packet.profiles[index];
        if (['identical', 'extended'].includes(compareEvidence(serialized(prior), serialized(next)).status)) retain(index, prior.stamps.length, 'retained_previous_terminal_profile');
      }
    }
  }
  for (const edge of perEdge) edge.key_anchor = keyMatched && !conflicts.length ? edge.index === 0 ? 'direct' : 'inherited' : 'unanchored';
  const anyReference = options.anchorProfile !== undefined || options.anchorCheckpoint !== undefined || options.previous !== undefined || options.expectedKeyCode !== undefined;
  const anchorStatus = conflicts.length ? 'conflict' : perEdge.every(edge => edge.history_anchor === 'exact') ? 'matched' : anyReference ? 'partial' : 'not_supplied';
  const rootConflict = conflicts.some(item => ['root_replacement', 'root_profile_anchor_conflict', 'root_checkpoint_anchor_conflict', 'expected_root_key_mismatch'].includes(item.code));
  return {
    package: packet, schema_version: SCHEMA, profiles_valid: true, transition_signatures_valid: true,
    transition_count: packet.transitions.length, root_profile_id: root.profile_id, current_profile_id: packet.profiles.at(-1).profile_id,
    root_key_code: code(root), current_key_code: code(packet.profiles.at(-1)), root_key_anchor_status: rootConflict ? 'conflict' : keyMatched ? 'matched' : 'not_supplied',
    perEdge, anchor_status: anchorStatus, anchors, conflicts, comparison,
    segments: checked.profileChecks.map(result => ({ profile_id: result.profile.profile_id, key_code: result.key_code, records: result.records, schema_version: result.profile.schema_version, arithmetic_valid: true, signatures_valid: true })),
    source_authenticated: false, identity_established: false, independent_timestamp: false, retirement_is_revocation: false, merged_metrics: false,
    hidden_competing_transitions_detectable: false, recipient_acceptance: 'not_determined',
    anchor_caveat: 'Matches caller-supplied retained evidence. The verifier cannot establish when a reference was retained. Inherited key linkage does not independently anchor unretained old events.',
    exit_code: anchorStatus === 'matched' ? 0 : 2,
  };
}

function readBounded(path) {
  check(statSync(path).size <= 12000000, 'Input file exceeds the bounded UTF-8 file size');
  const bytes = readFileSync(path);
  check(bytes.length <= 12000000, 'Input file exceeds the bounded UTF-8 file size');
  try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch { throw new Error('Input file must contain valid UTF-8; no replacement decoding is allowed'); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const positional = [], options = {}, args = process.argv.slice(2);
    const optionNames = { '--anchor-profile': 'anchorProfile', '--anchor-checkpoint': 'anchorCheckpoint', '--expected-key-code': 'expectedKeyCode' };
    for (let index = 0; index < args.length; index += 1) {
      const arg = args[index];
      if (Object.hasOwn(optionNames, arg)) {
        const name = optionNames[arg];
        check(options[name] === undefined && index + 1 < args.length, 'Repeated option or missing option value');
        options[name] = name === 'expectedKeyCode' ? args[++index] : readBounded(args[++index]);
      } else { check(!arg.startsWith('--'), 'Unknown option'); positional.push(arg); }
    }
    check(positional.length >= 1 && positional.length <= 2, 'Usage: node scripts/verify-continuity.mjs CURRENT [PREVIOUS] [--anchor-profile FILE | --anchor-checkpoint FILE] [--expected-key-code ROOT-CODE]');
    if (positional[1]) options.previous = readBounded(positional[1]);
    const { package: ignored, ...result } = verifyContinuity(readBounded(positional[0]), options);
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = result.exit_code;
  } catch (error) {
    console.error(`Continuity check failed: ${error.message}`);
    process.exitCode = 1;
  }
}
