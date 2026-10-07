# Additive key continuity, version 1

This protocol relates signing keys. It does not recover a key, identify a person, authenticate account data, establish time, revoke signatures, or combine performance metrics. Existing v3/v4 profiles and their verification rules remain unchanged.

## Exact wire format

A package has exactly `schema_version, profiles, transitions`, in that order when exported. `schema_version` is `n170.verify.continuity-package.v1`. `profiles` contains 2–5 fully verified legacy profile objects in chain order; `transitions` contains 1–4 certificates, one per adjacent pair. Every destination is a v4 profile. All aliases match, profile IDs and keys are unique, and loops are forbidden. Every outgoing profile has at least one event. The final destination may be empty, which establishes no new performance.

Each certificate has exactly `payload, sha256, old_signature, new_signature`. The canonical payload field order is:

```text
schema_version: "n170.verify.key-transition.v1"
serialization_version: "1.0.0"
purpose: "device_change"
old_profile_id
old_public_key
old_display_name
old_checkpoint: { sequence, end, sha256 }
new_profile_id
new_public_key
new_display_name
challenge
previous_transition_sha256
```

IDs derive using the unchanged `n170.verify.profile-key.v3\n` domain. A challenge is canonical base64url encoding of exactly 32 random bytes. The previous transition digest is null on the first edge and the preceding certificate's payload digest on every later edge. `old_checkpoint` matches the last event of the complete supplied old profile, including corrections. It never refers merely to its final performance period.

Canonicalization uses compact UTF-8 JSON with the fixed field order above. `sha256` identifies these payload bytes only. Each signature is P-256/SHA-256, 64-byte P1363, canonical base64url, over its role domain followed by the same canonical payload bytes:

```text
n170.verify.key-transition.old.v1\n
n170.verify.key-transition.new.v1\n
```

Equivalent high/low-S signatures do not change certificate identity. Unknown fields, duplicate fields (including escaped duplicates), non-plain integer tokens, unsafe integers, unsupported schemas, and excessive nesting are rejected. Limits: four transitions, five profiles; 8,192 characters per certificate; 500,000 per profile; 2,600,000 per JSON package; 2,100,000 per request; nesting depth 32. Embedded profile/certificate limits count their compact JSON serialization after the complete enclosing input has passed lexical checks; package and request limits count the complete supplied text, including whitespace. Existing HTML exports keep their 2,000,000-character limit and direct oversized users to JSON export.

A request has exactly `{ schema_version: 'n170.verify.key-transition-request.v1', payload, new_signature, history }`. History is a fully checked single old profile or complete continuity package ending in the outgoing profile. A request never proves completed continuity. Its historical chain has at most three transitions, allowing the requested fourth edge. Approval binds the complete supplied old head and previous transition digest. Completion contains the full history and an empty new v4 profile. Request text must retain history; detached claims are insufficient.

## Public module API

All async inspectors accept JSON text or JSON-compatible objects. Text is checked before embedded values are reserialized. Imported derived metadata is never accepted as evidence.

- `parseContinuityJSON(text, maximum = MAX_CONTINUITY_CHARACTERS)` returns strict parsed JSON for known-schema dispatch; it is not cryptographic verification.
- `checkpointOf(profile)` returns `{ sequence, end, sha256 }` for the final event, or null for an empty profile. `effectiveEnd(profile)` returns the last effective performance period end, or null.
- `canonicalTransitionPayload(payload)` returns the fixed-order payload object. `transitionPayloadBytes(payload)` returns its compact UTF-8 bytes. `transitionSignatureBytes(payload, role)` prepends the exact `old` or `new` domain.
- `inspectTransitionCertificate(certificate)` checks both role signatures, payload hash and key identities, then returns its canonical certificate. Matching it to complete profiles still requires the package inspector.
- `inspectContinuityHistory(history)` verifies a single profile or package and returns `{ history, profiles, transitions, currentProfile, profileInspections }`.
- `createTransitionRequest(history, newProfile, newSigner, challenge?)` returns the full request object. An optional challenge must use canonical 32-byte base64url; omission generates it cryptographically. The destination profile must be empty and v4.
- `inspectTransitionRequest(request)` returns `{ request, payload, sha256, history, historyInspection, oldProfile, newProfile, new_signature_valid }`. `newProfile` is reconstructed as an empty v4 profile from the checked payload.
- `approveTransitionRequest(request, oldSigner)` returns `{ certificate, package, completionPackage }`; the final two properties refer to the same checked full package. It performs no storage or retirement. The caller must atomically commit retirement and the certificate against the current stored head before exporting.
- `buildContinuityPackage(history, newProfile, certificate)` returns a fully checked appended package.
- `inspectContinuityPackage(package, { anchorProfile?, anchorCheckpoint?, previous?, expectedKeyCode? })` returns `{ package, profiles, transitions, currentProfile, profile, profileInspections, perEdge, transition_signatures_valid, anchor_status, anchor, gaps, conflicts, comparison, checks }`. The `profile` alias identifies only the current segment and must not drive a merged presentation.
- `compareContinuity(previous, current)` compares fully checked histories using payload identities and existing profile comparisons. Earlier sealed segments and certificate payload digests cannot change; the prior terminal segment may extend, and complete additional edges may follow it.

## Dates, anchors and comparison

For every edge, the destination's first performance period must start on or after `effectiveEnd(oldProfile)`. The final event checkpoint may be an early-period correction, so checkpoint.end is never used as the boundary. Any gap is reported. Corrections remain within their original segment; no metric is merged across keys.

External profile and checkpoint anchors address the root segment. A checkpoint may use an unchanged legacy fingerprint line or the exact JSON object `{ profile_id, sequence, end, sha256 }`; the embedded certificate checkpoint is never independent prior evidence. A retained checkpoint supplied as text (legacy fingerprint or JSON object) is limited to 20,000 characters, including leading and trailing whitespace, in both browser and independent verifier. This is distinct from the 8,192-character transition-certificate limit. An expected key code refers to the root, never silently to the newest key. An earlier matching root prefix is explicitly partial; a retained longer or conflicting history is a conflict. The root `anchorProfile` and `anchorCheckpoint` options are mutually exclusive. A retained continuity `previous` envelope may be combined with a root checkpoint; both references are checked.

Each edge reports `key_anchor` (`direct`, `inherited`, `unanchored`) separately from `history_anchor` (`exact`, `prefix_only`, `not_retained`). Inherited key authority does not establish that a segment's final history was independently retained. Overall `anchor_status` distinguishes `not_supplied`, `partial`, `matched`, and `conflict`. `matched` requires independently retained exact history through **every outgoing segment's final head**. Root-only retention in a repeated chain therefore remains `partial`, even when `root_key_anchor_status` is `matched` and subsequent key authority is inherited. An earlier matching root prefix remains partial even for one edge.

Comparisons against a retained package independently identify which segment heads were retained. Previously sealed edges retain their exact anchors; a newly outgoing segment is exact only if the earlier package's terminal head already equals the now-sealed head. If it merely extends a retained prefix, historical coverage remains partial. Supplying only an expected root key code can match that key but does not establish a retained head. Conflicting transition payloads, including different destinations or old checkpoints, remain conflicts even when both packages' signatures verify. Hidden competing certificates cannot be discovered offline.

Recipient acceptance remains a local human decision, not a serialized trust flag. Local retirement prevents ordinary signing in this application's storage; it is not cryptographic revocation. A canceled pending request cannot revoke approval already signed on another device. Lost old keys have no bypass: continuity cannot be established.
