# Security policy and trust boundaries

Updated 27 October 2026 for N170 Verify with additive continuity support under acceptance review. This policy describes implementation and intended reporting scope; it does not certify a deployment or imply that remote security controls have executed.

## Supported code and evidence

Maintenance targets the current application. No older software release has a separate maintenance commitment. The current verifier implements signed v3 evidence under its original semantics and v4 evidence under calculation 2.0.0/serialization 1.0.0. The additive continuity inspector and independent CLI accept the bounded envelope specified in [the continuity contract](docs/key-continuity-contract.md); the existing single-profile verifier remains unchanged. Experimental earlier formats and unimplemented timestamp evidence are rejected. See [FORMAT.md](FORMAT.md).

## Reporting

Use the repository's private vulnerability-reporting form (https://github.com/GGeronik/n170-verify/security/advisories/new) only after confirming that it is available and enabled; this file cannot establish that it is reachable. If no verified route is available, request a private contact channel from the maintainer without posting vulnerability details. Do not publish sensitive findings in an issue or PR.

A useful report identifies the affected source revision/build, browser and operating system, observed versus expected behavior, required attacker capabilities, and minimal synthetic reproduction steps. Do not include financial account credentials, real account files or private keys. Response and resolution times are best effort; no response SLA is promised.

## Findings within scope

- A valid-looking result for tampered signed payloads, a wrong signing key, an invalid chain, incorrect v3/v4 arithmetic, invalid correction references, or a mismatch against a reviewer-supplied prior copy/checkpoint.
- Disagreement between the application and the independent verifier on supported evidence, including duplicate-field or encoding ambiguity.
- Unintended signing or export; raw-key extraction contrary to WebCrypto restrictions; a browser-storage race that persists conflicting histories or silently overwrites a newer draft.
- Financial data disclosed through an unintended application upload, logging or export path.
- Executable content reaching the application from untrusted JSON, CSV, private drafts or HTML packages; bypass of an applicable implemented browser policy.
- Accepted data that causes materially wrong results, unsupported financial treatment without a clear exception, or bounded-input resource exhaustion.
- Build/dependency/workflow paths that could introduce unauthorized code or disclose credentials.

## Deliberate limits

**Arithmetic and source authenticity are separate.** Signed records disclose rounded relative returns, calculations and owner declarations. An owner can sign invented amounts, incorrect flow treatments, incomplete account scope or selected dates. IBKR file parsing and source hashes do not authenticate IBKR, establish execution, live/paper status, identity or completeness. An aggregate summary without the series is not reproducible evidence.

**Signatures identify a key, not a person.** Anyone may create a profile. A key code supplied through a trusted channel can establish consistency with that claimed key; it does not establish legal identity, account ownership, qualifications or investment skill. No employment suitability score exists.

**Continuity is relative to retained evidence.** A key holder can sign alternative histories. The local transactional append policy constrains what this app stores in one browser origin; it is not global fork prevention. A valid shorter history is not detectable as a truncation without a supplied earlier copy or checkpoint that includes the missing events. A matching checkpoint covers only its exact prefix. The checker performs no public history discovery or monitoring. Dual-signed transitions relate keys without merging performance. Inherited key authority and independently retained outgoing history are distinct. Exact retained history is required through every outgoing final head for a matched anchor; root-only retention in a repeated chain and earlier retained prefixes remain partial. A supplied reference does not prove when it was retained. Detected competing certificates remain conflicts; hidden competing transitions cannot be discovered offline.

**No independent time.** Observation dates are financial labels. Neither signature validity nor a pasted fingerprint authenticates a creation/posting date. There is no external timestamp, transparency service or independently checked publication in this release.

**Deletion, revocation and key loss differ.** WebCrypto keys are generated nonextractable and stored in IndexedDB. That prevents raw private-key export through WebCrypto, not copying a loaded capability or access by the browser/device owner. Deleting the stored profile does not revoke past signatures or erase handles retained elsewhere. The app rejects an append if its saved profile has disappeared. Clearing/evicting origin storage may permanently end signing continuity; a public-profile export is not a key backup. Lost-key recovery remains unimplemented. Device changes require both available keys and exact locally committed history. Retirement and cancellation are local policies, not cryptographic revocation; cancellation cannot revoke approval already signed on another device, and retained completion evidence cannot recreate a missing destination key.

**Local/browser compromise is outside this application's authority.** A person or extension with effective origin/device access may read local data and use signing capabilities. Nonextractability is not a hardware or encrypted-storage guarantee. A compromised origin serving application code can undermine local assurances. Do not use this application as protection against a compromised device or deployment.

**Shared data remains sensitive.** Returns, dates, source digests, scope descriptions and correction reasons may disclose investment information. Knowing source values or guessing candidate input can expose more. Raw amounts are omitted from public records by design, but owner-entered text can disclose them. Hashes are not encryption or zero-knowledge proofs. Private draft saves/exports deliberately include original financial text and reviewed edits, and the app does not encrypt draft storage.

**ECDSA signatures are malleable.** Both valid s forms are accepted. Record identity, predecessor links and retained checkpoints use the payload hash, so a changed signature encoding does not change the financial record's identity.

## Implemented controls

- **Data boundaries:** working original financial data stays in component memory unless the user explicitly saves/exports a private draft. Signed public records and nonextractable keys use separate IndexedDB storage. There is no financial-upload endpoint, broker connector or telemetry implementation.
- **Browser lifecycle:** unsaved draft replacement/navigation is guarded with save/export/discard choices; beforeunload requests the browser's native unsaved-work prompt. Browser scheduling/crash/eviction behavior remains a browser boundary. Draft saves use revision comparison. Every next signed history is fully verified and canonically copied before a transaction compares its identity and complete preserved hash prefix to the stored copy.
- **Signed evidence:** key ID derivation, strict schema, integer encoding, versioned canonicalization, exact record hash, ECDSA signature, predecessor chain and calculation semantics are checked. Correction events bind the original hash and retain the original period; all retained events are checked. Comparison validates both files before reporting extension/truncation/replacement/conflict.
- **Parsing:** 500,000-character profile limit; 120 events; 499 intervals/event; exact object fields and rejection of duplicates/noncanonical numeric or base64url forms. Review HTML is bounded to 2,000,000 characters, only its unique inert JSON attachment is extracted, and no imported HTML is inserted into a DOM or executed. Source CSV limits and financial support are documented in [import formats](docs/import-formats.md) and [methods](docs/methods.md).
- **Additive continuity scope:** one to four transitions and two to five fully checked profiles; 8,192 characters per certificate, 500,000 per embedded profile, 2,600,000 per JSON envelope and 2,100,000 per request. Incoming bytes use bounded fatal UTF-8 decoding, with character limits applied after decoding. Existing review HTML retains its 2,000,000-character limit. Candidate request creation, approval/retirement, completion and append paths use transactional profile/continuity-store checks. Retained public completion evidence does not restore a lost key; local cancellation and retirement do not revoke signatures. These are implementation controls to validate, not a claim of completed security acceptance.
- **Independent checking:** `scripts/verify-record.mjs` imports no application code or third-party package. It uses Node standard crypto plus separately written parsing, serialization and arithmetic. Signed v3/v4 fixtures and tampering/comparison tests are retained in the repository. The separate `scripts/verify-continuity.mjs` implements transition canonicalization, role signatures and retained-history comparisons using Node standard libraries and the unchanged independent profile checker.
- **Production browser policy:** the worker applies `default-src 'none'`, same-origin scripts/styles/images, `connect-src 'none'`, `base-uri 'none'`, `form-action 'none'`, frame/object/worker restrictions and Trusted Types directives. Browser support affects enforcement. The build embeds the meta-compatible subset; framing protection requires a response header. Preview reuses response headers; development mode is not the production security boundary.
- **Other response headers:** HSTS, MIME sniffing protection, no-referrer, COOP/COEP/CORP, Origin-Agent-Cluster and restricted Permissions-Policy are configured in the worker. Actual public host enforcement requires an executed deployment check.

CSP blocks connection APIs; it does not mean the browser makes no requests. Loading scripts/styles/images from the app's origin and following external links can use the network. CSP is defense in depth and cannot establish trust in a compromised application origin. The downloaded static review package uses its own restrictive policy with inline styling for portability and no executable script; its visual presentation itself is unsigned.

## Captured accounting receipts and deliberate local execution

V2 run-review packages are unsigned supplied evidence, separate from signed
profiles and continuity envelopes. Browser and offline package review check
supported artifact digests and receipt relationships without executing received
strategy source, commands or oracle workers. A separately retained manifest
digest identifies exact evidence bytes; an internally consistent package can
still be fabricated. Neither digest consistency nor supplied oracle agreement
authenticates a producer, witnesses execution or discovers omitted attempts.

The exact-decimal model, native binary64 compatibility and supplied optional
oracle evidence are distinct results. Only cash, quantity and accumulated net
PnL have native comparisons; the other six metrics remain `NOT_SUPPLIED`, and
overall accounting remains `NOT_ASSESSABLE`. The supported synthetic spot bridge
does not establish financial realism, broker execution or profitability. See
the [accounting release guide](docs/accounting-release.md) and versioned
[capture limits](verify_toolkit/CAPTURE_V2.md).

Executing a reviewed local strategy is a separate, deliberate action with the
pinned engine and explicit local-code opt-in. Optional oracle execution uses a
separately installed, pinned dependency and a trusted Python interpreter; it is
not required for ordinary package review and is not an operating-system network
sandbox. Never treat received strategy source or an interpreter path as trusted
merely because its bytes appear in a receipt. Follow the
[v2 execution and oracle instructions](verify_toolkit/ACCOUNTING_V2.md).

The browser's captured-run review is memory-only. Complete run exports can
contain source code, settings, data, paths and logs; deliberate sharing requires
review of those bytes. A reading summary omits those artifacts and cannot stand
in for them. The public source/toolkit archives contain the explicitly reviewed
source inventory, not private acceptance logs or user financial evidence. The
separately pinned 68-case private-source challenge pack contains synthetic fixtures and its accepted checker; it is not a security assessment of this combined source.

## Configured controls versus executed evidence

Pinned exact package versions, lockfile integrity and disabled install scripts are configured. Public repository CI configuration is included for future use. Configuration does not demonstrate remote execution, enabled private reporting, required review, branch protection or a successfully secured release. Check the actual repository configuration and run evidence before making those claims. No unexecuted badges are used as release evidence.

The [public validation guide](docs/release-validation.md) describes reproducible checks and their limitations; historical internal logs and screenshots are not included in the public source inventory. [Release readiness](docs/release-readiness.md) distinguishes unresolved external prerequisites. Local automated tests are not an external audit, outside-user study or assurance about a deployed service.

Verify original received archive bytes against a separately retained SHA-256 before extracting or editing, as described in [README.md](README.md). The public build hashes the current explicit inventory into a new artifact; an edited source tree does not have to match the original immutable receipt. Preserve both identities. Archive integrity checks do not authenticate the producer, make dependencies trustworthy, or detect a producer that intentionally rebuilds different internally consistent unsigned evidence.

## Good-faith research

Use a local copy or deployment you control and synthetic or explicitly authorized data. Do not access other people's records/accounts, degrade services, contact financial providers on the project's behalf or test third-party services without authorization. This policy grants no authority over other systems and makes no legal safe-harbor promise.
