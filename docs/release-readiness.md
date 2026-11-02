# Release readiness and source workflow

This guide describes a free open-source browser application at its tagged source revision. It does not itself assert publication, deployment, a successful remote CI run, a broker connection or an external human audit; the notes of a published release state publication and hosting separately. The
[README](../README.md) describes current behavior; [validation scope](release-validation.md)
describes reproducible local checks and their limits.

## Verify what you received

Retain the exact received ZIP and obtain its expected SHA-256 through a trusted
channel. Obtain the independent `verify_release.py` verifier through a trusted
channel as well. Before extraction or editing:

```sh
python3 verify_release.py source.zip --sha256 EXPECTED_ARCHIVE_SHA256
```

Substitute the actual filename and digest. Python 3's standard library is enough.
The verifier checks exact archive identity, inventory and hashes without
extracting. The archive hash binds `MANIFEST.json` too, although the manifest's
file map omits itself. Hashes establish byte consistency, not publisher identity,
correctness or authenticity of financial evidence.

## Run the private-source CLI without a browser build

The [private-source guide](verify-reconciliation.md) describes the separately
supplied private reconciliation artifact, explicit v4 event selection, result
codes and limits. After verifying the archive, the complete source or combined
release places the checker under `app/scripts/`; use `cd app` from its extracted
root. The standalone toolkit places `scripts/` directly at the extraction root;
do not enter an `app/` folder there. Both layouts use this same command from the
folder containing `scripts/`, after replacing both quoted paths and the event
digest placeholder:

```sh
node scripts/verify-reconciliation.mjs --record "/absolute/path/to/signed-record.json" --event-sha256 EVENT_SHA256 --reconciliation "/absolute/path/to/n170-private-reconciliation.json"
```

Use Node satisfying `^20.19.0 || >=22.12.0`. No npm installation or build is needed
for this CLI; the browser-build instructions below are a separate workflow.
`EVENT_SHA256` is invalid until replaced with the selected event's 64 lowercase
hexadecimal payload digest. This is conditional checking of deliberately supplied,
unencrypted private evidence, not account authentication or completeness proof.
Whole continuity envelopes are outside this command's input scope. Exit 0 remains
`VERIFIED_UNDER_OWNER_ASSERTIONS`; retain all nonzero outcomes and the original
inputs. No completed independent financial acceptance is asserted here.

## Build or maintain a source copy

After verification, extract into a new directory. Complete source and combined
release ZIPs put the application, `verify_toolkit/`, `verify_accounting/`,
`toolkit-tests/` and `accounting-tests/` in `app/`. Use Node satisfying
`^20.19.0 || >=22.12.0`, npm and Python 3. Building and offline package review
need no third-party Python packages. Deliberate engine and optional oracle
execution require separately installed dependencies.

```sh
cd app
npm ci --ignore-scripts
npm run build
npm test
npm run preview -- --host 127.0.0.1 --port 4174 --strictPort
```

`npm run preflight` diagnoses source, link, runtime and dependency setup without
writing a build; it also runs automatically during the build. The install needs
registry access or a complete matching npm cache. Node packages
are not vendored. The build emits `dist/client`, `dist/server` and a fresh complete
`dist/client/n170-verify-source.zip` from the exact reviewed inventory in
[`scripts/public-source-inventory.json`](../scripts/public-source-inventory.json).
Historical reports, screenshots and private work material are outside that
public inventory. Complete source includes editable app and toolkit source under
`app/`. The separate `dist/client/n170-verify-toolkit.zip` places `verify_toolkit/`,
`verify_accounting/` and their two test directories at the extraction root. It
also includes `scripts/verify-reconciliation.mjs`, `reconciliation-input.mjs`,
`reconciliation-source.mjs` and `verify-record.mjs` in `scripts/`, the private-source
guide and result schema in `docs/`, and root `LICENSE`/`NOTICE`.
Both ZIPs have detached checksums and
include independent archive verification and metadata. A combined release adds
root documentation and `build.py`, which delegates to this same app build; no
second toolkit copy is placed at the root.

Some tests need retained evidence or separately installed software that is not part of this source, and are skipped without it. At this revision, `npm test` runs 754 tests: 750 pass and 4 are skipped unless `N170_ACCOUNTING_V2_PACKAGE_ROOT` (2 tests), `N170_RUN_REVIEW_PACKAGE_ROOT` (1) or `N170_WALLET_SCOPE_PACKAGE` (1) names a retained package. `python3 -S -m unittest discover -s toolkit-tests` runs 150 tests: 125 pass and 25 are skipped unless `N170_ACCOUNTING_EVIDENCE` names a directory of retained accounting captures. `python3 -m unittest discover -s accounting-tests` runs 51 tests: 48 pass and 3 are skipped unless `N170_BEANCOUNT_PYTHON` names a separately installed pinned oracle interpreter. A skipped test is not a pass; record skips with their conditions.

Maintainers can edit explicitly inventoried source and rebuild with the same
`npm run build`. The build hashes current files into a new manifest rather than
requiring them to match the original immutable receipt. Review and explicitly
inventory any new public source file. Preserve the received ZIP and digest and
retain modified outputs as separate artifacts with new identities. See
[CONTRIBUTING.md](../CONTRIBUTING.md).

## Scope before wider use

The public candidate supports local preparation, disclosed return calculations,
corrections, signing, recipient verification and retained-copy comparison. Tests
use original synthetic inputs. A valid loss is valid evidence. Signed v3/v4
compatibility and documented financial support limits remain required.

The [captured-run contract](../verify_toolkit/RUN_REVIEW_V1.md) defines local byte and
selected-attempt checks. The [private account-reconciliation contract](account-reconciliation-contract.md)
defines source inventories and unresolved interval dependencies. Neither authenticates
producer identity or undisclosed history/account completeness.

The [accounting release guide](accounting-release.md) describes the additive v2
captured-run workflow and combined offline toolkit. Package integrity, detector
outcome, capture support, exact model, native compatibility and supplied optional
oracle evidence remain separate. Six native metrics are `NOT_SUPPLIED`; overall
accounting remains `NOT_ASSESSABLE`, including when supported calculations match.
These are implementation and interpretation boundaries, not a claim of completed
acceptance or a new financial-realism assurance.

The Methods page offers the separate
[68-case private-source challenge](../release-assets/private-source-challenge/README.md).
Its six fixed files are served under `/private-source-challenge/`: instructions,
challenge ZIP, accepted checker ZIP, detached verifier, checksums and acceptance
summary. Follow that unchanged README to reproduce all 68 expected status/exit
pairs, including 31 conditional positive cases. The original result remains 51
raw passes and 17 flags with explicit adjudications; the flags are retained.
No source authenticity, complete-account coverage, investment performance or
outside human review follows from these local results.

The challenge ZIP retains SHA-256
`e7471919bdf7f5b42ab233d6c89c834a2a3f1952fd0aa268a5931a4b53b35f57`
and manifest SHA-256
`5abe3172731422206ac4418f8c0b8f056b2e8b93d85d6d3624c7747549da2c83`.
Its accepted checker and all six delivery files retain their own identities.
Adding these downloads changes the rebuilt app/source archive identity; it does
not re-identify the accepted challenge pack or validate every combined feature.
This local delivery is not publication or outside-user reproduction.

An earlier 175-case challenge kit for the wave2 compatibility-v4 baseline is retained outside this distribution with its original identity. Its documented result remains `INCOMPLETE` / exit `2`; continuity and accounting are excluded, and it is not validation of this combined source.

Further evidence is needed for real broker-produced source compatibility,
authorized personal-account reconciliation, outside-user reproduction, supported
native browser and assistive-technology coverage, hosting header enforcement and
remote repository controls. The proposed [bounded continuity implementation](key-continuity-contract.md)
adds one to four dual-signed device/key transitions while both keys for each
transition remain available. Signed profile segments stay separate. Inherited
key authority does not independently anchor an outgoing history head: each final
outgoing head needs exact independently retained evidence, and root-only retention
in a repeated chain or a retained prefix remains partial. A supplied reference
does not establish when it was retained. This candidate remains under acceptance
review; no completed security audit or release acceptance is claimed.

Lost-key recovery, independent time, authenticated broker acquisition and global
history discovery remain separate unimplemented capabilities. See
[security boundaries](../SECURITY.md).

The AuditZK adapter is original disabled/mock-only code under Apache-2.0.
No upstream implementation or real TEE verification is included. Optional
Freqtrade is separately installed GPL software; its engine is in neither ZIP.
The optional pinned accounting oracle is also installed separately and is not
required for the standard-library package-verification workflow.

A future authorized pilot should measure whether owners reconcile supported
inputs without losing failures, recipients explain the source/identity/time
limits, and retained-copy comparisons reveal the supplied changes. Local automated
checks do not substitute for participants. Publication, deployment, account
access and contacting participants are separate actions, not build steps.
