# Optional AuditZK interface: synthetic contract exercise

This app contains an original Apache-2.0 interface in
[`src/auditZkAdapter.js`](../src/auditZkAdapter.js). It contains **no AuditZK
implementation, real TEE verification, provider retrieval, credentials, network
calls or account calculations**. It is not wired into the performance-report UI
or signing code. An AuditZK collaboration is a candidate, not an available app
integration. The default adapter returns `unavailable`.

The useful deliverable here is a bounded contract for capability discovery,
missing prerequisites, simulated verification failures and source-claim handling.
Mock success is always `mock-checks-passed`, never `verified`. All results carry
`synthetic: true`, a prominent `SYNTHETIC MOCK ONLY` limitation, and explicit false
values for real attestation, report signature, report digest, source binding and
financial verification. Source authenticity, freshness and completeness remain
`unknown` in every case. A provider API label is retained as a supplied claim; it
does not authenticate a provider or account.

## Run the original contract cases

Run in the app folder containing `package.json` (`cd app` from either source
archive root), using the Node version supported by that file:

```sh
node --test tests/auditzk-adapter.test.mjs
```

This focused suite covers disabled
capabilities, six distinct failed checks, missing prerequisites, unsupported
formats, verifier failure, supplied-file and provider claims, immutable snapshots,
malformed contracts, unsupported versions, excess fields, credential-field
rejection, getters/prototypes/symbols, absence of fetch calls and the pending grant
inventory. Running this suite is a synthetic contract check, not external review or
evidence of AuditZK/AMD verification. No live report or enclave was exercised.

## Interface and example

`auditZkCapabilities()` returns a frozen descriptor. Real integration is unavailable,
and the descriptor names the six prerequisites and eight mock scenarios. The
request and result schema names are N170-owned; they do not claim compatibility
with an AuditZK wire format. Passing a real upstream response directly is an error.

`createAuditZkAdapter()` returns the disabled implementation.
`createAuditZkAdapter({ mode: "mock", scenario, prerequisites })` requires an
explicit scenario and explicit booleans for every prerequisite. These booleans
simulate presence only. They do not establish that any evidence is valid or that
a real deployment is ready. Changing the options after construction does not
change the adapter. `verify(request)` returns a promise of a frozen result and
snapshots accepted request values before returning it.

```js
import {
  AUDITZK_REQUEST_VERSION,
  auditZkCapabilities,
  createAuditZkAdapter,
} from "./src/auditZkAdapter.js";

const prerequisites = Object.fromEntries(
  auditZkCapabilities().prerequisiteNames.map((name) => [name, true]),
);
const adapter = createAuditZkAdapter({
  mode: "mock",
  scenario: "invalid-signature",
  prerequisites,
});
const result = await adapter.verify({
  schema: AUDITZK_REQUEST_VERSION,
  synthetic: true,
  reportSha256: "ab".repeat(32), // Synthetic declared identifier, not a checked digest.
  attestationFormat: "amd-sev-snp",
  sourceClaim: {
    kind: "provider-api",
    provider: "Synthetic Broker",
    accountScope: "Synthetic account A only",
    periodStart: "2026-01-01",
    periodEnd: "2026-01-31",
  },
});
console.log(result.status); // mock-check-failed
console.log(result.sourceAuthenticity); // unknown
console.log(result.realAttestationVerified); // false
```

Only exact object shapes, exact schema versions, `synthetic: true`, lowercase
64-character declared SHA-256 strings, recognized source kinds/formats and valid
ordered ISO dates are accepted. Provider and account-scope strings are bounded at
200 characters each. Accessors, extra fields, inherited class instances and
symbol keys are rejected. Text labels are data: a future UI must render them as
text, never HTML. This API consumes local plain objects and is not a JSON/file
importer; no serialized-input acceptance is advertised. It cannot accept report
bytes or secrets, so it cannot authenticate their declared digest or source.

| Result status | Meaning |
| --- | --- |
| `unavailable` | Default disabled mode. No checks run. |
| `unsupported-format` | Mock request declares an unknown format. No checks run. |
| `prerequisites-missing` | At least one simulated prerequisite is absent. All absent names are retained; no checks run. |
| `mock-verifier-error` | Explicitly simulated internal verification failure. No check is marked passing. |
| `mock-check-failed` | The selected simulated check fails. Other mock results remain visibly simulated. |
| `mock-checks-passed` | All synthetic fixture checks pass. Nothing about a real report is verified. |

The separately reported mock checks are endorsement chain, measurement, freshness,
report signature, report binding and source binding. They are **selected outcomes**,
not computed cryptographic checks. A real implementation must define its checks
and failure propagation against actual supported evidence; it cannot reuse these
booleans as verification results.

## Prerequisites for any future real integration

The mock contract has a slot for each of: a pinned code/measurement policy,
attestation report plus endorsements, a freshness/challenge policy, report bytes
plus signature, a binding between the attested environment and report signing key,
and declared source/scope binding. Before implementing a real verifier, resolve
the actual report serialization/signing domain, supported hardware evidence
version, trust roots and endorsement policy, reproducible measurement mapping,
challenge/replay and time rules, error behavior, and what the measured code proves
about acquisition, identity, period and coverage. These are N170 design requirements,
not a claim that the public documentation supplies or satisfies them. A valid
signature with a supplied key alone must never be promoted to hardware-attested
execution or authenticated account coverage.

Financial values and signed N170 records remain separate. Even a future supported
attestation must describe its exact claim scope and cannot establish unreported
accounts or periods merely by passing an integrity check. Real provider and user
validation remain unmet. Any future implementation needs its own tests, review
and threat model; the present mock cannot activate it.

## License inventory and public references

[`auditzk-license-inventory.json`](auditzk-license-inventory.json) reserves the
written grant path/digest, issuer/date, exact repository/revision/components and
file inventory, use/modification/source and binary redistribution permissions,
downstream modification/self-hosting/redistribution rights, required notices and
component license. All grant rights remain `pending`. An exact applicable MIT
revision can be evaluated if identified; none is asserted here. No upstream
implementation code was copied, so no upstream code is included by this adapter.
The original N170 files use the app's Apache-2.0 license. The inventory does not
relicense any future upstream component or treat an owner-reported forthcoming
grant as a grant already received.

Public primary documentation read on 18 September 2026:

- [AuditZK enclave audit guide](https://www.auditzk.com/audit) describes an
  attestation endpoint, AMD signature verification and measurement comparison.
  Those are distinct evidence stages, not a reason to trust an endpoint's own
  `verified` flag. The guide's live repository/reference is not treated here as
  an immutable implementation or license inventory.
- [AuditZK report verification page](https://www.auditzk.com/verify) describes
  ECDSA P-256 report signatures, report hash/key inputs and client-side checking.
  This adapter does not implement that format or adopt the page's broader
  authenticity claims as verified facts.
- [AuditZK architecture page](https://www.auditzk.com/trustless) presents its
  confidential-computing claims. This work did not independently evaluate those
  claims.
- The coordinated project direction identifies the public license at
  [tee-aggregator revision e3924317ae3c82ee899f706d2399a18162ec11b5](https://github.com/AuditZK/tee-aggregator/blob/e3924317ae3c82ee899f706d2399a18162ec11b5/LICENSE).
  The pinned source/README/license fetches were unavailable during this adapter
  task. No fresh source/license inspection or permission conclusion is claimed.

The mock interface is original and intentionally narrower than the referenced
product claims. Receipt of the grant is not required to use the separate local
performance and tool-observation workflows.
