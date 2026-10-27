# Evidence and research decisions

This public note describes the boundaries of this local release candidate. It
does not reproduce the historical internal research reports referenced by earlier
versions of the app.

The browser workflow helps an owner reconcile supplied portfolio observations,
retain corrections, sign the disclosed relative returns, and give a reviewer a
portable copy. A valid negative return is valid evidence; positive performance
is not a condition for passing arithmetic and signature checks.

The supported decimal amounts, end-of-interval external flows, rounded return
series and versioned metrics are specified in [financial methods](methods.md)
and [record format](../FORMAT.md). The separate command-line verifier recomputes
the disclosed evidence using Node's standard cryptography and its own arithmetic
implementation. Verify the received source bytes before extraction or editing and follow the
[release guide](release-readiness.md). A maintainer build creates a new artifact
from edited, explicitly inventoried code and does not reuse the original receipt.

Supplied files, tool labels, owner assertions, hashes and signing keys do not
authenticate brokers, live trading, account ownership, identity, complete
coverage, investment skill or the time of publication. A retained earlier copy
can reveal a changed supplied history, but cannot discover every hidden branch.

The original toolkit interprets bounded external-engine evidence. Parsing a
Freqtrade CSV is distinct from running the real detector; a no-finding row does
not establish freshness, untriggered-signal coverage or feasible execution. The
GPL engine remains separately installed. Real-engine results require independently
identified code, inputs, configuration and complete run accounting.

The [captured-run review contract](../verify_toolkit/RUN_REVIEW_V1.md) checks supplied
artifact bytes and selected-attempt relationships without executing code. The
[private reconciliation contract](account-reconciliation-contract.md) retains
source attempts, unresolved intervals and their input dependencies. Neither
establishes unknown attempt/account completeness. Original toolkit source and
tests ship with the app inside `app/`, and a separate toolkit ZIP supports local
CLI use without the browser build or an execution engine.

AuditZK is a collaboration candidate. No upstream implementation is
part of this cut. The included original disabled/mock interface does not constitute
real integration or confidential-computing attestation.

Use [release status](release-readiness.md) and [validation scope](release-validation.md)
to interpret this artifact. Actual-account reconciliation, an outside participant
reproducing the result and user-completion studies require separate evidence.
