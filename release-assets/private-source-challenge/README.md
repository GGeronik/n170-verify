# N170 Verify private-source challenge pack

Prepared and locally accepted on 27 September 2026. This package lets another reviewer reproduce the existing 68 synthetic source-checker cases without internal working folders, npm installation or a financial engine. It has not been published or reproduced by an outside person.

The new execution reproduced all 68 expected status/exit pairs and all 204 case output/receipt files. The original result remains **51 raw passes and 17 flags**, with the same explicit adjudication of those flags. There are 31 conditional positive cases; success does not authenticate a broker, prove complete account coverage or establish investment performance.

## Files

- [Challenge pack](n170-private-source-challenge-v1.zip): unchanged synthetic inputs, expectations, historical raw results, adjudication, provenance and portable harnesses.
- [Detached data verifier](verify_pack.py): inspect it and compare its hash before use.
- [Accepted offline toolkit](accepted-offline-toolkit.zip): the exact released checker; the runner uses only four pinned modules.
- [File checksums](SHA256SUMS): compare these against the independently supplied release identities.
- [Release identity and result summary](RELEASE.json).

Only these selected public artifacts are intended for distribution. The main working repository and private review evidence are not part of this package. Historical candidate labels inside the immutable ZIP describe its preparation state; acceptance is recorded separately here without rewriting the frozen archive.

## Reproduce

On Linux or macOS, use Python 3.9 or newer and Node `^20.19.0 || >=22.12.0`. Place the three downloads above together. First compare `verify_pack.py` with SHA-256 `2eda69531c3c079f71e1bbfb9e6dc3a6683deddd3bdab7e3ca0b2bcf45e75d72`. Then use new output directories:

```sh
python3 -B verify_pack.py \
  --archive n170-private-source-challenge-v1.zip \
  --archive-sha256 e7471919bdf7f5b42ab233d6c89c834a2a3f1952fd0aa268a5931a4b53b35f57 \
  --manifest-sha256 5abe3172731422206ac4418f8c0b8f056b2e8b93d85d6d3624c7747549da2c83 \
  --destination "$PWD/challenge-pack"

python3 -B challenge-pack/run_challenge.py \
  --toolkit-zip accepted-offline-toolkit.zip \
  --manifest-sha256 5abe3172731422206ac4418f8c0b8f056b2e8b93d85d6d3624c7747549da2c83 \
  --output "$PWD/challenge-run-001"
```

The expected outer result is exit 0 with `raw_passed: 51`, `raw_flagged: 17`, `status_and_exit_matches: 68` and `unresolved_cases: 0`. The original 60-case harness still records exit 1 because its 17 flags remain present. The wrapper accepts those historical adjudications only when every case's stdout, stderr and receipt match exactly. Keep unsuccessful attempts and inspect their reports before any retry.

Read the extracted README for scope, original-manifest mappings and the complete privacy review. JSON and HTML fixtures must be read as data; do not render the test HTML. Private-key fixture builders are excluded. No actual personal-account material is included. This is a finite engineering challenge, independently reviewed by AI agents and rerun on the same machine, not an outside human audit.
