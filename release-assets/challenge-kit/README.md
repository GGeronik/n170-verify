# N170 portable challenge kit — local candidate

The ZIP contains the accepted app/toolkit source, all 175 original challenge
cases and harnesses, six calculation probes, and unchanged fresh synthetic
receipt inputs. No publication has been performed.

Retain these identities through a trusted channel. This file and a verifier
received beside an untrusted archive cannot authenticate their own publisher.

- ZIP SHA-256: `5802a438f08afdad9e1d74d7ee9f1ab03b86a059e9d77bb30ea977148c9a0a22`
- Standalone verifier SHA-256: `0fb1cd2bd5da6ec6b8f809121ab76219ac36560a2d7cfca056c03eaab5c6fda1`
- ZIP: 4,979,175 bytes, 180 payload files plus its exact inventory.

From a directory containing these files, with Python 3.11+ and Node 22.12+:

```sh
python3 -B verify_archive.py public-challenge-kit.zip \
  --expected-sha256 5802a438f08afdad9e1d74d7ee9f1ab03b86a059e9d77bb30ea977148c9a0a22 \
  --extract challenge-kit
cd challenge-kit
python3 -B prepare_source.py --output ../accepted-source
python3 -B run_challenges.py --source ../accepted-source \
  --receipts receipts \
  --receipt-freeze-sha256 f510104c165d61705472197ad5b21a765d180071410b4392a1ca430b81707ec7 \
  --output ../challenge-results
```

Output directories must be new. The documented run returns exit `2` /
`INCOMPLETE` with no scored failures because separate engine and public-build
challenges remain unrun; unsupported operations remain explicit. Read
`../challenge-results/report.json` and the kit README for the receipt-free workflow,
case meanings, self-tests, scope and unexecuted Go recipe. No default command
fetches dependencies, executes an engine, connects a broker or publishes files.

Validation is AI agent engineering work, not an external audit or a real-market
performance study. The receipt inputs record eight executions of four synthetic
controls; repeats do not establish general detection accuracy.
