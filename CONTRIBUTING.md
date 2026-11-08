# Contributing to N170 Verify

An issue tracker, contribution endpoint and private vulnerability-reporting route must be confirmed on the repository before use; this file does not establish that they are available. While
contribution terms are being set up, pull requests are limited to repository
collaborators. Describe proposed fixes through the maintainer's available channel.
Use [SECURITY.md](SECURITY.md) for security reports and never post sensitive
vulnerability details in a public issue.

## Reproduce a problem privately

Use bundled synthetic examples or invented data. Include the source archive hash
or revision, browser/OS versions, steps, expected behavior and actual behavior.
Retain failures and unsupported cases. Do not attach real account files, private
drafts, NAV histories, keys or credentials. A screenshot can disclose private
information too.

## Verify the received archive

Before extracting or editing, obtain `verify_release.py` through a trusted channel
and check the unchanged archive against a separately retained digest:

```sh
python3 verify_release.py source.zip --sha256 EXPECTED_ARCHIVE_SHA256
```

Replace the archive name and digest with the received values. The independent
verifier checks archive bytes and inventory without extraction. Keep that archive
and receipt. Hash equality does not authenticate the publisher or certify the code.

## Edit and rebuild

Extract into a new directory. Commands below run in the app folder containing
`package.json`; source archives place it at `app/`. Use Node satisfying
`^20.19.0 || >=22.12.0`, npm and Python 3. No Python package installation is needed.

```sh
cd app
npm ci --ignore-scripts
npm run build
npm test
npm run dev
```

`npm run preflight` checks source inventory, local links, runtime and installed
dependencies without writing a build. The ordinary build runs it automatically.
Installation uses the exact lockfile and disables install scripts. It requires
network access unless the needed packages are already cached. For production
preview, stop the development server and run
`npm run preview -- --host 127.0.0.1 --port 4174 --strictPort`.

`npm run build` is the ordinary public build. It uses
[`scripts/public-source-inventory.json`](scripts/public-source-inventory.json),
checks supported paths and regular files, and creates a fresh source archive in
`dist/client/n170-verify-source.zip` with hashes of the selected current files.
When adding a file intended for distribution, review it and update this exact
inventory. Do not add private inputs, historical evidence dumps or local secrets.

An edited source file is expected to differ from the original immutable
`MANIFEST.json`. Maintainer builds do not require it to match that receipt. Retain
the newly generated ZIP and manifest under their new identity; do not overwrite
the original archive, change its receipt, or claim the edited result has the old
hash. The combined release root `python3 build.py` delegates to the same ordinary
app build after dependencies are installed in `app/`.

Keep format and calculation compatibility tests when changing relevant behavior.
Use original synthetic examples; report exact failures, limitations and skipped
checks. Optional browser harnesses need an existing Playwright runtime and browser
binaries. See [README.md](README.md) and
[validation scope](docs/release-validation.md) for commands and boundaries.

## License

Original N170 code is licensed under [Apache-2.0](LICENSE), with [NOTICE](NOTICE).
Preserve dependency notices and component license boundaries. AuditZK's original
mock interface does not include or grant rights to upstream implementation code.
