# Primary references and reuse boundary

Research and local implementation assessment: 18 September 2026. Exact revisions
below identify the inspected source; none is a claim about authenticated investment
results. Original N170 source in this directory is under the repository's Apache
2.0 license. No third-party implementation was copied here. Synthetic fixtures and
generated interchange files are original. Third-party engines are separately
licensed dependencies; their license conditions are not replaced by N170's license.

## Selected independent engine: Beancount

Pinned revision: `9747213802acb733ce53acc6e963f5961f47d6cd`; actual installed version:
**3.2.3**, local Python **3.12.13**, macOS arm64. The inspected
[project metadata](https://github.com/beancount/beancount/blob/9747213802acb733ce53acc6e963f5961f47d6cd/pyproject.toml)
declares `GPL-2.0-only` and Python >=3.9. The source was built and installed in a
separate temporary environment, not vendored into or installed globally by N170.

- [Language syntax](https://beancount.github.io/docs/beancount_language_syntax/):
  posting costs, prices, inventory booking and balance assertions.
- [FIFO booking implementation](https://github.com/beancount/beancount/blob/9747213802acb733ce53acc6e963f5961f47d6cd/beancount/parser/booking_method.py):
  reference checked for independent acquisition selection and same-date ordering.
- [Validation](https://github.com/beancount/beancount/blob/9747213802acb733ce53acc6e963f5961f47d6cd/beancount/ops/validation.py)
  and [checker entry point](https://github.com/beancount/beancount/blob/9747213802acb733ce53acc6e963f5961f47d6cd/beancount/scripts/check.py):
  actual loader validation plus HARDCORE_VALIDATIONS is executed.
- [Balance assertions](https://github.com/beancount/beancount/blob/9747213802acb733ce53acc6e963f5961f47d6cd/beancount/ops/balance.py)
  and [parser options](https://github.com/beancount/beancount/blob/9747213802acb733ce53acc6e963f5961f47d6cd/beancount/parser/options.py):
  explicit zero assertion tolerance and zero inferred tolerance multiplier.
- [Loader](https://github.com/beancount/beancount/blob/9747213802acb733ce53acc6e963f5961f47d6cd/beancount/loader.py):
  cache disabled and no input-controlled include/plugin directives admitted.

Observed source archive SHA-256:
`e37dd47e6ae7540db448e8f82b4302f996ca01a71aa0d6e0befc5f05c58ea686`.
Observed built wheel SHA-256:
`7317d6c4c81a37d7b307e0020bc357041d95a601018baf51b6b099e9e26ad632`.
The latter identifies this local build, not a reproducibility guarantee. Runtime
package identities, installation metadata and a complete Beancount Python/native
code inventory are retained with actual oracle execution evidence. The installed
code inventory digest was
`e8613933996e605176913722520851dc65b61f479a94f5da0589facb9a829bc9`.

## Considered capabilities, not executed by this accounting slice

- **QuantConnect LEAN:** inspected revision
  `f78c35d7c88c3ea0be9fbd1aeabce3d4ee2347f5`,
  [Apache 2.0 license](https://github.com/QuantConnect/Lean/blob/f78c35d7c88c3ea0be9fbd1aeabce3d4ee2347f5/LICENSE).
  A full execution comparison still needs N170's explicit fill, ordering, valuation
  and cost overrides in `docs/reproducibility-research/03-execution-contract.md`.
  This work neither executes LEAN nor supplies rights to third-party market data.
- **Portfolio Performance:** inspected revision
  `11ca09c1d4add1f7725fc015549464f66801cb18`,
  [EPL 1.0 license](https://github.com/portfolio-performance/portfolio/blob/11ca09c1d4add1f7725fc015549464f66801cb18/LICENSE),
  [ClientIndex calculations](https://github.com/portfolio-performance/portfolio/blob/11ca09c1d4add1f7725fc015549464f66801cb18/name.abuchen.portfolio/src/name/abuchen/portfolio/snapshot/ClientIndex.java).
  Its observed daily-flow convention places incoming flow at the start and outgoing
  flow at the end; compatibility with a uniform end-of-interval convention cannot
  be assumed. No PP algorithm or implementation was imported.
- **OpenTimestamps client:** inspected revision
  `cd71c7609421bed2a07b9642a3c02a58c9fd2cdf`,
  [repository and license](https://github.com/opentimestamps/opentimestamps-client/tree/cd71c7609421bed2a07b9642a3c02a58c9fd2cdf).
  Useful later for a preexisting digest, not accounting truth. The reference client
  verifies confirmed Bitcoin attestations with Bitcoin Core. Pending calendar
  receipts must not be presented as confirmed blockchain timestamps. Neither the
  client nor Bitcoin Core was installed or executed for this slice.

These references guided contract choices. Availability of source, compatible data
formats or permissive licensing is distinct from demonstrated independent execution.
