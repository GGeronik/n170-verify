# Local import and reconciliation

14 September 2026 · Import rules `n170.import.v1`

The first complete path is an **IBKR Activity Flex Change in NAV CSV**, followed by explicit local reconciliation. N170 also accepts its own three-column NAV/flow template. Trading 212 transaction exports and Portfolio Performance asset-chart exports are recognized with precise missing-data guidance; these are **not complete performance importers**. No broker account connection is implemented and no uploaded file is broker authenticated.

## IBKR configuration and support contract

In Client Portal, create an Activity Flex query containing **only Change in NAV**. Choose CSV, enable column headers, disable head/trailer records and section codes/line descriptors. Choose ISO `YYYY-MM-DD` or compact `YYYYMMDD` dates. Select one account and no model filter. Choose one P&L mode. Export adjacent daily or longer statement periods without overlaps. The importer accepts one table, including quoted CSV, UTF-8 BOM and CRLF.

Required fields: `Account ID`, `From Date`, `To Date`, `Starting Value`, `Ending Value`, `Deposits/Withdrawals`, `Internal Cash Transfers`, `Asset Transfers`, `Linking Adjustments`, `Other`. Include every populated financial component from the statement so the NAV bridge reconciles. Column matching ignores punctuation, spaces and case. Unmapped fields fail closed. A missing value is not zero. Select the account's base currency in N170 because this section need not contain it. [IBKR field reference](https://ibkrguides.com/reportingreference/reportguide/changeinnav_fq.htm), [IBKR export configuration](https://www.ibkrguides.com/reportingreference/reportguide/delivery%20configuration%20and%20general%20configuration.htm).

For each statement:

- The initial value becomes the opening observation, dated at the prior calendar-day close because the report's start date is inclusive. This derivation is displayed.
- The report end becomes the closing observation. A following statement must start the next day and its opening NAV must equal the previous closing NAV exactly.
- Deposits/withdrawals map to external flow; gains, dividends, interest, fees, taxes and FX components remain reflected in NAV. Starting NAV plus the supplied component amounts must equal ending NAV in exact decimal arithmetic. An unreconciled rounding difference is surfaced rather than hidden.
- Nonzero asset transfers, internal cash transfers, linking adjustments, vague `Other` changes and model-specific scope are unsupported. Different currencies/accounts, absent fields, duplicate rows, discontinuities and overlapping/missing periods block calculation.
- **The flow field is netted.** Even zero can hide offsetting deposits and withdrawals. Every IBKR import requires the owner's cash-activity review: no offsetting flows are hidden and any external flow really occurred at interval end. A checkbox records this assertion; it does not independently prove it. Otherwise obtain valuations immediately around the flows and reconcile a separately explained N170 observation series.

This is a bounded statement-boundary method, not a reproduction of IBKR's own TWR. IBKR may use more frequent valuations or different flow timing. One monthly statement supports one interval: its drawdown observes only its endpoints and annualized volatility is unavailable. More statements improve sampling but do not establish all accounts were disclosed.

## Supported breadth

| Input | Implemented | Missing evidence / next step |
| --- | --- | --- |
| IBKR configured Change in NAV CSV | Mapping, decimal NAV bridge, account/currency/scope checks, explicit flow review, exceptions, normalization, source correction chain | Real authorized broker-produced fixtures and version variance remain pilot prerequisites. Synthetic fixture is clearly labeled. |
| N170 `date,nav,external_flow` CSV | Dated NAV/flow validation and calculation handoff | Owner supplies all values, currency, scope and interval-end cash-flow treatment. |
| Trading 212 history CSV | Detects activity-style `Action`, `Time`, `Total` columns and blocks return calculation | Trading history is not a full portfolio-value series. Obtain account-value statements and flows; never use trade proceeds or cash alone as NAV. |
| Portfolio Performance assets chart CSV | Detects common English assets-chart columns and blocks return calculation | Pair the same-scope values with all external flows. PP's beginning-day inflow convention cannot silently become N170's end-flow convention. Localized and custom-series labels may require explicit format selection. |
| Arbitrary PDF, image, XML or other broker exports | Not imported | No OCR guessing, invented valuations or simulated connector. Obtain documented CSV with necessary observations. |

Trading 212 documents separate trading CSV and account-value statements; the latter can contain identifying details. Portfolio Performance documents chart CSV and transaction exports separately. [Trading 212 documents](https://helpcentre.trading212.com/hc/en-us/articles/11700508002845-What-documents-can-I-get-from-Trading-212), [PP chart export](https://help.portfolio-performance.info/en/reference/view/reports/statement/statement-chart/), [PP export](https://help.portfolio-performance.info/en/reference/file/export/).

## Correction, privacy and review

`importStatement(text, options)` returns `normalizedCsv`, `rows`, explicit `mapping`, actionable `exceptions`, `canCalculate`, `source`, `coverage` and `review`. `canCalculate` means no importer blocker; calculation range/support rules still apply. All raw values remain local working material. No network request is used to import.

`correctImport(previous, correctedSource, reason, options)` reprocesses the entire replacement source. It preserves the original hash and every before/after source and normalized hash, reason and device-clock time. It cannot bypass a missing period or unsupported event. Corrections of already signed records must use the application's appended correction-record workflow; reimport does not edit a historical signature.

SHA-256 hashes bind the UTF-8 text as supplied before parsing, **not an assertion of broker origin**. Browser file decoding is outside this function, so the digest is not claimed to be a byte-identical fingerprint of arbitrary original encodings. Retain the UTF-8 source text privately to reproduce it. A digest can be linkable and is not an anonymization guarantee.

`importDisclosure(review)` returns a bounded diagnostic summary identified as `n170.import-disclosure.v2`. It retains only supported format/version/currency enums, validated lowercase SHA-256 strings, bounded source/observation/correction counts, correction hash links, importer status and fixed issue descriptions. Account labels, coverage dates, filenames, mapping text, correction reasons/times and arbitrary exception messages/actions/paths are omitted. Invalid digest/count values become `null`; unknown enums use fixed fallbacks. Excessive or missing correction collections require review. `raw_values_included:false` and `free_text_included:false` mean no source amounts or source-provided free text are copied; fixed product descriptions are still present. The summary does not replace a reproducible signed record or validate an arbitrary caller's review object. Its status reports importer readiness for owner review, never broker authentication.

`safeIssueSummaries(issues)` supplies only deduplicated fixed `{code,severity,message,action}` entries for known importer and handoff issues. Raw messages, actions, paths, unknown code text and other metadata are never copied. Unknown/malformed issues become a fixed `needs_review` error. At most 10,000 issue entries are inspected; longer collections also produce `needs_review` so incomplete diagnostics are explicit. Severity comes from the catalog; the shared cash-activity-review code preserves its existing error/warning contexts, with an error winning duplicates. This helper supports privacy-conscious copy/repair guidance, while source-specific details remain available only in the private local review. It does not invent missing values, waive owner review or change calculation decisions.

Counts and digests can still reveal or link workflow information; this is not anonymization. The separate signed-record workflow may include owner-written correction reasons after explicit review, so those explanations must be checked for sensitive details before sharing. Exported relative returns also reveal a performance pattern. A recipient can recompute signed return-series metrics but cannot independently reconstruct NAV-to-return transformation without a separately authorized disclosure of the source.

CSV support: at most 2,000,000 JavaScript characters, 5,000 source rows, 500 normalized observations, 18 fractional decimal places. The calculator may have stricter documented magnitude/precision limits. No silent deduplication, sorting, currency conversion, missing-value filling, statement authenticating or flow classification by AI occurs.

## Fixtures and verification

`tests/fixtures/import/ibkr-flex-synthetic.csv` and exported `ibkrSampleInput` are synthetic and match the documented query configuration; they are not captured broker files. The independent no-flow control is `10200 / 10000 - 1 = 0.02` before return-series rounding. Tests exercise exact large-decimal cancellation, reconciliation failure, missing periods, duplicate rows, account/currency mismatch, flow timing including net-zero, malformed CSV, unsupported sources and persistent correction digests. In the app folder containing `package.json` (`cd app` from the complete source or combined release root), run `node --test tests/importer.test.mjs tests/import-disclosure.test.mjs tests/safe-issues.test.mjs`. The disclosure regressions include raw-value parser errors, hostile column names, arbitrary nested metadata, unknown issue codes, correction reasons, bounded digests/counts and unchanged legitimate summaries.

Pilot exit gate: obtain one explicitly authorized, redacted real export for this precise configuration and verify mapping against the owner's visible statement, including a zero-flow period, fees/dividends, netted offsetting flows and an unsupported event. Until then the adapter is a documented-format implementation with synthetic conformance tests, not a claim of broad real-world IBKR compatibility.

## Assistant / broker MCP handoff

The preparation screen also accepts `n170.agent-handoff.v1` JSON from an assistant with already authorized broker access. The [contract](agent-handoff.md) carries dated decimal NAV/flow observations, private field references, declared scope and explicit missing-evidence states. It is supplied-data evidence, not a broker-authenticated format. Its source data must pass deterministic checks and fresh owner review; an imported private draft cannot carry an external review flag into this session. Browser-saved drafts retain their own review state. No fields are inferred.


## Currency consistency

IBKR imports now require every explicit Currency/Base Currency cell to be nonempty and consistent with all other rows and the selected reporting currency. A disagreement blocks calculation/provenance rather than silently choosing a field. When neither currency column exists, the explicit owner choice remains supported with the existing assumption warning. No FX conversion or source authenticity follows. See [public validation scope and reproduction](release-validation.md). That guide describes the release scope and does not include historical research logs. Existing signed records keep their original rules.
