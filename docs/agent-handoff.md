# Assistant and broker-MCP handoff

Version `n170.agent-handoff.v1` · 14 September 2026. This is a local interchange contract for **supplied data prepared by an assistant**. It is not an authenticated broker connector, an MCP extension, a financial-data attestation or permission to access an account.

Use the [copyable assistant instructions](agent-instructions.txt) only with an already connected source and the owner's explicit account-scope/date-range authorization. [`llms.txt`](../llms.txt) follows the [llms.txt proposal](https://llmstxt.org/), a voluntary discovery convention, not a formal standard or an enforcement mechanism. An assistant may ignore it. The parser and owner review remain necessary.

## Use the visible prompt

In **Prepare a record**, **Ask your AI** is the default entry, beside **Import a file**. No new connection or setup is created in Verify.

1. Read the prompt under **Copy this prompt to your AI**. **Copy prompt**, **Select prompt** and **Download prompt** use the exact same visible text: a friendly introduction followed by the complete instructions and file format. Paste it into the assistant where your broker is already connected; it asks for the selected account scope, dates and currency if those are missing.
2. Under **Bring its answer back here**, choose **Choose AI file** or use **Or paste your AI’s reply**, then **Review my record**. The pasted reply may be plain JSON or one complete JSON/unlabelled Markdown code block. The application removes only that wrapper and preserves the exact inner source text, including decimal tokens and whitespace. Surrounding prose, multiple blocks and incomplete wrappers are rejected with a next action; the underlying JSON/schema checks remain strict. Files and the CLI still require JSON directly.
3. Review the actual observations, source claims and exceptions in **Reconciliation** before approving the source and proceeding to calculation/signing. Loading a source collapses the prompt and focuses reconciliation. Switching the **Ask your AI** / **Import a file** entry preserves the working draft and pasted reply.

If clipboard access fails, the full prompt is selected for ordinary copying; download is another option. The visible textbox contains all instructions, including the contract, so a remote assistant does not need repository access. [Public validation scope and reproduction](release-validation.md) describes the checks to run and their limits. Historical browser captures and execution logs are not included in this public archive.

## Workflow and authority

1. The owner authorizes read-only access to a specific account scope and date range in the assistant's existing connected environment. N170 Verify requests no credentials and establishes no connection.
2. The assistant inspects actual available tool schemas and provider documentation, then uses only documented nonmutating operations. It does not infer permission from an installed plugin or MCP `readOnlyHint`, discover every account, guess tools, modify settings, place/cancel orders or transfer funds. The [MCP specification](https://modelcontextprotocol.io/specification/2026-07-28/schema#toolannotations) defines annotations as hints whose trust depends on the server; they are not authorization enforcement.
3. It gathers actual total portfolio NAV and gross external flow activity with matching coverage, observes all required pagination termination conditions and preserves valuation-date semantics. Missing data produces a blocked packet; it is never invented.
4. The local parser deterministically validates the packet and checks calculation support. The optional CLI emits a small status/count summary by default. It never signs, saves browser data, calls financial tools or uploads anything.
5. The owner imports the JSON into N170 Verify, reviews source mappings, observations, cash-flow treatment, scope and warnings, and explicitly approves any later signing. A machine result of `ready_for_owner_review` is not owner approval or verification of the source.

An assistant-mediated tool result can be selected, altered or fabricated before it reaches this application. Broker/connector/tool labels, private field paths and completion assertions are sender claims. No tool result signature, broker-side attestation, live/paper status or independent timestamp is established by this format. Raw connector results may be retained privately outside N170 Verify only when the owner authorizes it. Do not include them or secrets in the packet.

## JSON contract

The [machine-readable JSON Schema](../schemas/agent-handoff-v1.schema.json) supports structural tooling; the application parser additionally enforces cross-field and calculation checks. Use exactly these keys; unknown keys are rejected. Numbers representing money are **strings**, not JSON numeric values. The complete structural bounds are enforced in [`src/agentHandoff.js`](../src/agentHandoff.js); calculation bounds are in [methods.md](methods.md). The CLI accepts at most 1,000,000 UTF-8 input bytes and rejects invalid UTF-8 instead of substituting characters; the application additionally enforces its own bounded input rules.

| Field | Shape and interpretation |
| --- | --- |
| `schema_version` | Exactly `n170.agent-handoff.v1` |
| `synthetic` | Boolean. True explicitly identifies demonstration data. False is still an unchecked sender claim about real data. |
| `source` | `{broker,connector,tools,retrieved_at}`. Broker and connector labels, 0–40 unique actually called tool-name strings (1–80 characters), and a sender-reported ISO retrieval timestamp with timezone or `null` when no retrieval occurred. Labels use 1–80 characters; no credentials. |
| `account_scope` | Public alias of 1–160 visible characters describing only the owner-authorized account scope. No account number. |
| `currency` | One of `USD`, `EUR`, `GBP`, `CHF`, `CAD`, `AUD`, `JPY`. No automatic FX conversion. |
| `frequency` | One of `252`, `365`, `52`, `12`, `4`, `1`. It selects a documented observation schedule; it does not override date checks. |
| `requested_period` | `{start,end}` as actual requested ISO calendar dates; start on or before end. |
| `coverage` | `{pagination,missing_periods,unsupported_events}`. Pagination is `complete`, `incomplete` or `unknown`; up to 100 missing periods are `{start,end,reason}` with a 1–300 character reason; up to 100 unsupported events are explanatory strings of 1–300 characters. |
| `flow_timing` | `interval_end`, `intraperiod` or `unknown`. End timing is a sender assertion requiring owner review of gross activity. |
| `observations` | 0–500 `{date,nav,external_flow,source_ref}` objects. Dates strictly ascend. Amount strings use ≤50 characters, plain decimals, magnitude ≤10¹⁵ and ≤18 fractional places. Source references use 1–240 visible characters and are private field paths/navigation aids, not attestations. |
| `mapping` | `{date,nav,external_flow}` with sender-provided source field paths of 1–120 visible characters. Owner review must confirm financial meaning and valuation timing. |

At least two actual observations are required to become ready for review. The opening external flow must be zero because it establishes the starting NAV; an earlier genuine valuation is needed to measure an opening flow. The first/last observed valuation dates must match the requested period. Absent retrieval (`retrieved_at:null` or `tools:[]`), unknown/incomplete pagination, missing periods, unsupported events and non-end flow timing block readiness. Deterministic financial support failures also block readiness, including total loss, unsupported precision/wealth ranges and invalid flow treatment.

The `complete` pagination value means the sender says documented termination was observed. The application cannot independently confirm that all pages, accounts or source datasets were retrieved. `retrieved_at` is never independent time evidence. Use `null` with `tools:[]` when no retrieval occurred; do not invent a timestamp to make a blocked packet fit. Source metadata and private row references are retained in the private handoff/draft, while any public performance record uses bounded supplied-data provenance and generic observation mappings rather than copying private tool-result paths.

A complete, explicitly [synthetic packet](../examples/agent-handoff-synthetic.json) is included for parser testing. The [copyable instructions](agent-instructions.txt) contain the full contract and an inline example, so a remote assistant does not require repository access. Synthetic retrieval labels are illustrations, not real tool calls.

## Financial mapping requirements

NAV means the total value of the declared portfolio scope, including its cash and investments as valued by the actual source. A cash balance, trading proceeds, a list of trades or reported trade P/L cannot substitute for a complete valuation series. Keep internal trades and retained dividends inside performance; do not classify them as external contributions. Fees/taxes affect the supplied NAV only as represented by the source.

Inspect gross deposit/withdrawal activity, including offsetting flows. A zero net cash-flow field is not evidence of no activity. The method requires actual valuations at flow boundaries; without them, mark timing unknown/intraperiod and return a blocked packet. This date-only format cannot represent multiple valuations within one day; keep that case unsupported rather than relabeling observation dates. Do not convert missing flow fields to zero.

Check provider-specific timestamp semantics against current documentation. Some portfolio-history APIs label a window's start while the equity belongs to its end. In particular, [Alpaca’s portfolio-history model](https://alpaca.markets/sdks/python/api_reference/trading/models.html#alpaca.trading.models.PortfolioHistory) distinguishes a window label from end-of-window equity. Do not blindly turn that timestamp into a NAV date, or reuse a simple equity/base-value P/L percentage as time-weighted return. Never round, interpolate, sort away duplicates, omit losses or infer missing coverage silently. [Research decisions](research-decisions.md) records the source/trust considerations behind this limited integration boundary.

## Local CLI

Requires Node supported by `package.json`. Run in the app folder containing that
file (`cd app` from the complete source or combined release root). The CLI reads one local
JSON file or stdin and calls the same deterministic handoff parser. It makes no
network requests or signing/storage calls. Replace `HANDOFF.json` and `PRIVATE.csv`
with your chosen file paths; use absolute paths when they are outside this folder.

```sh
node scripts/prepare-agent-handoff.mjs HANDOFF.json
cat HANDOFF.json | node scripts/prepare-agent-handoff.mjs -
node scripts/prepare-agent-handoff.mjs HANDOFF.json --csv PRIVATE.csv
```

Default output includes only status, observation/exception counts, allowlisted issue codes and fixed descriptions, support limits and explicit unchecked trust dimensions. It omits broker/account labels, dates, NAVs, flows, metrics, hashes, private references and raw parser/filesystem error messages. Counts and status can still reveal workflow information. Treat the original handoff JSON as private financial data.

`--csv` is an explicit request to create a private normalized CSV at the chosen local `.csv` path. It writes only when ready for owner review, refuses to overwrite any existing file, and requests owner-only permissions on systems that support POSIX modes. The output contains raw values. No directories are created automatically. A blocked/invalid packet creates no CSV. A filesystem failure or interrupted write can leave a partial file at the explicitly chosen path; the CLI reports failure, never success, and will not overwrite that file on retry. No profile or signing key is created and no review requirement is waived.

| Exit | Meaning |
| --- | --- |
| 0 | Valid and ready for mandatory owner review; optional CSV successfully created if requested. This is not source authentication. |
| 2 | Structurally readable but blocked by missing/unsupported source evidence. No CSV written. |
| 1 | Invalid contract, excessive input, read error, invalid command arguments or failed/refused CSV write. Fixed errors contain no raw values. |

A blocked packet may have zero observations. It should accurately state incomplete/unknown pagination, unresolved period coverage, unsupported events or unknown timing. Never fabricate data to change exit 2 to exit 0. If authorization or an already connected source is unavailable, stop source access and obtain the missing information; no alternate connector is simulated.

## Privacy and review limitations

The packet is mutable JSON containing private financial amounts and sender claims. It is not itself a signed N170 performance record. Hashing it later identifies those supplied text contents but does not authenticate a broker. Public review packages reproduce disclosed rounded returns → metrics; they do not reproduce private raw source acquisition or NAV → returns without separately provided original data. The CLI summary intentionally contains neither a performance recommendation nor a green verification status.
