// Deterministic local statement preparation. Parsing never authenticates a broker.
import { parseAgentHandoff } from "./agentHandoff.js";
import { safeIssueSummaries } from "./safeIssues.js";
export const IMPORT_VERSION = "n170.import.v1";
export const IMPORT_FORMATS = [
  { id: "auto", label: "Detect from column headers" },
  { id: "ibkr-flex", label: "IBKR · Change in NAV Flex CSV" },
  { id: "agent-handoff", label: "Assistant / broker MCP · supplied handoff" },
  { id: "n170", label: "N170 · dated NAV and external flows" },
  { id: "trading212", label: "Trading 212 · transactions (needs valuations)" },
  { id: "portfolio-performance", label: "Portfolio Performance · assets chart (needs flows)" },
];

const decimalPattern = /^-?(?:\d+(?:\.\d*)?|\.\d+)$/;
const encode = new TextEncoder();
async function digest(text) {
  const bytes = await globalThis.crypto.subtle.digest("SHA-256", encode.encode(text));
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
const normalizedHeader = (value) => value.toLowerCase().replace(/[^a-z0-9]/g, "");
const issue = (code, severity, message, action, row = null) => ({ code, severity, message, action, row });

// RFC-4180 quoting, LF/CRLF, BOM; delimiter is explicit/detected, never inferred from numbers.
export function parseCsv(text, delimiter) {
  if (typeof text !== "string" || text.length > 2000000) throw new Error("Use a UTF-8 CSV with at most 2,000,000 characters.");
  text = text.replace(/^\uFEFF/, "");
  if (!delimiter) {
    const first = text.split(/\r?\n/, 1)[0];
    delimiter = first.includes(";") && !first.includes(",") ? ";" : ",";
  }
  if (![",", ";", "\t"].includes(delimiter)) throw new Error("Choose comma, semicolon or tab as the separator.");
  const rows = []; let row = []; let cell = ""; let quoted = false; let closed = false;
  const pushCell = () => { row.push(cell.trim()); cell = ""; closed = false; };
  const pushRow = () => { pushCell(); if (row.some(Boolean)) rows.push(row); row = []; if (rows.length > 5001) throw new Error("Use at most 5,000 CSV rows."); };
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    if (quoted) {
      if (char === '"') { if (text[i + 1] === '"') { cell += '"'; i += 1; } else { quoted = false; closed = true; } }
      else cell += char;
    } else if (char === '"') {
      if (cell || closed) throw new Error("A CSV quote is misplaced. Export the file again without editing its quoting.");
      quoted = true;
    } else if (char === delimiter) pushCell();
    else if (char === "\n" || char === "\r") { if (char === "\r" && text[i + 1] === "\n") i += 1; pushRow(); }
    else { if (closed && !/\s/.test(char)) throw new Error("Unexpected content after a closing CSV quote."); if (!closed) cell += char; }
  }
  if (quoted) throw new Error("A CSV quote is not closed. Export the file again.");
  if (cell || row.length || closed) pushRow();
  if (rows.length < 2) throw new Error("Include column headers and at least one data row.");
  const headers = rows[0].map(normalizedHeader);
  if (new Set(headers).size !== headers.length || headers.includes("")) throw new Error("Column names must be nonempty and unique.");
  for (let i = 1; i < rows.length; i += 1) if (rows[i].length !== rows[0].length) throw new Error(`CSV row ${i + 1} has ${rows[i].length} columns; the header has ${rows[0].length}. Export one table with column headers and no section/trailer rows.`);
  return { headers: rows[0], rows: rows.slice(1), delimiter };
}

function dateValue(value) {
  const iso = /^\d{8}$/.test(value) ? `${value.slice(0, 4)}-${value.slice(4, 6)}-${value.slice(6)}` : value;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(iso) || !Number.isFinite(Date.parse(iso)) || new Date(iso).toISOString().slice(0, 10) !== iso) throw new Error(`Use a valid YYYY-MM-DD or YYYYMMDD date; found “${value.slice(0, 24)}”.`);
  return iso;
}
function decimalValue(value) {
  if (value.length > 40 || !decimalPattern.test(value)) throw new Error(`Use plain decimal amounts without grouping or currency symbols; found “${value.slice(0, 24)}”.`);
  const [whole, fraction = ""] = value.replace(/^-/, "").split(".");
  if (fraction.length > 18) throw new Error("Amounts may have at most 18 decimal places.");
  return { units: BigInt((whole || "0") + fraction) * (value.startsWith("-") ? -1n : 1n), scale: fraction.length };
}
function decimalSum(values) {
  const parsed = values.map(decimalValue); const scale = Math.max(...parsed.map((v) => v.scale));
  return parsed.reduce((total, value) => total + value.units * 10n ** BigInt(scale - value.scale), 0n);
}
const isZero = (value) => decimalValue(value).units === 0n;
const sameDecimal = (a, b) => decimalSum([a, b.startsWith("-") ? b.slice(1) : `-${b}`]) === 0n;
const previousDay = (value) => new Date(Date.parse(value) - 86400000).toISOString().slice(0, 10);
const toCsv = (rows) => "date,nav,external_flow\n" + rows.map((row) => [row.date, row.nav, row.flow].join(",")).join("\n");

export function detectImportFormat(text) {
  if (typeof text === "string" && text.trimStart().startsWith("{")) return "agent-handoff";
  const { headers } = parseCsv(text); const keys = headers.map(normalizedHeader);
  if (["fromdate", "todate", "startingvalue", "endingvalue"].every((key) => keys.includes(key))) return "ibkr-flex";
  if (["date", "nav", "externalflow"].every((key) => keys.includes(key))) return "n170";
  if (keys.includes("action") && keys.includes("time") && (keys.includes("total") || keys.includes("currencytotal"))) return "trading212";
  if (keys.includes("date") && keys.some((key) => ["total", "totalassets", "totalassetsmarketprice", "totalportfolio", "gesamtvermögen"].includes(key))) return "portfolio-performance";
  return "unknown";
}

const ibkrRequired = ["Account ID", "From Date", "To Date", "Starting Value", "Ending Value", "Deposits/Withdrawals", "Internal Cash Transfers", "Asset Transfers", "Linking Adjustments", "Other"];
const unsupportedEvents = ["Internal Cash Transfers", "Asset Transfers", "Linking Adjustments", "Other"];
const economicFields = ["Mark-to-Market", "Realized", "Change in Unrealized", "Deposits/Withdrawals", "Internal Cash Transfers", "Asset Transfers", "Dividends", "Withholding Tax", "871(m) Withholding", "Change in Dividend Accruals", "Interest", "Change in Interest Accruals", "Advisor Fees", "Client Fees", "Other Fees", "Fees Receivable", "Commissions", "Commissions Receivable", "Forex Commissions", "Transaction Tax", "Tax Receivables", "Sales Tax", "Soft Dollars", "Net Forex Trading", "Forex Translation", "Linking Adjustments", "Other"];

function parseIBKR(table, options, exceptions) {
  const keys = table.headers.map(normalizedHeader);
  const at = (row, name) => row[keys.indexOf(normalizedHeader(name))];
  const absent = ibkrRequired.filter((key) => !keys.includes(normalizedHeader(key)));
  if (absent.length) { exceptions.push(issue("missing_columns", "error", `Required IBKR fields missing: ${absent.join(", ")}.`, "Create a Change in NAV Flex query with all required fields listed in Import formats.")); return { rows: [], mapping: [] }; }
  const known = [...ibkrRequired, ...economicFields, "Account Alias", "Model", "TWR", "Currency", "Base Currency"];
  const unknown = table.headers.filter((header) => !known.some((name) => normalizedHeader(name) === normalizedHeader(header)));
  if (unknown.length) exceptions.push(issue("unknown_columns", "error", `Unmapped IBKR fields: ${unknown.join(", ")}.`, "Use the documented Change in NAV query configuration; do not silently omit financial fields."));
  if (keys.includes("marktomarket") && (keys.includes("realized") || keys.includes("changeinunrealized"))) exceptions.push(issue("mixed_modes", "error", "Both IBKR P&L modes are present and may double-count the same change.", "Export either Mark-to-Market or Realized & Unrealized, not both."));
  const accounts = new Set(table.rows.map((row) => at(row, "Account ID")));
  if (accounts.has("") || accounts.size !== 1) exceptions.push(issue("multiple_accounts", "error", "This file does not identify exactly one account.", "Export each account separately. Combining accounts needs explicit consolidation and internal-transfer treatment."));
  // Every explicit currency field is evidence to review. A blank or conflicting
  // field cannot be repaired by choosing another column or the UI's default.
  const currencyColumns = ["Currency", "Base Currency"].filter((name) => keys.includes(normalizedHeader(name)));
  const currencies = new Set(currencyColumns.length
    ? table.rows.flatMap((row) => currencyColumns.map((name) => at(row, name)))
    : [options.currency || ""]);
  const currency = [...currencies][0] || "";
  const ownerCurrencyDiffers = currencyColumns.length > 0 && options.currency !== undefined && options.currency !== currency;
  if (currencies.size !== 1 || !/^[A-Z]{3}$/.test(currency) || ownerCurrencyDiffers) exceptions.push(issue("currency_required", "error", "Every supplied currency field and the selected reporting currency must identify the same three-letter currency; blank fields and conflicts need review.", "Check Currency, Base Currency and the selected reporting currency against the original statement. Resolve missing or conflicting source fields explicitly. No foreign-exchange conversion is performed."));
  else if (!currencyColumns.length) exceptions.push(issue("currency_assumption", "warning", `Base currency ${currency} is supplied by you, not contained in this export.`, "Check it against the account statement."));
  if (!options.flowTimingConfirmed) exceptions.push(issue("flow_activity_review", "error", "Net deposits/withdrawals can hide offsetting flows even when their total is zero.", "Check cash activity and confirm that no offsetting flows are hidden and every external flow occurs at interval end. Otherwise obtain valuations at each flow."));
  const rows = []; let prior = null; const seen = new Set();
  for (let index = 0; index < table.rows.length; index += 1) {
    const row = table.rows[index]; const number = index + 2;
    try {
      const from = dateValue(at(row, "From Date")); const to = dateValue(at(row, "To Date"));
      const start = at(row, "Starting Value"); const end = at(row, "Ending Value"); const flow = at(row, "Deposits/Withdrawals");
      [start, end, flow].forEach(decimalValue);
      const signature = JSON.stringify(row);
      if (seen.has(signature)) exceptions.push(issue("duplicate_row", "error", "An identical statement row appears more than once.", "Remove the duplicate through a recorded source correction; never count it twice.", number));
      seen.add(signature);
      if (from > to || (prior && from <= prior.to)) exceptions.push(issue("overlapping_period", "error", "Statement periods overlap or are out of order.", "Use non-overlapping statements in ascending order.", number));
      if (prior && previousDay(from) !== prior.to) exceptions.push(issue("missing_period", "error", `No statement covers the dates after ${prior.to} and before ${from}.`, "Add the missing statement. Do not bridge an unobserved period as if it were supplied.", number));
      if (prior && !sameDecimal(start, prior.end)) exceptions.push(issue("nav_discontinuity", "error", "This starting NAV does not equal the previous ending NAV.", "Check currency, account, report dates and adjustments. Correct the supplied file with an explanation.", number));
      if (at(row, "Model")) exceptions.push(issue("model_scope", "error", "A model-specific statement does not establish whole-account scope.", "Export an account-level statement without model filtering.", number));
      unsupportedEvents.forEach((name) => { if (!isZero(at(row, name))) exceptions.push(issue("unsupported_event", "error", `${name} is nonzero; its cash-flow treatment is unsupported.`, "Reconcile with additional valuations and a reviewed treatment before preparing N170 observations.", number)); });
      if (!isZero(flow) && !options.flowTimingConfirmed) exceptions.push(issue("flow_timing", "error", "The statement has deposits/withdrawals but does not establish when those flows occurred.", "Only confirm interval-end timing if all external flows actually occurred at interval end; otherwise obtain valuations at each flow.", number));
      const included = economicFields.filter((name) => keys.includes(normalizedHeader(name)));
      const changes = included.map((name) => at(row, name));
      if (decimalSum([start, ...changes, end.startsWith("-") ? end.slice(1) : `-${end}`]) !== 0n) exceptions.push(issue("reconciliation_difference", "error", "Starting NAV plus the supplied changes does not exactly reconcile to ending NAV.", "Include every Change in NAV component. Investigate rounding and missing items before calculating.", number));
      if (!prior) rows.push({ date: previousDay(from), nav: start, flow: "0", sourceRow: number, derived: "Opening NAV is dated at the end of the day before the inclusive From Date." });
      rows.push({ date: to, nav: end, flow, sourceRow: number });
      prior = { to, end };
    } catch (error) { exceptions.push(issue("invalid_row", "error", error.message, "Correct this row or export the statement again.", number)); }
  }
  if (options.flowTimingConfirmed) exceptions.push(issue("flow_timing_claim", "warning", "You state that no offsetting flows are hidden and external cash flows occur at interval end. The export does not authenticate this claim.", "Do not continue if flows occurred during the period."));
  exceptions.push(issue("sampled_statement", "warning", "Only statement boundaries are observed; missing intraperiod valuations and unreported accounts cannot be discovered.", "Use daily statements for finer sampling and disclose account coverage."));
  return { rows, currency, mapping: [
    { source: "From Date + Starting Value", target: "Opening date and NAV", explanation: "The start value is dated at the prior calendar-day close; the report's From Date is inclusive." },
    { source: "To Date + Ending Value", target: "Closing date and NAV", explanation: "One observation per supplied statement boundary; no intraperiod values are invented." },
    { source: "Deposits/Withdrawals", target: "external_flow", explanation: "Positive contributions, negative withdrawals; only supported at interval end." },
    { source: "P&L, dividends, interest, fees, tax and FX components", target: "Reconciliation only", explanation: "They remain within investment performance in ending NAV, not external deposits. Supplied components must exactly reconcile." },
  ] };
}

function parseN170(table, options, exceptions) {
  const keys = table.headers.map(normalizedHeader);
  if (!["date", "nav", "externalflow"].every((key) => keys.includes(key)) || keys.length !== 3) { exceptions.push(issue("missing_columns", "error", "Use exactly date,nav,external_flow.", "Export the three-column N170 template or select the documented broker format.")); return { rows: [], mapping: [] }; }
  return { rows: table.rows.map((row, i) => ({ date: row[keys.indexOf("date")], nav: row[keys.indexOf("nav")], flow: row[keys.indexOf("externalflow")], sourceRow: i + 2 })), currency: options.currency || "unspecified", mapping: [
    { source: "date", target: "Observation date", explanation: "ISO date at each portfolio valuation." },
    { source: "nav", target: "Net asset value", explanation: "Total portfolio equity in one consistent currency, including cash and accrued items already present." },
    { source: "external_flow", target: "External flows", explanation: "Contributions positive, withdrawals negative; all at interval end. Trades, dividends, fees and taxes remain in NAV." },
  ] };
}

function validateRows(rows, exceptions) {
  if (rows.length < 2 || rows.length > 500) exceptions.push(issue("observation_count", "error", "Performance needs 2 to 500 valid dated NAV observations.", "Add opening and closing valuations or split a longer history into records."));
  const dates = new Map();
  rows.forEach((row, index) => {
    try {
      row.date = dateValue(row.date); const nav = decimalValue(row.nav); decimalValue(row.flow);
      if (nav.units <= 0n) exceptions.push(issue("nonpositive_nav", "error", "Zero or negative NAV is outside this calculation's support.", "Separate the period before total loss or recapitalization and explain the unsupported interval.", row.sourceRow));
      if (index === 0 && !isZero(row.flow)) exceptions.push(issue("opening_flow", "error", "The opening valuation establishes the base and must have zero flow.", "Include an earlier valuation to measure this flow-bearing interval.", row.sourceRow));
      if (dates.has(row.date)) exceptions.push(issue("duplicate_date", "error", `The date ${row.date} appears more than once.`, "Resolve duplicate/conflicting observations; no rows are removed automatically.", row.sourceRow));
      dates.set(row.date, true);
      if (index && row.date <= rows[index - 1].date) exceptions.push(issue("date_order", "error", "Observation dates must be in strictly ascending order.", "Review and reorder the source with a correction explanation.", row.sourceRow));
      if (index && (Date.parse(row.date) - Date.parse(rows[index - 1].date)) / 86400000 > 4) exceptions.push(issue("sparse_observations", "warning", `There are more than four calendar days between ${rows[index - 1].date} and ${row.date}.`, "Check missing observations. This does not prove a trading-day gap; annualization may be withheld.", row.sourceRow));
    } catch (error) { exceptions.push(issue("invalid_observation", "error", error.message, "Correct the value and review again.", row.sourceRow)); }
  });
}

export async function importStatement(text, options = {}) {
  if (options.format === 'agent-handoff' || (typeof text === 'string' && text.trimStart().startsWith('{'))) {
    const { handoff, review } = await parseAgentHandoff(text);
    if (options.currency && options.currency !== handoff.currency) throw new Error('The reporting currency differs from the assistant handoff. Load it again and review the original currency; Verify does not convert currencies.');
    if (options.frequency && Number(options.frequency) !== handoff.frequency) throw new Error('The observation frequency differs from the assistant handoff. Review its original date mapping before changing the frequency.');
    if (!options.flowTimingConfirmed) {
      review.exceptions.push(issue('owner_review_required', 'error', 'Assistant-prepared observations need your review against the source.', 'Check field mappings, valuation dates, account scope, all cash-activity pages and interval-end flows, then confirm below.'));
      review.canCalculate = false;
    }
    review.review.flow_timing = options.flowTimingConfirmed ? 'owner_confirmed_interval_end' : 'interval_end_required';
    review.source.file_name = (options.fileName || 'Assistant handoff JSON').slice(0, 200);
    return review;
  }
  const table = parseCsv(text, options.delimiter);
  const format = options.format && options.format !== "auto" ? options.format : detectImportFormat(text);
  const exceptions = []; let parsed = { rows: [], mapping: [] };
  if (format === "ibkr-flex") parsed = parseIBKR(table, options, exceptions);
  else if (format === "n170") parsed = parseN170(table, options, exceptions);
  else if (format === "trading212") exceptions.push(issue("valuations_required", "error", "Trading 212 transaction history contains activity, not a complete dated portfolio NAV series.", "Obtain account-value statements plus flows. Do not turn trade proceeds, cash balances or deposits into portfolio returns."));
  else if (format === "portfolio-performance") exceptions.push(issue("flows_required", "error", "An assets-chart export gives portfolio values but does not establish external flows.", "Reconcile deposits, withdrawals and deliveries from the same account scope, then prepare N170 observations. Portfolio Performance uses a different flow-timing convention."));
  else exceptions.push(issue("unknown_format", "error", "These column headers do not match a supported export.", "Use the IBKR Flex configuration or N170 template. No financial column mapping is guessed."));
  if (["ibkr-flex", "n170"].includes(format)) validateRows(parsed.rows, exceptions);
  exceptions.push(issue("supplied_file", "warning", "This is supplied-file evidence. The parser does not authenticate the broker, account ownership or completeness.", "Keep the original privately and disclose scope and assumptions when sharing."));
  const sourceHash = await digest(text);
  const normalizedCsv = parsed.rows.length ? toCsv(parsed.rows) : "";
  return {
    version: IMPORT_VERSION, format, label: IMPORT_FORMATS.find((item) => item.id === format)?.label || "Unrecognized CSV", source: { kind: "supplied_file", authenticated: false, sha256: sourceHash, digest_scope: "UTF-8 text exactly as supplied before parsing", file_name: (options.fileName || "Pasted CSV").slice(0, 200), uploaded: false },
    normalizedCsv, rows: parsed.rows, mapping: parsed.mapping, exceptions, canCalculate: parsed.rows.length >= 2 && !exceptions.some((item) => item.severity === "error"), currency: parsed.currency || options.currency || "unspecified", corrections: [],
    coverage: { source_rows: table.rows.length, observations: parsed.rows.length, start: parsed.rows[0]?.date || null, end: parsed.rows.at(-1)?.date || null, accounts: format === "ibkr-flex" ? "One account required; completeness unverified" : "Scope supplied by owner" },
    review: { normalized_sha256: await digest(normalizedCsv), source_verified: false, flow_timing: options.flowTimingConfirmed ? "owner_confirmed_interval_end" : "interval_end_required", reviewed: false },
  };
}

// Re-import a corrected SOURCE file; preserve every original digest and reason.
// This does not silently bypass unsupported source events or reconciliation failures.
export async function correctImport(previous, correctedText, reason, options = {}) {
  if (!previous?.source?.sha256 || typeof reason !== "string" || reason.trim().length < 8 || reason.length > 500) throw new Error("Explain the source correction in 8–500 characters.");
  const next = await importStatement(correctedText, { format: previous.format, currency: previous.currency, ...options });
  if (next.source.sha256 === previous.source.sha256) throw new Error("The corrected source is identical. Change the source or cancel the correction.");
  next.corrections = [...previous.corrections, { sequence: previous.corrections.length + 1, previous_source_sha256: previous.source.sha256, replacement_source_sha256: next.source.sha256, previous_normalized_sha256: previous.review.normalized_sha256, replacement_normalized_sha256: next.review.normalized_sha256, reason: reason.trim(), changed_at: new Date().toISOString(), time_evidence: "device_clock_only" }];
  next.original_source_sha256 = previous.original_source_sha256 || previous.source.sha256;
  return next;
}

// Public diagnostic summary only, not a signed record or verification result.
// Free-form metadata stays private even when it usually contains harmless text.
const disclosedHash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value) ? value : null;
const disclosedCount = (value, maximum) => Number.isSafeInteger(value) && value >= 0 && value <= maximum ? value : null;
const disclosureFormats = ['ibkr-flex', 'n170', 'agent-handoff', 'trading212', 'portfolio-performance'];
const disclosureCurrencies = ['USD', 'EUR', 'GBP', 'CHF', 'CAD', 'AUD', 'JPY'];
export function importDisclosure(review) {
  const source = review && typeof review === 'object' ? review : {};
  const exceptions = safeIssueSummaries(source.exceptions);
  const correctionList = Array.isArray(source.corrections) && source.corrections.length <= 100 ? source.corrections : null;
  if (!correctionList) exceptions.push(...safeIssueSummaries([null]));
  const corrections = (correctionList || []).map(correction => ({
    sequence: disclosedCount(correction?.sequence, 100),
    previous_source_sha256: disclosedHash(correction?.previous_source_sha256),
    replacement_source_sha256: disclosedHash(correction?.replacement_source_sha256),
    previous_normalized_sha256: disclosedHash(correction?.previous_normalized_sha256),
    replacement_normalized_sha256: disclosedHash(correction?.replacement_normalized_sha256),
  }));
  const safeExceptions = safeIssueSummaries(exceptions);
  return {
    disclosure_version: 'n170.import-disclosure.v2',
    importer_version: [IMPORT_VERSION, 'n170.agent-handoff.v1'].includes(source.version) ? source.version : 'unknown',
    source_kind: 'supplied_file', source_authenticated: false,
    status: source.canCalculate === true && !safeExceptions.some(item => item.severity === 'error') ? 'ready_for_owner_review' : 'blocked',
    owner_review_required: true,
    format: disclosureFormats.includes(source.format) ? source.format : 'unknown',
    original_source_sha256: disclosedHash(source.original_source_sha256 ?? source.source?.sha256),
    source_sha256: disclosedHash(source.source?.sha256),
    normalized_sha256: disclosedHash(source.review?.normalized_sha256),
    currency: disclosureCurrencies.includes(source.currency) ? source.currency : 'unspecified',
    coverage: { source_rows: disclosedCount(source.coverage?.source_rows, 5000), observations: disclosedCount(source.coverage?.observations, 500), completeness: 'not_established' },
    correction_count: correctionList ? correctionList.length : null, corrections,
    exceptions: safeExceptions,
    flow_timing: source.review?.flow_timing === 'owner_confirmed_interval_end' ? 'owner_confirmed_interval_end' : 'interval_end_required',
    raw_values_included: false, free_text_included: false,
  };
}

// Synthetic fixture shaped to the documented query; not a broker-sourced file.
export const ibkrSampleInput = "Account ID,From Date,To Date,Starting Value,Ending Value,Deposits/Withdrawals,Internal Cash Transfers,Asset Transfers,Linking Adjustments,Other,Mark-to-Market,Dividends,Interest,Commissions\nSYNTHETIC,2025-01-02,2025-01-02,10000,10100,0,0,0,0,0,105,0,0,-5\nSYNTHETIC,2025-01-03,2025-01-03,10100,9999,0,0,0,0,0,-96,0,0,-5\nSYNTHETIC,2025-01-04,2025-01-06,9999,10200,0,0,0,0,0,196,10,0,-5";
