// Public diagnostic copy must never reuse source-derived messages, paths or
// actions. These descriptions are product text, not a second validation engine.
const definitions = {
  needs_review: ['error', 'Some import details need local review.', 'Review the original source and complete local diagnostics. Keep unresolved evidence blocked; do not invent missing data.'],
  missing_columns: ['error', 'Required source columns are missing.', 'Use the documented export configuration or handoff schema. Obtain missing fields from the source; do not guess them.'],
  unknown_columns: ['error', 'Some source columns have no supported mapping.', 'Review the original columns locally and use the documented export configuration. Do not silently discard financial fields.'],
  mixed_modes: ['error', 'Different profit-and-loss modes may double count changes.', 'Export one documented profit-and-loss mode and reconcile all changes to ending NAV.'],
  multiple_accounts: ['error', 'The export does not establish one supported account scope.', 'Use the specifically authorized account scope. Consolidation needs an explicit treatment of internal transfers.'],
  currency_required: ['error', 'A single reporting currency has not been established.', 'Confirm the source currency with the owner. Do not infer or silently convert currencies.'],
  currency_assumption: ['warning', 'The reporting currency is supplied by the owner.', 'Check the currency against the original account statement; the file does not authenticate this assumption.'],
  flow_activity_review: ['error', 'Gross external cash activity and flow timing require owner review.', 'Review all cash-activity pages, including offsetting flows. Confirm only actual interval-end flows; otherwise obtain supported valuations.'],
  duplicate_row: ['error', 'A source row appears more than once.', 'Compare the original rows and document any correction. Do not count duplicates twice or silently remove conflicts.'],
  overlapping_period: ['error', 'Source periods overlap or are out of order.', 'Obtain nonoverlapping periods in date order and retain explanations for corrections.'],
  missing_period: ['error', 'A source statement period is missing.', 'Obtain the missing statement within the authorized scope. Keep the gap explicit until evidence is available.'],
  nav_discontinuity: ['error', 'Adjacent source valuations do not reconcile.', 'Check account scope, currency, dates and adjustments against the source before recording a correction.'],
  model_scope: ['error', 'A filtered model statement does not establish account-level scope.', 'Obtain the authorized account-level statement or keep the scope limitation unresolved.'],
  unsupported_event: ['error', 'A financial event has no supported treatment.', 'Keep the event visible and obtain the valuations and reviewed treatment needed. Do not drop the event to obtain a result.'],
  flow_timing: ['error', 'The source does not establish external-flow timing.', 'Obtain actual valuations at supported flow boundaries. Do not relabel intraperiod flows as interval-end flows.'],
  reconciliation_difference: ['error', 'Opening NAV and supplied changes do not reconcile to closing NAV.', 'Review all statement components and rounding against the original source. Do not invent a balancing adjustment.'],
  invalid_row: ['error', 'A source row does not meet the supported format.', 'Check the original row locally and obtain a corrected source export. Do not infer absent values.'],
  flow_timing_claim: ['warning', 'Interval-end flow timing is an owner assertion.', 'Retain the cash-activity evidence privately. A review checkbox does not independently establish timing.'],
  sampled_statement: ['warning', 'Only supplied statement boundaries are observed.', 'Disclose the sampling limits and obtain finer actual valuations where available. Unobserved drawdowns remain unknown.'],
  observation_count: ['error', 'The observation count is outside the supported range.', 'Use two to five hundred actual dated valuations per record. Do not invent opening or closing values.'],
  nonpositive_nav: ['error', 'Zero or negative NAV is outside the supported calculation.', 'Keep the total-loss or recapitalization interval explicit and seek a supported treatment. Do not remove losses to obtain a result.'],
  opening_flow: ['error', 'The opening valuation includes an external flow.', 'Obtain an actual earlier valuation for that flow-bearing interval. Do not replace a real opening flow with zero.'],
  duplicate_date: ['error', 'More than one observation has the same date.', 'Review duplicates and conflicts against the source and document corrections. Do not silently discard observations.'],
  date_order: ['error', 'Observation dates are not unique and ascending.', 'Review source dates and document any reorder or correction. Do not relabel valuations to hide gaps.'],
  sparse_observations: ['warning', 'Some valuation intervals are sparse.', 'Check whether observations are missing. Preserve known gaps; annualized results may be withheld.'],
  invalid_observation: ['error', 'An observation has an unsupported date or amount.', 'Check the original date and exact decimal values locally. Do not round or invent values to pass validation.'],
  owner_review_required: ['error', 'The owner has not completed source review.', 'The owner must inspect mappings, valuation dates, scope and complete gross cash activity in Verify. An assistant cannot grant this approval.'],
  valuations_required: ['error', 'The source lacks a complete dated portfolio-value series.', 'Obtain actual NAV observations and matching external flows. Cash balances, trade proceeds and trade profit are not substitutes.'],
  flows_required: ['error', 'External-flow evidence is missing.', 'Obtain matching gross cash activity and review timing. Missing flow values must not become zero.'],
  unknown_format: ['error', 'The source format is unsupported or unrecognized.', 'Use the documented source format or handoff contract. No financial mapping should be guessed.'],
  supplied_file: ['warning', 'This is supplied-file evidence.', 'Review source and coverage separately. Parsing and hashing do not authenticate a broker or establish account completeness.'],
  source_not_retrieved: ['error', 'No completed source retrieval is reported.', 'Use only already available, explicitly authorized read-only source access. Keep the packet blocked if actual observations cannot be retrieved.'],
  pagination_incomplete: ['error', 'Source pagination is incomplete.', 'Retrieve all relevant authorized pages using documented continuation rules, or keep the handoff blocked.'],
  pagination_unknown: ['error', 'Source pagination completion is unknown.', 'Confirm the documented end condition for every required dataset. Do not infer completeness from the available pages.'],
  missing_periods: ['error', 'The handoff reports missing period coverage.', 'Obtain actual missing observations within the authorized scope. Keep gaps explicit and never fill them with invented values.'],
  unsupported_events: ['error', 'The handoff reports unsupported financial events.', 'Retain the events and resolve their supported treatment before calculation. Do not omit them to get a result.'],
  flow_timing_unsupported: ['error', 'External-flow timing is unknown or intraperiod.', 'Obtain actual valuations at supported flow boundaries. Do not shift dates or assume interval-end timing.'],
  missing_observations: ['error', 'Fewer than two complete actual valuations are available.', 'Return only observed values, or an empty blocked packet. Never invent NAV or missing zero flows.'],
  requested_period_mismatch: ['error', 'Observed boundaries do not match the requested period.', 'Obtain the requested opening and closing valuations, or ask the owner to explicitly revise the scope.'],
  calculation_unsupported: ['error', 'The observations exceed calculation support limits.', 'Review the original values and documented limits. Keep losses and unsupported intervals visible; do not alter data to force a result.'],
  agent_claims_unverified: ['warning', 'Assistant-reported source details are unverified claims.', 'Review the original tool results privately. Tool labels, retrieval time and connection claims are not broker, identity or independent-time evidence.'],
  synthetic_example: ['warning', 'The packet identifies synthetic demonstration data.', 'Keep the synthetic label in every review and shared record. Never present this example as actual account performance.'],
  invalid_json: ['error', 'The supplied handoff is not valid JSON.', 'Return one complete JSON object following the contract, without surrounding explanation or multiple replies.'],
  size_limit: ['error', 'The input exceeds the supported size limit.', 'Use a bounded handoff for the authorized scope. Do not silently truncate observations or omit missing coverage.'],
  duplicate_key: ['error', 'A JSON field is repeated.', 'Emit every field once using its actual source value. Resolve conflicts rather than choosing a value silently.'],
  unknown_key: ['error', 'The handoff includes unsupported fields.', 'Follow the exact schema and omit credentials, account numbers and unsupported verification claims. Review unknown fields locally.'],
  missing_key: ['error', 'A required handoff field is missing.', 'Supply required fields from actual evidence. Use the documented blocked states where evidence is unavailable.'],
  invalid_type: ['error', 'A handoff field has the wrong type.', 'Follow the schema types, including exact decimal strings for amounts. Do not silently coerce missing values to zero.'],
  invalid_value: ['error', 'A handoff field has an unsupported value.', 'Check the documented enums and bounds against the actual source. Do not guess a value to pass validation.'],
  invalid_date: ['error', 'A valuation or coverage date is invalid.', 'Use an actual calendar date in the documented format and preserve the source valuation-time meaning.'],
  invalid_timestamp: ['error', 'The reported retrieval timestamp is invalid.', 'Use the documented timestamp format only for an actual retrieval, or null when no retrieval occurred. Do not invent time evidence.'],
  invalid_decimal: ['error', 'An amount is not a supported exact decimal string.', 'Use the exact source decimal without exponent notation or grouping. Do not round values or invent missing amounts.'],
  decimal_range: ['error', 'An amount exceeds the supported magnitude.', 'Keep the source value unchanged and report the unsupported range. Do not scale or clip data to pass validation.'],
  invalid_range: ['error', 'A requested or missing-period date range is reversed.', 'Check the intended dates with the owner and source. Do not silently change the requested period.'],
  invalid_encoding: ['error', 'The file is not valid UTF-8 text.', 'Obtain a UTF-8 source export. Do not substitute characters or reconstruct missing financial data.'],
  invalid_source: ['error', 'The retained source cannot be reconciled.', 'Review the original source locally and obtain a corrected export before proceeding. Keep current work and history intact.'],
  reconciliation_needed: ['error', 'Source observations have not been accepted into the draft.', 'Review mappings, scope, cash activity and exceptions, then reconcile the source in Verify.'],
};
const MAX_ISSUES = 10000;

export function safeIssueSummaries(issues) {
  const found = new Map();
  function add(issue) {
    const inputCode = issue && typeof issue === 'object' ? issue.code : null;
    const code = typeof inputCode === 'string' && Object.hasOwn(definitions, inputCode) ? inputCode : 'needs_review';
    const [defaultSeverity, message, action] = definitions[code];
    // This one code is emitted as a blocking pre-review error by CSV import and
    // as a continuing review reminder by agent handoff. Errors win duplicates.
    const severity = code === 'flow_activity_review' && issue?.severity === 'warning' ? 'warning' : defaultSeverity;
    const previous = found.get(code);
    if (!previous || severity === 'error') found.set(code, { code, severity, message, action });
  }
  if (!Array.isArray(issues)) add(null);
  else {
    for (let index = 0; index < Math.min(issues.length, MAX_ISSUES); index++) add(issues[index]);
    if (issues.length > MAX_ISSUES) add(null);
  }
  return [...found.values()];
}
