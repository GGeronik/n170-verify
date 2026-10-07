#!/usr/bin/env node
// Local preparation bridge for data supplied by an assistant. No connection,
// signing, browser storage, tool execution, or implicit financial-data output.
import { createReadStream } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseAgentHandoff } from '../src/agentHandoff.js';

const MAX_INPUT_BYTES = 1000000;
const reasons = Object.freeze({
  source_not_retrieved: 'No completed source retrieval is reported. Keep the packet blocked until an authorized read-only source provides the required data.',
  pagination_incomplete: 'Source pagination is incomplete. Retrieve the remaining authorized pages or return a blocked packet.',
  pagination_unknown: 'Pagination completion is unknown. Do not infer that all source pages were supplied.',
  missing_periods: 'The requested period has known missing observations or coverage.',
  unsupported_events: 'The source contains financial events outside the supported treatment.',
  flow_timing_unsupported: 'External flow timing is unknown or intraperiod. Obtain valuations at each flow before using this method.',
  missing_observations: 'At least two actual portfolio valuation observations are required.',
  requested_period_mismatch: 'The observations do not match both requested period boundaries.',
  calculation_unsupported: 'The observations fail the deterministic calculation support checks. Review the source and calculation limits.',
  agent_claims_unverified: 'Assistant-supplied source statements are not broker authentication, identity proof or independent time evidence.',
  flow_activity_review: 'The owner must review gross cash activity and flow timing. Net zero does not establish that no flows occurred.',
  synthetic_example: 'The packet identifies synthetic demonstration data.',
});
const structuralCodes = new Set(['invalid_json','size_limit','duplicate_key','unknown_key','missing_key','invalid_type','invalid_value','invalid_date','invalid_timestamp','invalid_decimal','decimal_range','date_order','invalid_range']);
const limits = Object.freeze({ input_bytes: MAX_INPUT_BYTES, maximum_observations: 500, minimum_observations_to_review: 2, maximum_amount_magnitude: '1000000000000000', maximum_decimal_places: 18, supported_frequencies: [1,4,12,52,252,365] });
const base = () => ({ schema_version: 'n170.agent-handoff-result.v1', source_authenticated: false, identity_established: false, independent_time_established: false, record_signed: false, browser_storage_changed: false, financial_values_included: false, csv_written: false });
const knownIssues = (issues, severity) => [...new Set((issues || []).filter(issue => issue.severity === severity).map(issue => Object.hasOwn(reasons, issue.code) ? issue.code : 'review_required'))].map(code => ({ code, message: reasons[code] || 'The source needs deterministic reconciliation and owner review.' }));

export async function prepareAgentHandoff(text) {
  const { handoff, review } = await parseAgentHandoff(text);
  return {
    summary: {
      ...base(), status: review.canCalculate ? 'ready_for_owner_review' : 'blocked',
      owner_review_required: true,
      counts: { observations: handoff.observations.length, missing_periods: handoff.coverage.missing_periods.length, unsupported_events: handoff.coverage.unsupported_events.length },
      pagination: { sender_claim: handoff.coverage.pagination, independently_checked: false },
      blockers: knownIssues(review.exceptions, 'error'), warnings: knownIssues(review.exceptions, 'warning'), support_limits: limits,
    },
    // Kept inside this process unless --csv explicitly asks for a private file.
    normalizedCsv: review.canCalculate ? review.normalizedCsv : null,
  };
}

async function readBounded(input) {
  const stream = input === '-' ? process.stdin : createReadStream(input);
  const parts = []; let size = 0;
  for await (const part of stream) {
    const bytes = Buffer.isBuffer(part) ? part : Buffer.from(part);
    size += bytes.length;
    if (size > MAX_INPUT_BYTES) { stream.destroy(); throw Object.assign(new Error('Input too large'), { safeCode: 'size_limit' }); }
    parts.push(bytes);
  }
  try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(Buffer.concat(parts)); }
  catch { throw Object.assign(new Error('Invalid UTF-8'), { safeCode: 'invalid_encoding' }); }
}

function argumentsFor(args) {
  let input = null, csv = null;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--csv') {
      if (csv !== null || !args[i + 1] || args[i + 1].startsWith('--')) throw new Error('Invalid arguments');
      csv = args[++i];
      if (csv === '-' || csv.includes('://') || csv.includes('\0') || /^\\\\/.test(csv) || path.extname(csv).toLowerCase() !== '.csv') throw new Error('Invalid output path');
    } else if (arg === '-' || !arg.startsWith('-')) {
      if (input !== null) throw new Error('Only one input is supported');
      input = arg;
    } else throw new Error('Unknown argument');
  }
  if (input === null && process.stdin.isTTY) throw new Error('Supply an input file or pipe JSON');
  return { input: input ?? '-', csv };
}

async function main(args) {
  if (args.length === 1 && ['--help','-h'].includes(args[0])) {
    process.stdout.write('Usage: node scripts/prepare-agent-handoff.mjs [HANDOFF.json|-] [--csv PRIVATE.csv]\nRead a local JSON packet or stdin. Default output contains only bounded status/counts.\n--csv explicitly creates a private normalized CSV, with no overwrite, only if ready.\nExit 0: ready for mandatory owner review; 2: blocked source; 1: invalid input/request.\n');
    return;
  }
  let parsed;
  try { parsed = argumentsFor(args); }
  catch { process.stdout.write(JSON.stringify({ ...base(), status: 'invalid_request', issue_codes: ['invalid_arguments'], message: 'Supply one local JSON file or stdin; optional --csv requires a local .csv path. Run with --help for usage.' }) + '\n'); process.exitCode = 1; return; }
  try {
    const input = await readBounded(parsed.input);
    const { summary, normalizedCsv } = await prepareAgentHandoff(input);
    if (parsed.csv && normalizedCsv !== null) {
      try { await writeFile(parsed.csv, normalizedCsv, { encoding: 'utf8', flag: 'wx', mode: 0o600 }); summary.csv_written = true; }
      catch (cause) {
        process.stdout.write(JSON.stringify({ ...base(), status: 'invalid_request', issue_codes: [cause.code === 'EEXIST' ? 'output_exists' : 'output_unavailable'], message: 'The private CSV could not be completed. Choose a new local .csv file in an existing writable directory; existing files are never overwritten. An interrupted write may leave a partial file at the chosen path.' }) + '\n');
        process.exitCode = 1; return;
      }
    }
    process.stdout.write(JSON.stringify(summary, null, 2) + '\n');
    process.exitCode = summary.status === 'blocked' ? 2 : 0;
  } catch (cause) {
    // Parser messages, unknown field names and filesystem paths may contain
    // private data. Emit only a fixed message and allowlisted structural codes.
    const codes = [...new Set((Array.isArray(cause.errors) ? cause.errors : []).map(error => structuralCodes.has(error.code) ? error.code : 'invalid_handoff'))];
    if (['size_limit', 'invalid_encoding'].includes(cause.safeCode)) codes.push(cause.safeCode);
    process.stdout.write(JSON.stringify({ ...base(), status: 'invalid', issue_codes: codes.length ? codes : ['invalid_handoff'], message: 'The handoff could not be validated. Check UTF-8 encoding, the JSON contract, required field types and input size. No financial values were printed or CSV created.', support_limits: limits }) + '\n');
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main(process.argv.slice(2));
