import test from 'node:test';
import assert from 'node:assert/strict';
import { safeIssueSummaries } from '../src/safeIssues.js';
import { HANDOFF_BLOCK_CODES, validateAgentHandoff } from '../src/agentHandoff.js';
const secret = 'PRIVATE_SENTINEL_987654321.123';

test('public issue copy never reads source messages, actions, paths or extra metadata', () => {
  const raw = { code: 'invalid_observation', severity: secret, path: secret, row: secret, source_ref: secret };
  Object.defineProperty(raw, 'message', { get() { throw new Error('Private message must not be read'); } });
  Object.defineProperty(raw, 'action', { get() { throw new Error('Private action must not be read'); } });
  const [result] = safeIssueSummaries([raw]);
  assert.deepEqual(Object.keys(result), ['code', 'severity', 'message', 'action']);
  assert.equal(result.code, 'invalid_observation'); assert.equal(result.severity, 'error');
  assert.equal(JSON.stringify(result).includes(secret), false);
  assert.match(result.action, /Do not round or invent/);
});

test('unknown codes, prototype names and malformed entries become one fixed review issue', () => {
  const input = [{ code: secret, message: secret }, { code: '__proto__' }, { code: 'constructor' }, { code: 'toString' }, { code: { toString() { throw Error('Do not coerce'); } } }, null, 123, secret];
  const result = safeIssueSummaries(input);
  assert.equal(result.length, 1); assert.equal(result[0].code, 'needs_review'); assert.equal(result[0].severity, 'error');
  assert.equal(JSON.stringify(result).includes(secret), false);
  assert.deepEqual(safeIssueSummaries(null), result); assert.deepEqual(safeIssueSummaries([]), []);
});

test('deduplication cannot downgrade a known blocker and preserves legitimate flow reminders', () => {
  const issues = [{code:'pagination_incomplete',severity:'warning'}, {code:'pagination_incomplete',severity:'error'}, {code:'flow_activity_review',severity:'warning'}, {code:'flow_activity_review',severity:'error'}];
  assert.deepEqual(safeIssueSummaries(issues).map(({code,severity})=>({code,severity})), [{code:'pagination_incomplete',severity:'error'}, {code:'flow_activity_review',severity:'error'}]);
  assert.equal(safeIssueSummaries([{code:'flow_activity_review',severity:'warning'}])[0].severity, 'warning');
  assert.equal(safeIssueSummaries([{code:'flow_activity_review',severity:secret}])[0].severity, 'error');
  assert.equal(safeIssueSummaries([{code:'synthetic_example',severity:secret}])[0].severity, 'warning');
});

test('every acquisition blocker has specific fixed guidance without source-derived detail', () => {
  const result = safeIssueSummaries(HANDOFF_BLOCK_CODES.map(code=>({code,message:secret,action:secret,metadata:{secret}})));
  assert.deepEqual(result.map(item=>item.code), [...HANDOFF_BLOCK_CODES]);
  for (const item of result) { assert.equal(item.severity,'error'); assert(item.message.length > 10); assert(item.action.length > 20); }
  assert.equal(JSON.stringify(result).includes(secret), false);
  assert.match(result.find(item=>item.code==='missing_observations').action,/Never invent/);
  assert.match(result.find(item=>item.code==='source_not_retrieved').action,/explicitly authorized read-only/);
});

test('actual structural errors can be shared without their private path or parser message', () => {
  const validation = validateAgentHandoff(JSON.stringify({ [secret]: secret }));
  assert.equal(validation.valid, false);
  const result = safeIssueSummaries(validation.errors);
  assert(result.some(item=>item.code==='unknown_key')); assert(result.some(item=>item.code==='missing_key'));
  assert.equal(JSON.stringify(result).includes(secret),false);
  for (const code of ['invalid_json','size_limit','duplicate_key','unknown_key','missing_key','invalid_type','invalid_value','invalid_date','invalid_timestamp','invalid_decimal','decimal_range','date_order','invalid_range','invalid_encoding']) assert.equal(safeIssueSummaries([{code}])[0].code, code);
});

test('oversized issue arrays remain bounded and explicitly require full local review', () => {
  const input = Array.from({length:10001},()=>({code:'supplied_file',message:secret}));
  const result = safeIssueSummaries(input);
  assert.deepEqual(result.map(item=>item.code),['supplied_file','needs_review']);
  assert.equal(JSON.stringify(result).includes(secret),false);
});

test('returned issues are independent values and cannot poison later public copy', () => {
  const result = safeIssueSummaries([{code:'missing_periods'}]); result[0].message = secret; result.push({code:secret});
  assert.equal(JSON.stringify(safeIssueSummaries([{code:'missing_periods'}])).includes(secret),false);
});
