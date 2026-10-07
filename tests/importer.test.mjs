import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { importStatement, detectImportFormat, parseCsv, correctImport, importDisclosure, ibkrSampleInput } from "../src/importer.js";
import { calculateEvidence } from "../src/calculator.js";
import { provenanceFromImport } from "../src/trackRecord.js";
const fixture = await readFile(new URL("./fixtures/import/ibkr-flex-synthetic.csv", import.meta.url), "utf8");
const options = { currency: "USD", flowTimingConfirmed: true };
const has = (review, code) => review.exceptions.some((item) => item.code === code);

test("documented IBKR source reconciles without treating fees/dividends as flows", async () => {
  assert.equal(fixture.trim(), ibkrSampleInput);
  const result = await importStatement(fixture, options);
  assert.equal(result.canCalculate, true);
  assert.equal(result.format, "ibkr-flex");
  assert.equal(result.rows.length, 4);
  assert.deepEqual(result.rows.map((row) => row.flow), ["0", "0", "0", "0"]);
  assert.equal(result.rows[0].date, "2025-01-01");
  assert.equal(result.rows.at(-1).nav, "10200");
  assert.equal(result.source.sha256, createHash("sha256").update(fixture).digest("hex"));
  assert.equal(result.source.authenticated, false);
  const total = calculateEvidence(result.normalizedCsv).metrics.total_return_twr;
  assert.ok(Math.abs(total - 0.02) < 1e-7, `Expected independent endpoint return 2%, got ${total}`);
});

test("changed NAV, missing components, overlapping/missing periods and duplicate rows block", async () => {
  assert.ok(has(await importStatement(fixture.replace("10000,10100", "10000,10101"), options), "reconciliation_difference"));
  assert.ok(has(await importStatement(fixture.replace("2025-01-03,2025-01-03", "2025-01-05,2025-01-05"), options), "missing_period"));
  assert.ok(has(await importStatement(fixture.replace("2025-01-03,2025-01-03", "2025-01-02,2025-01-03"), options), "overlapping_period"));
  const duplicate = fixture.trim() + "\n" + fixture.trim().split("\n").at(-1);
  assert.ok(has(await importStatement(duplicate, options), "duplicate_row"));
  assert.equal((await importStatement(duplicate, options)).canCalculate, false);
});

test("cash flow timing requires explicit owner claim, including netted summaries", async () => {
  const flowFile = fixture.split("\n").slice(0, 2).join("\n").replace("10000,10100,0", "10000,11100,1000");
  const blocked = await importStatement(flowFile, { currency: "USD" });
  assert.ok(has(blocked, "flow_timing"));
  assert.equal(blocked.canCalculate, false);
  const claimed = await importStatement(flowFile, { ...options, flowTimingConfirmed: true });
  assert.equal(claimed.canCalculate, true);
  assert.ok(has(claimed, "flow_timing_claim"));
  assert.equal(claimed.source.authenticated, false);
  assert.equal(claimed.rows.at(-1).flow, "1000");
});

test("account/currency mismatch and unsupported transfer/model blocks", async () => {
  const otherAccount = fixture.replace("SYNTHETIC,2025-01-03", "SECOND,2025-01-03");
  assert.ok(has(await importStatement(otherAccount, options), "multiple_accounts"));
  assert.ok(has(await importStatement(fixture), "currency_required"));
  assert.ok(has(await importStatement(fixture, { currency: "not a currency" }), "currency_required"));
  const asset = fixture.replace("10000,10100,0,0,0", "10000,10100,0,0,1");
  assert.ok(has(await importStatement(asset, options), "unsupported_event"));
  const missingColumn = fixture.split("\n").map((line) => line.split(",").filter((_, i) => i !== 8).join(",")).join("\n");
  assert.ok(has(await importStatement(missingColumn, options), "missing_columns"));
});

test("IBKR explicit currency fields cannot hide conflicts or missing values", async () => {
  const withCurrencies = (headers, values) => fixture.trim().split("\n")
    .map((line, index) => `${line},${index === 0 ? headers : (typeof values === 'function' ? values(index) : values)}`).join("\n");
  for (const [name, input, selected] of [
    ["conflicting columns", withCurrencies("Currency,Base Currency", "USD,EUR"), "USD"],
    ["conflicting owner selection", withCurrencies("Currency", "EUR"), "USD"],
    ["blank explicit Currency", withCurrencies("Currency", ""), "USD"],
    ["blank explicit Base Currency", withCurrencies("Base Currency", ""), "USD"],
    ["blank field beside valid field", withCurrencies("Currency,Base Currency", ",USD"), "USD"],
    ["currency change across rows", withCurrencies("Currency", index => index === 2 ? "EUR" : "USD"), "USD"],
  ]) {
    const result = await importStatement(input, { ...options, currency: selected });
    assert.equal(result.canCalculate, false, name);
    assert.ok(has(result, "currency_required"), name);
    assert.equal(has(result, "currency_assumption"), false, name);
    assert.equal(result.source.sha256, createHash("sha256").update(input).digest("hex"), name);
    assert.throws(() => provenanceFromImport(result, { accountScope: 'One account', reviewed: true }), /Resolve import exceptions/, name);
  }
});

test("IBKR matching explicit currencies keep review and signed provenance aligned", async () => {
  for (const headers of ["Currency", "Base Currency", "Currency,Base Currency"]) {
    const input = fixture.trim().split("\n").map((line, index) => `${line},${index === 0 ? headers : headers.split(',').map(() => 'EUR').join(',')}`).join("\n");
    const result = await importStatement(input, { ...options, currency: 'EUR' });
    assert.equal(result.canCalculate, true);
    assert.equal(result.currency, 'EUR');
    assert.equal(provenanceFromImport(result, { accountScope: 'One account', reviewed: true }).currency, 'EUR');
    assert.equal(has(result, "currency_assumption"), false);
    assert.deepEqual(result.rows.map(row => [row.nav, row.flow]), [['10000', '0'], ['10100', '0'], ['9999', '0'], ['10200', '0']]);
    assert.equal((await importStatement(input, { flowTimingConfirmed: true })).canCalculate, true);
  }
  const ownerSupplied = await importStatement(fixture, options);
  assert.equal(ownerSupplied.canCalculate, true);
  assert.equal(ownerSupplied.currency, 'USD');
  assert.ok(has(ownerSupplied, "currency_assumption"));
});

test("exact decimal reconciliation is independent of binary cancellation", async () => {
  const input = "Account ID,From Date,To Date,Starting Value,Ending Value,Deposits/Withdrawals,Internal Cash Transfers,Asset Transfers,Linking Adjustments,Other\nSYNTHETIC,20250102,20250102,0.1,999999999999999.9,999999999999999.8,0,0,0,0";
  const result = await importStatement(input, { ...options, flowTimingConfirmed: true });
  assert.equal(has(result, "reconciliation_difference"), false);
  assert.equal(result.rows[1].nav, "999999999999999.9");
  assert.equal(result.rows[1].flow, "999999999999999.8");
});

test("transaction/valuation-only formats have actionable blocks, never invented performance", async () => {
  const t212 = await importStatement("Action,Time,Total,Currency (Total)\nMarket buy,2025-01-02 12:00:00,100,USD");
  assert.equal(t212.format, "trading212"); assert.equal(t212.canCalculate, false); assert.ok(has(t212, "valuations_required")); assert.equal(t212.normalizedCsv, "");
  const pp = await importStatement("Date;Total Assets\n2025-01-02;100");
  assert.equal(pp.format, "portfolio-performance"); assert.ok(has(pp, "flows_required"));
});

test("CSV parser handles quoted separators/BOM/CRLF and rejects malformed/duplicate columns", () => {
  assert.deepEqual(parseCsv('\uFEFF"one","two"\r\n"a,b","a""b"\r\n').rows, [["a,b", 'a"b']]);
  assert.throws(() => parseCsv('one,two\n"unclosed,b'), /not closed/);
  assert.throws(() => parseCsv("Date,date\n1,2"), /unique/);
  assert.throws(() => parseCsv("one,two\n1,2,3"), /columns/);
  assert.throws(() => parseCsv('one,two\n"x"BAD,2'), /closing CSV quote/);
});

test("corrections preserve prior digests and cannot bypass source errors", async () => {
  const original = await importStatement(fixture, options);
  await assert.rejects(correctImport(original, fixture, "No actual change"), /identical/);
  await assert.rejects(correctImport(original, fixture, "oops"), /8–500/);
  const changed = fixture.replace("10000,10100", "10000,10101");
  const corrected = await correctImport(original, changed, "Corrected closing NAV against the retained statement", options);
  assert.equal(corrected.corrections.length, 1);
  assert.equal(corrected.original_source_sha256, original.source.sha256);
  assert.equal(corrected.corrections[0].previous_source_sha256, original.source.sha256);
  assert.equal(corrected.canCalculate, false);
  const disclosure = importDisclosure(original);
  assert.equal(disclosure.source_authenticated, false);
  assert.equal(disclosure.raw_values_included, false);
  assert.equal(JSON.stringify(disclosure).includes("SYNTHETIC"), false);
  assert.equal(JSON.stringify(disclosure).includes("10200"), false);
});

test("N170 import blocks duplicates, missing/invalid dates and invalid opening flow", async () => {
  assert.equal(detectImportFormat("date,nav,external_flow\n2025-01-01,100,0"), "n170");
  assert.ok(has(await importStatement("date,nav,external_flow\n2025-01-01,100,1\n2025-01-01,105,0"), "opening_flow"));
  assert.ok(has(await importStatement("date,nav,external_flow\n2025-01-01,100,0\n2025-02-30,105,0"), "invalid_observation"));
});

test("net-zero flow summaries still require cash activity review", async () => {
  const result = await importStatement(fixture, { currency: "USD" });
  assert.equal(result.canCalculate, false);
  assert.ok(has(result, "flow_activity_review"));
});
