import assert from "node:assert/strict";
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { inspectProfile } from "../src/trackRecord.js";

// An independent checker for examples/, written from FORMAT.md with Node's own
// crypto instead of the app's code, so the specification and the app can't drift apart.
const text = readFileSync(new URL("../examples/example-profile.json", import.meta.url), "utf8");
const fingerprints = readFileSync(new URL("../examples/example-fingerprints.txt", import.meta.url), "utf8");
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function canonical(p) {
  return JSON.stringify({
    schema_version: p.schema_version,
    calculation_version: p.calculation_version,
    sequence: p.sequence,
    profile_id: p.profile_id,
    display_name: p.display_name,
    previous_sha256: p.previous_sha256,
    source_kind: p.source_kind,
    provider_authenticated: p.provider_authenticated,
    independent_timestamp: p.independent_timestamp,
    period: { start: p.period.start, end: p.period.end },
    periods_per_year: p.periods_per_year,
    relative_returns: p.relative_returns.map(({ start, end, return_e8 }) => ({ start, end, return_e8 })),
    coverage: { nav_observations: p.coverage.nav_observations, return_observations: p.coverage.return_observations, external_cash_flow_count: p.coverage.external_cash_flow_count },
    metrics: { total_return_twr_e8: p.metrics.total_return_twr_e8, annualized_volatility_e8: p.metrics.annualized_volatility_e8, max_drawdown_e8: p.metrics.max_drawdown_e8 },
  });
}

function units(x) {
  const scaled = x * 100000000;
  const floor = Math.floor(scaled);
  return (scaled - floor >= 0.5 ? floor + 1 : floor) || 0;
}

function metrics(returnUnits, periodsPerYear) {
  const returns = returnUnits.map((value) => value / 100000000);
  let wealth = 1;
  let peak = 1;
  let drawdown = 0;
  for (const r of returns) {
    wealth = wealth * (1 + r);
    peak = Math.max(peak, wealth);
    drawdown = Math.min(drawdown, wealth / peak - 1);
  }
  let sum = 0;
  for (const r of returns) sum = sum + r;
  const mean = sum / returns.length;
  let squares = 0;
  for (const r of returns) squares = squares + (r - mean) * (r - mean);
  const volatility = returns.length > 1 ? Math.sqrt(squares / (returns.length - 1)) * Math.sqrt(periodsPerYear) : null;
  return { total_return_twr_e8: units(wealth - 1), annualized_volatility_e8: volatility === null ? null : units(volatility), max_drawdown_e8: units(drawdown) };
}

test("the example profile passes the app's checker with its key code and published fingerprints", async () => {
  const result = await inspectProfile(text, { expectedKeyCode: "71dc-2b62-8045-f792-681b", publishedFingerprints: fingerprints });
  assert.equal(result.checks.key_code, "matched");
  assert.deepEqual(result.checks.published_fingerprints, { supplied: 2, matched: 2, latest_record: 2 });
  assert.deepEqual(result.summary.frequency_warnings, []);
});

test("an independent checker following FORMAT.md reaches the same result", () => {
  const profile = JSON.parse(text);
  const raw = Buffer.from(profile.public_key, "base64url");
  assert.equal(raw.length, 65);
  assert.equal(profile.profile_id, sha256(Buffer.concat([Buffer.from("n170.verify.profile-key.v3\n"), raw])));
  const keyCode = profile.profile_id.slice(0, 20).match(/.{4}/g).join("-");
  const key = createPublicKey({ format: "jwk", key: { kty: "EC", crv: "P-256", x: raw.subarray(1, 33).toString("base64url"), y: raw.subarray(33).toString("base64url") } });
  let previous = null;
  profile.stamps.forEach((stamp, index) => {
    const payload = stamp.payload;
    const bytes = Buffer.from(canonical(payload), "utf8");
    assert.equal(payload.sequence, index + 1);
    assert.equal(payload.previous_sha256, previous);
    assert.equal(sha256(bytes), stamp.sha256);
    const message = Buffer.concat([Buffer.from("n170.verify.stamp-signature.v3\n"), bytes]);
    assert.equal(verify("sha256", message, { key, dsaEncoding: "ieee-p1363" }, Buffer.from(stamp.signature, "base64url")), true);
    assert.deepEqual(metrics(payload.relative_returns.map(({ return_e8 }) => return_e8), payload.periods_per_year), payload.metrics);
    previous = stamp.sha256;
  });
  assert.equal(profile.stamps[0].sha256, "ef8581ab4870834ffede0a185ec56f6b00703e2b9f5db33389a7c2ce20cee4ef", "matches the worked example in FORMAT.md");
  const lines = fingerprints.trim().split("\n");
  assert.deepEqual(lines, profile.stamps.map((stamp) => `n170-verify key=${keyCode} record=${stamp.payload.sequence} end=${stamp.payload.period.end} sha256=${stamp.sha256}`));
});
