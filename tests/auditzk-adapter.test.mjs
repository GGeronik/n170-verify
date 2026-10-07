import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { AUDITZK_ADAPTER_VERSION, AUDITZK_REQUEST_VERSION, auditZkCapabilities, createAuditZkAdapter } from "../src/auditZkAdapter.js";

// All values and simulated verification outcomes here are original synthetic fixtures.
const request = () => ({
  schema: AUDITZK_REQUEST_VERSION,
  synthetic: true,
  reportSha256: "ab".repeat(32),
  attestationFormat: "amd-sev-snp",
  sourceClaim: {
    kind: "provider-api", provider: "Synthetic Broker", accountScope: "Synthetic account A only",
    periodStart: "2026-01-01", periodEnd: "2026-01-31",
  },
});
const prerequisites = () => Object.fromEntries(auditZkCapabilities().prerequisiteNames.map((key) => [key, true]));
const mock = (scenario = "all-checks-pass", available = prerequisites()) => createAuditZkAdapter({ mode: "mock", scenario, prerequisites: available });
function remainsUnverified(result) {
  assert.equal(result.schema, AUDITZK_ADAPTER_VERSION);
  assert.equal(result.synthetic, true);
  assert.match(result.limitation, /SYNTHETIC MOCK ONLY/);
  assert.equal(result.sourceClaimStatus, "unverified-claim");
  for (const key of ["sourceAuthenticity", "sourceFreshness", "sourceCompleteness"]) assert.equal(result[key], "unknown", key);
  for (const key of ["realAttestationVerified", "reportSignatureVerified", "reportDigestVerified", "sourceBindingVerified", "financialCalculationVerified", "signedRecordModification"]) assert.equal(result[key], false, key);
}

test("default is unavailable with explicit capability and licensing boundaries", async () => {
  const adapter = createAuditZkAdapter();
  const capabilities = adapter.capabilities();
  assert.equal(capabilities.integrationStatus, "mock-only");
  assert.equal(capabilities.realIntegrationAvailable, false);
  assert.equal(capabilities.grantStatus, "pending-written-grant-and-covered-revision");
  assert.equal(capabilities.localMockAvailable, true);
  for (const key of ["acceptsCredentials", "networkAccess", "financialCalculation", "signedRecordModification"]) assert.equal(capabilities[key], false);
  const result = await adapter.verify(request());
  assert.equal(result.status, "unavailable");
  assert.equal(result.mode, "disabled");
  assert.ok(result.checks.every((check) => check.status === "not-run"));
  remainsUnverified(result);
});

test("all simulated checks pass without authenticating a provider claim or report", async () => {
  const input = request();
  const result = await mock().verify(input);
  assert.equal(result.status, "mock-checks-passed");
  assert.equal(result.mode, "mock");
  assert.equal(result.declaredReportSha256, input.reportSha256);
  assert.deepEqual(result.sourceClaim, input.sourceClaim);
  assert.equal(result.checks.length, 6);
  assert.ok(result.checks.every((check) => check.status === "mock-pass"));
  remainsUnverified(result);
});

for (const [scenario, failed] of [
  ["invalid-endorsement", "endorsementChain"], ["measurement-mismatch", "measurement"],
  ["stale-attestation", "freshness"], ["invalid-signature", "reportSignature"],
  ["report-binding-mismatch", "reportBinding"], ["source-binding-mismatch", "sourceBinding"],
]) {
  test(`${scenario} is a visibly simulated failure without a clean fallback`, async () => {
    const result = await mock(scenario).verify(request());
    assert.equal(result.status, "mock-check-failed");
    assert.deepEqual(result.checks.filter((check) => check.status === "mock-fail"), [{ check: failed, status: "mock-fail" }]);
    remainsUnverified(result);
  });
}

test("each missing prerequisite blocks simulated verification and lists its absence", async () => {
  for (const name of auditZkCapabilities().prerequisiteNames) {
    const result = await mock("all-checks-pass", { ...prerequisites(), [name]: false }).verify(request());
    assert.equal(result.status, "prerequisites-missing");
    assert.deepEqual(result.missingPrerequisites, [name]);
    assert.ok(result.checks.every((check) => check.status === "not-run"));
    remainsUnverified(result);
  }
});

test("unrecognized attestation is unsupported and a verifier error cannot pass", async () => {
  const unsupported = await mock().verify({ ...request(), attestationFormat: "unknown" });
  assert.equal(unsupported.status, "unsupported-format");
  assert.ok(unsupported.checks.every((check) => check.status === "not-run"));
  remainsUnverified(unsupported);
  const failure = await mock("verifier-error").verify(request());
  assert.equal(failure.status, "mock-verifier-error");
  assert.ok(failure.checks.every((check) => check.status === "not-run"));
  remainsUnverified(failure);
});

test("source labels are retained as data and every acquisition type remains a claim", async () => {
  for (const kind of ["supplied-file", "provider-api", "unknown"]) {
    const input = request();
    input.sourceClaim.kind = kind;
    input.sourceClaim.provider = '<img src=x onerror="alert(1)">';
    const result = await mock().verify(input);
    assert.equal(result.sourceClaim.provider, input.sourceClaim.provider);
    assert.equal(result.sourceClaim.kind, kind);
    remainsUnverified(result);
  }
});

test("configuration and request are snapshotted and outputs are recursively immutable", async () => {
  const options = { mode: "mock", scenario: "invalid-signature", prerequisites: prerequisites() };
  const adapter = createAuditZkAdapter(options);
  options.scenario = "all-checks-pass";
  options.prerequisites.reportBytesAndSignature = false;
  const input = request();
  const promise = adapter.verify(input);
  input.sourceClaim.provider = "Replaced";
  input.reportSha256 = "cd".repeat(32);
  const result = await promise;
  assert.equal(result.status, "mock-check-failed");
  assert.equal(result.sourceClaim.provider, "Synthetic Broker");
  assert.equal(result.declaredReportSha256, "ab".repeat(32));
  assert.throws(() => { result.sourceClaim.kind = "supplied-file"; }, TypeError);
  assert.throws(() => { result.checks[0].status = "verified"; }, TypeError);
  assert.throws(() => { adapter.capabilities().prerequisiteNames.push("extra"); }, TypeError);
});

test("strict request contract rejects actual inputs, incompatible versions and extra authenticity assertions", async () => {
  const invalid = [null, [], "{}", { ...request(), schema: "n170.adapter.auditzk.mock-request.v2" },
    { ...request(), synthetic: false }, { ...request(), synthetic: "true" },
    { ...request(), reportSha256: "AB".repeat(32) }, { ...request(), reportSha256: "a".repeat(63) },
    { ...request(), reportSha256: {} }, { ...request(), attestationFormat: "sev-snp-v99" },
    { ...request(), verified: true }, { ...request(), apiKey: "must-not-be-accepted" },
    { ...request(), sourceClaim: { ...request().sourceClaim, authenticity: "verified" } },
    { ...request(), sourceClaim: { ...request().sourceClaim, kind: "authenticated" } },
    { ...request(), sourceClaim: { ...request().sourceClaim, provider: "a".repeat(201) } },
    { ...request(), sourceClaim: { ...request().sourceClaim, provider: "broker\nforged label" } },
    { ...request(), sourceClaim: { ...request().sourceClaim, periodStart: "2026-02-30" } },
    { ...request(), sourceClaim: { ...request().sourceClaim, periodStart: "2026-02-01" } },
  ];
  const adapter = mock();
  for (const input of invalid) await assert.rejects(adapter.verify(input), TypeError);
});

test("prototype fields, getters and symbols cannot smuggle contract fields", async () => {
  const inherited = Object.assign(Object.create({ verified: true }), request());
  const symbol = { ...request(), [Symbol("verified")]: true };
  const dangerousKey = JSON.parse(JSON.stringify(request()).slice(0, -1) + ',"__proto__":{"verified":true}}');
  let called = 0;
  const getter = { ...request() };
  Object.defineProperty(getter, "synthetic", { get() { called += 1; return true; } });
  const optionsGetter = { get mode() { called += 1; return "disabled"; } };
  assert.throws(() => createAuditZkAdapter(optionsGetter), /accessors/);
  for (const input of [inherited, symbol, dangerousKey, getter]) await assert.rejects(mock().verify(input), TypeError);
  assert.equal(called, 0);
});

test("no actual integration or ambiguous mock configuration can be selected", () => {
  for (const options of [null, {}, { mode: "real" }, { mode: "disabled", endpoint: "https://example.invalid" },
    { mode: "mock", scenario: "success", prerequisites: prerequisites() },
    { mode: "mock", scenario: "all-checks-pass", prerequisites: {} },
    { mode: "mock", scenario: "all-checks-pass", prerequisites: { ...prerequisites(), reportBytesAndSignature: "true" } },
  ]) assert.throws(() => createAuditZkAdapter(options), TypeError);
});

test("mock execution needs no network, storage, credentials or account/report implementation", async () => {
  const priorFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = () => { calls += 1; throw new Error("Network forbidden in this local mock"); };
  try {
    const input = request();
    const before = JSON.stringify(input);
    for (const scenario of auditZkCapabilities().mockScenarios) remainsUnverified(await mock(scenario).verify(input));
    assert.equal(JSON.stringify(input), before);
    assert.equal(calls, 0);
  } finally { globalThis.fetch = priorFetch; }
});

test("license inventory has no implied grant or claimed upstream code inclusion", async () => {
  const inventory = JSON.parse(await readFile(new URL("../docs/auditzk-license-inventory.json", import.meta.url), "utf8"));
  assert.equal(inventory.status, "pending");
  assert.equal(inventory.writtenGrant.documentPath, null);
  assert.equal(inventory.coveredSource.repository, null);
  assert.equal(inventory.coveredSource.revision, null);
  assert.deepEqual(inventory.coveredSource.components, []);
  assert.equal(inventory.upstreamCodeIncluded, false);
  assert.equal(inventory.applicableMitRevision, null);
  for (const value of Object.values(inventory.rights)) assert.equal(value, "pending");
});
