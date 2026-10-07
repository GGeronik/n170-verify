// Original N170 contract exercise, Apache-2.0. No AuditZK implementation is included.
// This optional module is intentionally independent of calculation and signing.
export const AUDITZK_ADAPTER_VERSION = "n170.adapter.auditzk.v1";
export const AUDITZK_REQUEST_VERSION = "n170.adapter.auditzk.mock-request.v1";

const prerequisiteNames = Object.freeze([
  "pinnedCodeAndMeasurementPolicy",
  "attestationReportAndEndorsements",
  "freshnessAndChallengePolicy",
  "reportBytesAndSignature",
  "attestedReportSigningKeyBinding",
  "declaredSourceAndScopeBinding",
]);
const checkNames = Object.freeze([
  "endorsementChain", "measurement", "freshness", "reportSignature", "reportBinding", "sourceBinding",
]);
const scenarios = Object.freeze({
  "all-checks-pass": null,
  "invalid-endorsement": "endorsementChain",
  "measurement-mismatch": "measurement",
  "stale-attestation": "freshness",
  "invalid-signature": "reportSignature",
  "report-binding-mismatch": "reportBinding",
  "source-binding-mismatch": "sourceBinding",
  "verifier-error": "error",
});
const limitation = "SYNTHETIC MOCK ONLY. No AuditZK service, TEE attestation, report signature, source authenticity, freshness, completeness or financial calculation has been verified.";

function freeze(value) {
  if (value && typeof value === "object") {
    Object.values(value).forEach(freeze);
    Object.freeze(value);
  }
  return value;
}

// Reject accessors, class instances and extra fields before reading input values.
// Input is a local JS contract, not an upstream AuditZK report or API response.
function plainRecord(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    throw new TypeError(`${label} must be a plain object.`);
  }
  const own = Reflect.ownKeys(value);
  if (own.some((key) => !Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), "value"))) {
    throw new TypeError(`${label} cannot contain accessors.`);
  }
  return own;
}

function object(value, keys, label) {
  const own = plainRecord(value, label);
  if (own.length !== keys.length || own.some((key) => typeof key !== "string" || !keys.includes(key))) {
    throw new TypeError(`${label} must contain exactly: ${keys.join(", ")}.`);
  }
}

function text(value, label) {
  if (typeof value !== "string" || value.length < 1 || value.length > 200 ||
      value.trim() !== value || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new TypeError(`${label} must contain 1–200 plain text characters without surrounding whitespace or controls.`);
  }
  return value;
}

function date(value, label) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value) ||
      !Number.isFinite(Date.parse(value)) || new Date(value).toISOString().slice(0, 10) !== value) {
    throw new TypeError(`${label} must be a valid YYYY-MM-DD date.`);
  }
  return value;
}

function requestSnapshot(request) {
  object(request, ["schema", "synthetic", "reportSha256", "attestationFormat", "sourceClaim"], "AuditZK mock request");
  if (request.schema !== AUDITZK_REQUEST_VERSION) throw new TypeError("Unsupported AuditZK mock request version.");
  if (request.synthetic !== true) throw new TypeError("Only explicitly synthetic mock requests are supported.");
  if (typeof request.reportSha256 !== "string" || !/^[a-f0-9]{64}$/.test(request.reportSha256)) {
    throw new TypeError("reportSha256 must be 64 lowercase hexadecimal characters; it is a declared digest only.");
  }
  if (!["amd-sev-snp", "unknown"].includes(request.attestationFormat)) throw new TypeError("Unsupported attestation format value.");
  object(request.sourceClaim, ["kind", "provider", "accountScope", "periodStart", "periodEnd"], "sourceClaim");
  const claim = request.sourceClaim;
  if (!["supplied-file", "provider-api", "unknown"].includes(claim.kind)) throw new TypeError("Unsupported source claim kind.");
  const sourceClaim = {
    kind: claim.kind,
    provider: text(claim.provider, "provider"),
    accountScope: text(claim.accountScope, "accountScope"),
    periodStart: date(claim.periodStart, "periodStart"),
    periodEnd: date(claim.periodEnd, "periodEnd"),
  };
  if (sourceClaim.periodEnd < sourceClaim.periodStart) throw new TypeError("Source claim period ends before it starts.");
  return freeze({
    schema: request.schema, synthetic: true, reportSha256: request.reportSha256,
    attestationFormat: request.attestationFormat, sourceClaim,
  });
}

export function auditZkCapabilities() {
  return freeze({
    schema: AUDITZK_ADAPTER_VERSION,
    integrationStatus: "mock-only",
    realIntegrationAvailable: false,
    grantStatus: "pending-written-grant-and-covered-revision",
    localMockAvailable: true,
    acceptsCredentials: false,
    networkAccess: false,
    financialCalculation: false,
    signedRecordModification: false,
    requestSchema: AUDITZK_REQUEST_VERSION,
    mockAttestationFormats: ["amd-sev-snp"],
    prerequisiteNames: [...prerequisiteNames],
    mockScenarios: Object.keys(scenarios),
    limitation,
  });
}

function result(request, mode, status, checks, missingPrerequisites = []) {
  return freeze({
    schema: AUDITZK_ADAPTER_VERSION,
    mode,
    status,
    synthetic: true,
    limitation,
    declaredReportSha256: request.reportSha256,
    sourceClaim: request.sourceClaim,
    sourceClaimStatus: "unverified-claim",
    sourceAuthenticity: "unknown",
    sourceFreshness: "unknown",
    sourceCompleteness: "unknown",
    realAttestationVerified: false,
    reportSignatureVerified: false,
    reportDigestVerified: false,
    sourceBindingVerified: false,
    financialCalculationVerified: false,
    signedRecordModification: false,
    missingPrerequisites,
    checks,
  });
}

// Disabled by default. Deliberate mock construction is the only available implementation.
// Missing or failed simulated evidence never falls back to passing verification.
export function createAuditZkAdapter(options = { mode: "disabled" }) {
  plainRecord(options, "Adapter options");
  if (options.mode === "disabled") {
    object(options, ["mode"], "Adapter options");
    return Object.freeze({
      capabilities: auditZkCapabilities,
      async verify(request) {
        const snapshot = requestSnapshot(request);
        return result(snapshot, "disabled", "unavailable", checkNames.map((check) => ({ check, status: "not-run" })));
      },
    });
  }
  object(options, ["mode", "scenario", "prerequisites"], "Mock adapter options");
  if (options.mode !== "mock") throw new TypeError("Real AuditZK integration is unavailable; select disabled or mock.");
  if (typeof options.scenario !== "string" || !Object.hasOwn(scenarios, options.scenario)) throw new TypeError("Unknown mock scenario.");
  object(options.prerequisites, prerequisiteNames, "Mock prerequisites");
  if (prerequisiteNames.some((name) => typeof options.prerequisites[name] !== "boolean")) {
    throw new TypeError("Every mock prerequisite must be an explicit boolean.");
  }
  const scenario = options.scenario;
  const missing = prerequisiteNames.filter((name) => !options.prerequisites[name]);
  return Object.freeze({
    capabilities: auditZkCapabilities,
    async verify(request) {
      const snapshot = requestSnapshot(request);
      const checks = checkNames.map((check) => ({ check, status: "not-run" }));
      if (snapshot.attestationFormat === "unknown") return result(snapshot, "mock", "unsupported-format", checks);
      if (missing.length) return result(snapshot, "mock", "prerequisites-missing", checks, [...missing]);
      if (scenario === "verifier-error") return result(snapshot, "mock", "mock-verifier-error", checks);
      for (const check of checks) check.status = check.check === scenarios[scenario] ? "mock-fail" : "mock-pass";
      return result(snapshot, "mock", scenarios[scenario] ? "mock-check-failed" : "mock-checks-passed", checks);
    },
  });
}
