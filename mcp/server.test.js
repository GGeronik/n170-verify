"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const { execFileSync } = require("node:child_process");
const path = require("node:path");
const { PassThrough } = require("node:stream");
const test = require("node:test");

const {
  CANONICAL_LEAF_NAMES,
  TOOLS,
  TRANSCRIPT_PRIVACY_NOTICE,
  handleJsonRpcMessage,
  jcsCanonicalizeStr,
  startStdioServer,
  verifyProofBundle,
} = require("./server.js");

const REPO_ROOT = path.resolve(__dirname, "..");
const CORE_PYTHONPATH = path.join(REPO_ROOT, "core");

function generatePythonFixtures() {
  const pyScript = `
import hashlib, json
from n170_verify import create_signed_proof_bundle, verify_proof_bundle
from n170_verify.contracts import (
    AccountScope, EnvironmentTier, OriginAssurance, ProviderApprovalState, compute_blinded_account_tag
)
from n170_verify.crypto import (
    CANONICAL_LEAF_NAMES, ChainCadencePolicy, ContinuityLogLeaf, NotaryNodeInfo,
    ProspectiveChainLink, PublisherKeyRecord, PublisherKeyRegistryDocument,
    TranscriptCommitmentKind, create_signed_broker_signature,
    create_signed_c2sp_checkpoint, create_signed_witness_attestation,
    generate_ed25519_keypair, jcs_canonicalize_str
)

pub_kp = generate_ed25519_keypair(b"\\x11" * 32)
notary1_kp = generate_ed25519_keypair(b"\\x22" * 32)
notary2_kp = generate_ed25519_keypair(b"\\x33" * 32)
broker_kp = generate_ed25519_keypair(b"\\x44" * 32)
ckpt_w_kp = generate_ed25519_keypair(b"\\x55" * 32)

ckpt = create_signed_c2sp_checkpoint(
    origin="n170.verify/continuity-log/v3",
    size=42,
    root_hash_hex="aa" * 32,
    publisher_kid="n170-active-2026",
    publisher_private_key_hex=pub_kp.private_key_hex,
    witness_signers=[("witness-1", ckpt_w_kp.private_key_hex, ckpt_w_kp.public_key_hex, "2026-02-01T00:00:00Z")],
)

registry = PublisherKeyRegistryDocument(
    updated_at_utc="2026-02-01T00:00:00Z",
    keys=[
        PublisherKeyRecord(
            publisher_kid="n170-active-2026",
            public_key_hex=pub_kp.public_key_hex,
            status="active",
            not_before_utc="2026-01-01T00:00:00Z",
            issuer_org="N170",
        )
    ],
    notaries=[
        NotaryNodeInfo(
            notary_id="notary-cf",
            operator_org="CloudflarePrivacy",
            asn="AS13335",
            public_key_hex=notary1_kp.public_key_hex,
        ),
        NotaryNodeInfo(
            notary_id="notary-pse",
            operator_org="PSEFoundation",
            asn="AS16509",
            public_key_hex=notary2_kp.public_key_hex,
        ),
    ],
    checkpoint=ckpt,
    pinned_broker_keys={"ibkr": {"ibkr-ed25519-v1": broker_kp.public_key_hex}},
)

source_sha = hashlib.sha256(b"ibkr-flex-statement-v3-bytes").hexdigest()
acct_tag = compute_blinded_account_tag("ibkr", "U9988776", "cc" * 32)

leaves = {
    "core_metrics": {"twr_decimal": 0.125, "sharpe_ratio": 2.15, "observation_count": 60},
    "indexed_curve": [{"timestamp_utc": "2026-01-01T00:00:00Z", "index_value": 100.0}, {"timestamp_utc": "2026-01-31T00:00:00Z", "index_value": 112.5}],
    "reconciliation": {"status": "reconciled_within_tolerance", "discrepancy_count": 0},
    "coaching_and_context": {"win_rate": 0.58, "sample_eligible": True},
    "capital_bracket": {"capital_bracket": "100k_to_1m"},
    "benchmark_alpha": {"benchmark_symbol": "SPY", "alpha_decimal": 0.045},
    "delayed_closed_trades": [{"symbol": "MSFT", "return_pct": 4.2}],
}

w1 = create_signed_witness_attestation(
    notary_private_key_hex=notary1_kp.private_key_hex,
    notary_id="notary-cf",
    server_sni="ndcdyn.interactivebrokers.com",
    sanitized_request_target="/AccountManagement/FlexWebService/GetStatement?t=[REDACTED]&q=[REDACTED]&v=3",
    redacted_headers=["Authorization: [REDACTED]"],
    commitment_kind=TranscriptCommitmentKind.WHOLE_BODY_SHA256,
    response_body_sha256=source_sha,
    session_timestamp_utc="2026-02-01T00:01:00Z",
)
w2 = create_signed_witness_attestation(
    notary_private_key_hex=notary2_kp.private_key_hex,
    notary_id="notary-pse",
    server_sni="ndcdyn.interactivebrokers.com",
    sanitized_request_target="/AccountManagement/FlexWebService/GetStatement?t=[REDACTED]&q=[REDACTED]&v=3",
    redacted_headers=["Authorization"],
    commitment_kind=TranscriptCommitmentKind.FIXED_64B_PADDED_WINDOW,
    response_body_sha256=source_sha,
    session_timestamp_utc="2026-02-01T00:02:00Z",
)

bundle_witnessed = create_signed_proof_bundle(
    proof_id="prf-py-node-witnessed",
    issued_at_utc="2026-02-01T00:05:00Z",
    publisher_kid="n170-active-2026",
    publisher_private_key_hex=pub_kp.private_key_hex,
    broker_id="ibkr",
    blinded_account_tag=acct_tag,
    account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
    environment_tier=EnvironmentTier.LIVE_PRODUCTION,
    claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
    source_body_sha256=source_sha,
    period_start_utc="2026-01-01T00:00:00Z",
    period_end_utc="2026-01-31T23:59:59Z",
    base_currency="USD",
    leaf_payloads=leaves,
    witness_attestations=[w1, w2],
)
redacted_bundle = bundle_witnessed.redact_leaves(["capital_bracket", "delayed_closed_trades"])
py_res = verify_proof_bundle(redacted_bundle, registry_doc=registry)

# Single witness bundle -> operator_retrieved downgrade
bundle_single_w = create_signed_proof_bundle(
    proof_id="prf-single-witness",
    issued_at_utc="2026-02-01T00:05:00Z",
    publisher_kid="n170-active-2026",
    publisher_private_key_hex=pub_kp.private_key_hex,
    broker_id="ibkr",
    blinded_account_tag=acct_tag,
    account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
    environment_tier=EnvironmentTier.LIVE_PRODUCTION,
    claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
    source_body_sha256=source_sha,
    period_start_utc="2026-01-01T00:00:00Z",
    period_end_utc="2026-01-31T23:59:59Z",
    base_currency="USD",
    leaf_payloads=leaves,
    witness_attestations=[w1],
)

# Broker-signed bundle -> broker_signed
b_sig = create_signed_broker_signature(
    broker_private_key_hex=broker_kp.private_key_hex,
    broker_id="ibkr",
    key_id="ibkr-ed25519-v1",
    signed_payload_sha256=source_sha,
)
bundle_broker_signed = create_signed_proof_bundle(
    proof_id="prf-broker-native",
    issued_at_utc="2026-02-01T00:05:00Z",
    publisher_kid="n170-active-2026",
    publisher_private_key_hex=pub_kp.private_key_hex,
    broker_id="ibkr",
    blinded_account_tag=acct_tag,
    account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
    environment_tier=EnvironmentTier.LIVE_PRODUCTION,
    claimed_origin_assurance=OriginAssurance.BROKER_SIGNED,
    source_body_sha256=source_sha,
    period_start_utc="2026-01-01T00:00:00Z",
    period_end_utc="2026-01-31T23:59:59Z",
    base_currency="USD",
    leaf_payloads=leaves,
    broker_native_signature=b_sig,
)

# 2-link prospective chain
policy = ChainCadencePolicy(expected_interval_seconds=86400, grace_window_seconds=14400)
link0 = ProspectiveChainLink(
    chain_id="chain-ibkr-1",
    sequence_number=0,
    prev_proof_hash=None,
    blinded_account_tag=acct_tag,
    enrolled_at_utc="2026-03-01T00:05:00Z",
    period_start_utc="2026-03-01T00:00:00Z",
    period_end_utc="2026-03-02T00:00:00Z",
    issued_at_utc="2026-03-02T01:00:00Z",
    cadence_policy=policy,
    beginning_index_value=100.0,
    ending_index_value=102.0,
    period_twr_decimal=0.02,
)
p0 = create_signed_proof_bundle(
    proof_id="chain-p0",
    issued_at_utc=link0.issued_at_utc,
    publisher_kid="n170-active-2026",
    publisher_private_key_hex=pub_kp.private_key_hex,
    broker_id="ibkr",
    blinded_account_tag=acct_tag,
    account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
    environment_tier=EnvironmentTier.LIVE_PRODUCTION,
    claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
    source_body_sha256=source_sha,
    period_start_utc=link0.period_start_utc,
    period_end_utc=link0.period_end_utc,
    base_currency="USD",
    leaf_payloads=leaves,
    prospective_chain_link=link0,
)
link1 = ProspectiveChainLink(
    chain_id="chain-ibkr-1",
    sequence_number=1,
    prev_proof_hash=p0.proof_hash(),
    blinded_account_tag=acct_tag,
    enrolled_at_utc="2026-03-01T00:05:00Z",
    period_start_utc="2026-03-02T00:00:00Z",
    period_end_utc="2026-03-03T00:00:00Z",
    issued_at_utc="2026-03-03T01:00:00Z",
    cadence_policy=policy,
    beginning_index_value=102.0,
    ending_index_value=105.06,
    period_twr_decimal=0.03,
)
p1 = create_signed_proof_bundle(
    proof_id="chain-p1",
    issued_at_utc=link1.issued_at_utc,
    publisher_kid="n170-active-2026",
    publisher_private_key_hex=pub_kp.private_key_hex,
    broker_id="ibkr",
    blinded_account_tag=acct_tag,
    account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
    environment_tier=EnvironmentTier.LIVE_PRODUCTION,
    claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
    source_body_sha256=source_sha,
    period_start_utc=link1.period_start_utc,
    period_end_utc=link1.period_end_utc,
    base_currency="USD",
    leaf_payloads=leaves,
    prospective_chain_link=link1,
)
log_leaves = [
    ContinuityLogLeaf(log_index=0, chain_id="chain-ibkr-1", blinded_account_tag=acct_tag, sequence_number=0, proof_hash=p0.proof_hash(), logged_at_utc=p0.issued_at_utc).to_dict(),
    ContinuityLogLeaf(log_index=1, chain_id="chain-ibkr-1", blinded_account_tag=acct_tag, sequence_number=1, proof_hash=p1.proof_hash(), logged_at_utc=p1.issued_at_utc).to_dict(),
]

w_evil1 = create_signed_witness_attestation(
    notary_private_key_hex=notary1_kp.private_key_hex,
    notary_id="notary-cf",
    server_sni="evil-replica.example",
    sanitized_request_target="/AccountManagement/FlexWebService/GetStatement?t=[REDACTED]&q=[REDACTED]&v=3",
    redacted_headers=["Authorization: [REDACTED]"],
    commitment_kind=TranscriptCommitmentKind.WHOLE_BODY_SHA256,
    response_body_sha256=source_sha,
    session_timestamp_utc="2026-02-01T00:01:00Z",
)
w_evil2 = create_signed_witness_attestation(
    notary_private_key_hex=notary2_kp.private_key_hex,
    notary_id="notary-pse",
    server_sni="evil-replica.example",
    sanitized_request_target="/AccountManagement/FlexWebService/GetStatement?t=[REDACTED]&q=[REDACTED]&v=3",
    redacted_headers=["Authorization: [REDACTED]"],
    commitment_kind=TranscriptCommitmentKind.WHOLE_BODY_SHA256,
    response_body_sha256=source_sha,
    session_timestamp_utc="2026-02-01T00:02:00Z",
)
bundle_evil_sni = create_signed_proof_bundle(
    proof_id="prf-evil-sni",
    issued_at_utc="2026-02-01T00:05:00Z",
    publisher_kid="n170-active-2026",
    publisher_private_key_hex=pub_kp.private_key_hex,
    broker_id="ibkr",
    blinded_account_tag=acct_tag,
    account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
    environment_tier=EnvironmentTier.LIVE_PRODUCTION,
    claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
    source_body_sha256=source_sha,
    period_start_utc="2026-01-01T00:00:00Z",
    period_end_utc="2026-01-31T23:59:59Z",
    base_currency="USD",
    leaf_payloads=leaves,
    witness_attestations=[w_evil1, w_evil2],
)
py_evil_sni_res = verify_proof_bundle(bundle_evil_sni, registry_doc=registry)

jcs_probe = {"z": [1.0, -0.0, 1e-7, 1e21], "a": "hello\\nworld", "\\u00e9": True}
print(json.dumps({
    "registry": registry.to_dict(),
    "bundle_witnessed": bundle_witnessed.to_dict(),
    "bundle_evil_sni": bundle_evil_sni.to_dict(),
    "py_evil_sni_result": py_evil_sni_res.to_dict(),
    "redacted_bundle": redacted_bundle.to_dict(),
    "py_redacted_result": py_res.to_dict(),
    "bundle_single_w": bundle_single_w.to_dict(),
    "bundle_broker_signed": bundle_broker_signed.to_dict(),
    "chain_p0": p0.to_dict(),
    "chain_p1": p1.to_dict(),
    "log_leaves": log_leaves,
    "jcs_probe_input": jcs_probe,
    "jcs_probe_expected": jcs_canonicalize_str(jcs_probe),
}))
`;

  const stdout = execFileSync(process.env.PYTHON_BIN || "python3", ["-B", "-c", pyScript], {
    env: {
      ...process.env,
      PYTHONDONTWRITEBYTECODE: "1",
      PYTHONPATH: CORE_PYTHONPATH,
    },
    encoding: "utf8",
  });
  return JSON.parse(stdout);
}

const FIXTURES = generatePythonFixtures();

test("RFC 8785 JCS canonicalizer matches Python jcs_canonicalize_str byte-for-byte", () => {
  const actual = jcsCanonicalizeStr(FIXTURES.jcs_probe_input);
  assert.equal(actual, FIXTURES.jcs_probe_expected);
  assert.equal(jcsCanonicalizeStr(-0), "0");
  assert.throws(() => jcsCanonicalizeStr(Number.NaN), RangeError);
});

test("Cross-verifies Python-generated selectively redacted VerifyProofBundle & k>=2 disjoint quorum", async () => {
  const nodeRes = await verifyProofBundle(FIXTURES.redacted_bundle, {
    registryDoc: FIXTURES.registry,
  });
  const pyRes = FIXTURES.py_redacted_result;

  assert.equal(nodeRes.valid, true);
  assert.equal(nodeRes.valid, pyRes.valid);
  assert.equal(nodeRes.proof_hash, pyRes.proof_hash);
  assert.equal(nodeRes.signature_valid, true);
  assert.equal(nodeRes.merkle_valid, true);
  assert.equal(nodeRes.transcript_safety_ok, true);
  assert.equal(nodeRes.signer_trust_status, "official_n170_hosted");
  assert.equal(nodeRes.effective_origin_assurance, "independently_witnessed_tls");
  assert.equal(nodeRes.witness_quorum.disjoint_quorum_size, 2);
  assert.deepEqual(nodeRes.assurance_profile, pyRes.assurance_profile);
  assert.deepEqual(nodeRes.disclosed_leaf_names, pyRes.disclosed_leaf_names);
  assert.deepEqual(nodeRes.undisclosed_leaf_names, ["capital_bracket", "delayed_closed_trades"]);
});

test("Evaluates single-witness downgrade and BrokerNativeSignature upgrade identically to Python", async () => {
  const singleRes = await verifyProofBundle(FIXTURES.bundle_single_w, {
    registryDoc: FIXTURES.registry,
  });
  assert.equal(singleRes.valid, true);
  assert.equal(singleRes.effective_origin_assurance, "operator_retrieved");
  assert.equal(singleRes.witness_quorum.disjoint_quorum_size, 1);

  const brokerRes = await verifyProofBundle(FIXTURES.bundle_broker_signed, {
    registryDoc: FIXTURES.registry,
  });
  assert.equal(brokerRes.valid, true);
  assert.equal(brokerRes.effective_origin_assurance, "broker_signed");
  assert.equal(brokerRes.witness_quorum.broker_signature_valid, true);
});

test("Verifies 2-link prospective chain and rejects tampered Merkle payload or signature", async () => {
  const chainRes = await verifyProofBundle(FIXTURES.chain_p1, {
    registryDoc: FIXTURES.registry,
    chainHistory: [FIXTURES.chain_p0],
    continuityLogLeaves: FIXTURES.log_leaves,
    nowUtc: "2026-03-03T12:00:00Z",
  });
  assert.equal(chainRes.valid, true);
  assert.equal(chainRes.effective_chain_continuity_mode, "prospective_continuous");
  assert.equal(chainRes.chain_verification.verified_length, 2);

  // Tamper disclosed leaf metric -> Merkle verification must fail closed
  const tamperedLeaf = structuredClone(FIXTURES.redacted_bundle);
  tamperedLeaf.disclosed_leaves[0].payload.twr_decimal = 0.999;
  const tamperedRes = await verifyProofBundle(tamperedLeaf, { registryDoc: FIXTURES.registry });
  assert.equal(tamperedRes.valid, false);
  assert.equal(tamperedRes.merkle_valid, false);

  // Tamper signature -> Ed25519 verification must fail closed
  const badSig = structuredClone(FIXTURES.redacted_bundle);
  badSig.signature_hex = "00".repeat(64);
  const badSigRes = await verifyProofBundle(badSig, { registryDoc: FIXTURES.registry });
  assert.equal(badSigRes.valid, false);
  assert.equal(badSigRes.signature_valid, false);
});

test("MCP JSON-RPC tools enforce additionalProperties=false, zero credentials/paths, and privacy notice", async () => {
  assert.equal(TOOLS.length, 3);
  for (const tool of TOOLS) {
    assert.equal(tool.inputSchema.additionalProperties, false);
  }

  const initResp = await handleJsonRpcMessage({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: { protocolVersion: "2025-11-25" },
  });
  assert.equal(initResp.result.serverInfo.name, "n170-verify-mcp");
  assert.ok(initResp.result.instructions.includes("TRANSCRIPT PRIVACY NOTICE"));

  const capResp = await handleJsonRpcMessage({
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: { name: "n170_verify_capabilities", arguments: {} },
  });
  assert.equal(capResp.result.isError, false);
  const capPayload = JSON.parse(capResp.result.content[0].text);
  assert.deepEqual(capPayload.canonical_leaf_names, CANONICAL_LEAF_NAMES);
  assert.equal(capPayload.transcript_privacy_notice, TRANSCRIPT_PRIVACY_NOTICE);

  const checkResp = await handleJsonRpcMessage(
    {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "n170_verify_check_bundle",
        arguments: {
          bundle: FIXTURES.redacted_bundle,
        },
      },
    },
    { defaultRegistryDoc: FIXTURES.registry }
  );
  assert.equal(checkResp.result.isError, false);
  const checkPayload = JSON.parse(checkResp.result.content[0].text);
  assert.equal(checkPayload.valid, true);
  assert.equal(checkPayload.effective_origin_assurance, "independently_witnessed_tls");

  const inspectResp = await handleJsonRpcMessage(
    {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: {
        name: "n170_verify_inspect_public_proof",
        arguments: {
          proof_id: "prf-py-node-witnessed",
          leaf_names: ["core_metrics", "benchmark_alpha"],
        },
      },
    },
    {
      defaultRegistryDoc: FIXTURES.registry,
      publicProofResolver: async (id) => {
        assert.equal(id, "prf-py-node-witnessed");
        return FIXTURES.redacted_bundle;
      },
    }
  );
  assert.equal(inspectResp.result.isError, false);
  const inspectPayload = JSON.parse(inspectResp.result.content[0].text);
  assert.equal(inspectPayload.valid, true);
  assert.deepEqual(Object.keys(inspectPayload.disclosed_payloads).sort(), [
    "benchmark_alpha",
    "core_metrics",
  ]);

  // Reject smuggled credentials, filesystem paths, URLs, and unknown properties
  const forbiddenCases = [
    { name: "n170_verify_capabilities", arguments: { extra_field: 1 } },
    { name: "n170_verify_check_bundle", arguments: { bundle: FIXTURES.redacted_bundle, api_key: "leak" } },
    { name: "n170_verify_inspect_public_proof", arguments: { file_path: "/etc/passwd" } },
    { name: "n170_verify_inspect_public_proof", arguments: { proof_id: "https://evil.example/p.json" } },
  ];
  for (const badParams of forbiddenCases) {
    const errResp = await handleJsonRpcMessage({
      jsonrpc: "2.0",
      id: 99,
      method: "tools/call",
      params: badParams,
    });
    assert.equal(errResp.result.isError, true);
  }
});

test("Stdio newline-delimited JSON-RPC server processes requests cleanly", async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const rl = startStdioServer({ input, output });

  const replyPromise = new Promise((resolve) => {
    output.once("data", (chunk) => {
      resolve(JSON.parse(chunk.toString("utf8").trim()));
    });
  });

  input.write(
    `${JSON.stringify({
      jsonrpc: "2.0",
      id: 77,
      method: "tools/list",
    })}\n`
  );
  const reply = await replyPromise;
  rl.close();
  input.end();

  assert.equal(reply.id, 77);
  assert.deepEqual(
    reply.result.tools.map((t) => t.name),
    ["n170_verify_capabilities", "n170_verify_check_bundle", "n170_verify_inspect_public_proof"]
  );
});

test("MCP inspect_public_proof & check_bundle resolve pinned apiBaseUrl via fetchImpl", async () => {
  const calls = [];
  const mockFetch = async (url) => {
    calls.push(url);
    if (url === "https://verify-api.internal/.well-known/n170-verify-keys.json") {
      return {
        ok: true,
        status: 200,
        json: async () => FIXTURES.registry,
      };
    }
    if (url === "https://verify-api.internal/api/v1/proofs/prf-py-node-witnessed") {
      return {
        ok: true,
        status: 200,
        json: async () => ({
          proof_bundle: FIXTURES.redacted_bundle,
          proof_hash: FIXTURES.py_redacted_result.proof_hash,
        }),
      };
    }
    return { ok: false, status: 404, json: async () => ({ error: "not_found" }) };
  };

  const inspectResp = await handleJsonRpcMessage(
    {
      jsonrpc: "2.0",
      id: 101,
      method: "tools/call",
      params: {
        name: "n170_verify_inspect_public_proof",
        arguments: {
          proof_id: "prf-py-node-witnessed",
          leaf_names: ["core_metrics"],
        },
      },
    },
    {
      apiBaseUrl: "https://verify-api.internal/",
      fetchImpl: mockFetch,
    }
  );

  assert.equal(inspectResp.result.isError, false);
  const payload = JSON.parse(inspectResp.result.content[0].text);
  assert.equal(payload.valid, true);
  assert.equal(payload.assurance_profile.signer_trust_status, "official_n170_hosted");
  assert.equal(payload.assurance_profile.effective_origin_assurance, "independently_witnessed_tls");
  assert.deepEqual(Object.keys(payload.disclosed_payloads), ["core_metrics"]);
  assert.deepEqual(calls, [
    "https://verify-api.internal/api/v1/proofs/prf-py-node-witnessed",
    "https://verify-api.internal/.well-known/n170-verify-keys.json",
  ]);
});

test("Red-team: caller-supplied arguments.registry_doc without host config is untrusted", async () => {
  const untrustedResp = await handleJsonRpcMessage({
    jsonrpc: "2.0",
    id: 201,
    method: "tools/call",
    params: {
      name: "n170_verify_check_bundle",
      arguments: {
        bundle: FIXTURES.redacted_bundle,
        registry_doc: FIXTURES.registry,
      },
    },
  });
  assert.equal(untrustedResp.result.isError, false);
  const payload = JSON.parse(untrustedResp.result.content[0].text);
  assert.equal(payload.valid, true);
  assert.equal(payload.signer_trust_status, "unrecognized_self_hosted_signer");
  assert.equal(payload.effective_origin_assurance, "self_reported");
  assert.notEqual(payload.signer_trust_status, "official_n170_hosted");
  assert.notEqual(payload.effective_origin_assurance, "independently_witnessed_tls");
  assert.ok(
    payload.warnings.some((w) =>
      w.includes("Caller-supplied registry_doc is untrusted")
    )
  );

  // Revoked key in caller-supplied registry_doc still fails closed as revoked_key
  const revokedReg = structuredClone(FIXTURES.registry);
  revokedReg.keys[0].status = "revoked";
  const revokedResp = await handleJsonRpcMessage({
    jsonrpc: "2.0",
    id: 202,
    method: "tools/call",
    params: {
      name: "n170_verify_check_bundle",
      arguments: {
        bundle: FIXTURES.redacted_bundle,
        registry_doc: revokedReg,
      },
    },
  });
  const revokedPayload = JSON.parse(revokedResp.result.content[0].text);
  assert.equal(revokedPayload.valid, false);
  assert.equal(revokedPayload.signer_trust_status, "revoked_key");
});

test("Red-team: caller-supplied arguments.registry_doc cannot override pinned defaultRegistryDoc or apiBaseUrl", async () => {
  const emptyAttackerRegistry = {
    updated_at_utc: "2026-02-01T00:00:00Z",
    keys: [],
    notaries: [],
  };

  // 1. Pinned defaultRegistryDoc wins over forged caller registry_doc
  const respPinnedDoc = await handleJsonRpcMessage(
    {
      jsonrpc: "2.0",
      id: 203,
      method: "tools/call",
      params: {
        name: "n170_verify_check_bundle",
        arguments: {
          bundle: FIXTURES.redacted_bundle,
          registry_doc: emptyAttackerRegistry,
        },
      },
    },
    { defaultRegistryDoc: FIXTURES.registry }
  );
  const pinnedPayload = JSON.parse(respPinnedDoc.result.content[0].text);
  assert.equal(pinnedPayload.signer_trust_status, "official_n170_hosted");
  assert.equal(pinnedPayload.effective_origin_assurance, "independently_witnessed_tls");
  assert.ok(
    pinnedPayload.warnings.includes(
      "Ignored caller-supplied registry_doc because a pinned N170 Verify registry is configured"
    )
  );

  // 2. Pinned apiBaseUrl wins over forged caller registry_doc containing attacker keys
  const respPinnedApi = await handleJsonRpcMessage(
    {
      jsonrpc: "2.0",
      id: 204,
      method: "tools/call",
      params: {
        name: "n170_verify_check_bundle",
        arguments: {
          bundle: FIXTURES.redacted_bundle,
          registry_doc: FIXTURES.registry,
        },
      },
    },
    {
      apiBaseUrl: "https://verify-api.internal",
      fetchImpl: async () => ({
        ok: true,
        status: 200,
        json: async () => emptyAttackerRegistry,
      }),
    }
  );
  const apiPayload = JSON.parse(respPinnedApi.result.content[0].text);
  assert.equal(apiPayload.signer_trust_status, "unrecognized_self_hosted_signer");
  assert.equal(apiPayload.effective_origin_assurance, "self_reported");
  assert.ok(
    apiPayload.warnings.includes(
      "Ignored caller-supplied registry_doc because a pinned N170 Verify registry is configured"
    )
  );
});

test("Red-team: mismatched witness server_sni (evil-replica.example) is rejected identically to Python", async () => {
  const nodeRes = await verifyProofBundle(FIXTURES.bundle_evil_sni, {
    registryDoc: FIXTURES.registry,
  });
  const pyRes = FIXTURES.py_evil_sni_result;
  assert.equal(nodeRes.valid, true);
  assert.equal(nodeRes.effective_origin_assurance, "operator_retrieved");
  assert.equal(nodeRes.effective_origin_assurance, pyRes.effective_origin_assurance);
  assert.equal(nodeRes.witness_quorum.valid_witness_count, 0);
  assert.equal(nodeRes.witness_quorum.disjoint_quorum_size, 0);
  assert.ok(
    nodeRes.warnings.some((w) =>
      w.includes("is not an official TLS endpoint for broker_id='ibkr'")
    )
  );
});

test("Verifies examples/specimen-s1.verify.json against n170-specimen-keys.json with 3-way parity and rejects tampered copy", async () => {
  const specimenPath = path.resolve(__dirname, "../examples/specimen-s1.verify.json");
  const registryPath = path.resolve(__dirname, "../web/public/specimens/n170-specimen-keys.json");

  if (!fs.existsSync(specimenPath) || !fs.existsSync(registryPath)) {
    return;
  }

  const bundle = JSON.parse(fs.readFileSync(specimenPath, "utf8"));
  const registry = JSON.parse(fs.readFileSync(registryPath, "utf8"));

  const res = await verifyProofBundle(bundle, {
    registryDoc: registry,
    nowUtc: "2026-04-02T00:00:00Z",
  });

  assert.strictEqual(res.valid, true);
  assert.strictEqual(typeof res.proof_hash, "string");
  assert.strictEqual(res.proof_hash.length, 64);
  assert.strictEqual(res.effective_origin_assurance, "independently_witnessed_tls");
  assert.strictEqual(res.assurance_profile.account_scope, "all_enumerated_subaccounts");
  assert.strictEqual(res.assurance_profile.provider_approval_state, "approved_live");
  assert.strictEqual(res.assurance_profile.environment_tier, "live_production");
  assert.strictEqual(res.signer_trust_status, "official_n170_hosted");
  assert.strictEqual(res.effective_chain_continuity_mode, "unenrolled_single_snapshot");
  assert.strictEqual(res.witness_quorum.disjoint_quorum_size, 3);
  assert.strictEqual(res.errors.length, 0);

  // Tamper with Merkle leaf payload
  const tamperedLeaf = JSON.parse(JSON.stringify(bundle));
  const coreLeaf = tamperedLeaf.disclosed_leaves.find((l) => l.leaf_name === "core_metrics");
  assert.ok(coreLeaf, "core_metrics disclosed leaf must exist");
  coreLeaf.payload.twr_decimal = 0.999;
  const tamperedLeafRes = await verifyProofBundle(tamperedLeaf, {
    registryDoc: registry,
    nowUtc: "2026-04-02T00:00:00Z",
  });
  assert.strictEqual(tamperedLeafRes.valid, false);
  assert.ok(tamperedLeafRes.errors.length > 0);

  // Tamper with publisher signature
  const tamperedSig = JSON.parse(JSON.stringify(bundle));
  tamperedSig.signature_hex = "00".repeat(64);
  const tamperedSigRes = await verifyProofBundle(tamperedSig, {
    registryDoc: registry,
    nowUtc: "2026-04-02T00:00:00Z",
  });
  assert.strictEqual(tamperedSigRes.valid, false);
  assert.ok(tamperedSigRes.errors.length > 0);
});
