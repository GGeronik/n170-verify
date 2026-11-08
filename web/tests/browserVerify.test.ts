import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  CANONICAL_LEAF_NAMES,
  ChainContinuityMode,
  OriginAssurance,
  SignerTrustStatus,
  VERIFY_SCHEMA_VERSION,
  extractTypedLeaves,
  type ContinuityLogLeaf,
  type PublisherKeyRegistryDocument,
  type VerifyProofBundle,
} from "../src/lib/contracts.ts";
import {
  computeProofHash,
  jcsCanonicalizeStr,
  jcsSha256Hex,
  redactProofBundleLeaves,
  verifyC2spCheckpoint,
  verifyProofBundle,
} from "../src/lib/browserVerify.ts";
import {
  fetchActiveRegistryDocument,
  fetchLeaderboardProfilesFromApi,
  getBadgeSvgUrl,
  submitOneShotVerification,
} from "../src/lib/apiClient.ts";
import {
  BUNDLE_COACHING_STUDIO,
  BUNDLE_COACHING_STUDIO_FULL,
  BUNDLE_CUSTODY_SIGNED,
  BUNDLE_DISCREPANCY_XRAY,
  BUNDLE_INSTITUTIONAL_FUND,
  BUNDLE_INSTITUTIONAL_SEQ0,
  BUNDLE_INSTITUTIONAL_SEQ1,
  BUNDLE_RETIRED_HISTORICAL,
  DEMO_CONTINUITY_LOG_LEAVES,
  DEMO_REGISTRY_DOCUMENT,
  SHOWCASE_PROFILES,
} from "../src/lib/demoFixtures.ts";

const CORE_PYTHON_DIR = fileURLToPath(new URL("../../core", import.meta.url));

function runPythonJson<T>(script: string): T {
  const stdout = execFileSync("python3", ["-B", "-c", script], {
    env: {
      ...process.env,
      PYTHONDONTWRITEBYTECODE: "1",
      PYTHONPATH: CORE_PYTHON_DIR,
    },
    encoding: "utf-8",
    maxBuffer: 16 * 1024 * 1024,
  });
  return JSON.parse(stdout) as T;
}

test("RFC 8785 JCS canonicalization matches Python across UTF-16 key ordering and ES6 floats", async () => {
  const sample = {
    z_zero: -0.0,
    exp_high: 1e21,
    exp_border: 1e20,
    exp_small_fixed: 1e-6,
    exp_small_sci: 1e-7,
    float_sum: 0.1 + 0.2,
    controls: "line1\nline2\t\"quoted\"\\\b\f\r\u0001\u001f",
    // Astral emoji U+1F600 (0xD83D 0xDE00) MUST sort BEFORE U+E000 (0xE000) in UTF-16 code units!
    utf16_order: {
      "\uE000": "bmp_private_use_0xE000",
      "\u{1F600}": "astral_surrogate_0xD83D",
      a: 1,
    },
    nested: [null, true, false, -123456.789, { b: 2, a: 1 }],
  };

  const tsCanonical = jcsCanonicalizeStr(sample);
  const tsDigest = await jcsSha256Hex(sample);

  const pyRes = runPythonJson<{ canonical: string; sha256: string }>(`
import json
from n170_verify.crypto.canonical import jcs_canonicalize_str, jcs_sha256_hex

sample = {
    "z_zero": -0.0,
    "exp_high": 1e21,
    "exp_border": 1e20,
    "exp_small_fixed": 1e-6,
    "exp_small_sci": 1e-7,
    "float_sum": 0.1 + 0.2,
    "controls": "line1\\nline2\\t\\"quoted\\"\\\\\\b\\f\\r\\x01\\x1f",
    "utf16_order": {
        "\\ue000": "bmp_private_use_0xE000",
        "\\U0001f600": "astral_surrogate_0xD83D",
        "a": 1,
    },
    "nested": [None, True, False, -123456.789, {"b": 2, "a": 1}],
}
print(json.dumps({
    "canonical": jcs_canonicalize_str(sample),
    "sha256": jcs_sha256_hex(sample),
}))
`);

  assert.equal(tsCanonical, pyRes.canonical);
  assert.equal(tsDigest, pyRes.sha256);

  // Reject non-finite numbers and lone UTF-16 surrogates
  assert.throws(() => jcsCanonicalizeStr({ bad: Number.NaN }), /forbids non-finite/);
  assert.throws(() => jcsCanonicalizeStr({ bad: Number.POSITIVE_INFINITY }), /forbids non-finite/);
  assert.throws(() => jcsCanonicalizeStr({ bad: "\uD800" }), /lone UTF-16 surrogate/);
  assert.throws(() => jcsCanonicalizeStr({ bad: "\uDFFF" }), /lone UTF-16 surrogate/);
});

test("Public demo fixtures and C2SP checkpoint verify end-to-end via WebCrypto", async () => {
  assert.ok(DEMO_REGISTRY_DOCUMENT.checkpoint);
  const activeKey = DEMO_REGISTRY_DOCUMENT.keys.find(
    (k) => k.publisher_kid === DEMO_REGISTRY_DOCUMENT.checkpoint!.publisher_kid,
  );
  assert.ok(activeKey);

  const ckptCheck = await verifyC2spCheckpoint(DEMO_REGISTRY_DOCUMENT.checkpoint, {
    publisherPublicKeyHex: activeKey.public_key_hex,
    minWitnessCosignatures: 2,
  });
  assert.equal(ckptCheck.valid, true);
  assert.equal(ckptCheck.validWitnessIds.length, 2);

  // 1. Flagship institutional continuous chain (#0 -> #1 -> #2)
  const instRes = await verifyProofBundle(BUNDLE_INSTITUTIONAL_FUND, {
    registryDoc: DEMO_REGISTRY_DOCUMENT,
    chainHistory: [BUNDLE_INSTITUTIONAL_SEQ0, BUNDLE_INSTITUTIONAL_SEQ1],
    continuityLogLeaves: DEMO_CONTINUITY_LOG_LEAVES,
    nowUtc: "2026-04-02T00:00:00Z",
  });
  assert.equal(instRes.valid, true);
  assert.equal(
    instRes.effective_origin_assurance,
    OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
  );
  assert.equal(instRes.witness_quorum.disjoint_quorum_size, 3);
  assert.equal(
    instRes.effective_chain_continuity_mode,
    ChainContinuityMode.PROSPECTIVE_CONTINUOUS,
  );
  assert.equal(instRes.signer_trust_status, SignerTrustStatus.OFFICIAL_N170_HOSTED);
  assert.equal(instRes.disclosed_leaf_names.length, CANONICAL_LEAF_NAMES.length);

  // 2. Discrepancy X-Ray bundle (single notary claiming independently_witnessed_tls -> downgraded)
  const xrayRes = await verifyProofBundle(BUNDLE_DISCREPANCY_XRAY, {
    registryDoc: DEMO_REGISTRY_DOCUMENT,
  });
  assert.equal(xrayRes.valid, true);
  assert.equal(
    BUNDLE_DISCREPANCY_XRAY.claimed_origin_assurance,
    OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
  );
  assert.equal(
    xrayRes.effective_origin_assurance,
    OriginAssurance.OPERATOR_RETRIEVED,
  );
  assert.equal(xrayRes.witness_quorum.disjoint_quorum_size, 1);
  assert.ok(xrayRes.warnings.length >= 1);

  // 3. Coaching Studio selectively redacted bundle + client-side redaction equivalence
  const coachRes = await verifyProofBundle(BUNDLE_COACHING_STUDIO, {
    registryDoc: DEMO_REGISTRY_DOCUMENT,
  });
  assert.equal(coachRes.valid, true);
  assert.deepEqual(coachRes.undisclosed_leaf_names, [
    "capital_bracket",
    "delayed_closed_trades",
  ]);
  const clientRedacted = redactProofBundleLeaves(BUNDLE_COACHING_STUDIO_FULL, [
    "capital_bracket",
    "delayed_closed_trades",
  ]);
  assert.equal(
    await computeProofHash(clientRedacted),
    await computeProofHash(BUNDLE_COACHING_STUDIO),
  );
  const clientRedactedRes = await verifyProofBundle(clientRedacted, {
    registryDoc: DEMO_REGISTRY_DOCUMENT,
  });
  assert.equal(clientRedactedRes.valid, true);

  // 4. Custody first-party broker-signed bundle
  const custodyRes = await verifyProofBundle(BUNDLE_CUSTODY_SIGNED, {
    registryDoc: DEMO_REGISTRY_DOCUMENT,
  });
  assert.equal(custodyRes.valid, true);
  assert.equal(
    custodyRes.effective_origin_assurance,
    OriginAssurance.BROKER_SIGNED,
  );
  assert.equal(custodyRes.witness_quorum.broker_signature_valid, true);

  // 5. Retired historical key + >24h genesis lag backfill bundle
  const histRes = await verifyProofBundle(BUNDLE_RETIRED_HISTORICAL, {
    registryDoc: DEMO_REGISTRY_DOCUMENT,
  });
  assert.equal(histRes.valid, true);
  assert.equal(
    histRes.signer_trust_status,
    SignerTrustStatus.RETIRED_HISTORICAL_VALID,
  );
  assert.equal(
    histRes.effective_chain_continuity_mode,
    ChainContinuityMode.RETROSPECTIVE_BACKFILL,
  );
});

interface CrossLangCase {
  name: string;
  bundle: VerifyProofBundle;
  registry: PublisherKeyRegistryDocument | null;
  chain_history: VerifyProofBundle[];
  continuity_log_leaves: ContinuityLogLeaf[] | null;
  now_utc: string | null;
  python_result: {
    valid: boolean;
    proof_hash: string;
    signature_valid: boolean;
    merkle_valid: boolean;
    transcript_safety_ok: boolean;
    signer_trust_status: string;
    effective_origin_assurance: string;
    effective_chain_continuity_mode: string;
    disclosed_leaf_names: string[];
    undisclosed_leaf_names: string[];
    witness_quorum: {
      effective_origin_assurance: string;
      valid_witness_count: number;
      disjoint_quorum_size: number;
      distinct_org_count: number;
      distinct_asn_count: number;
      broker_signature_valid: boolean;
    };
  };
}

test("Cross-language parity: Python verify_proof_bundle vs TypeScript WebCrypto across all trust, downgrade, redaction, and chain edge cases", async () => {
  const cases = runPythonJson<CrossLangCase[]>(`
import hashlib
import json

from n170_verify.contracts import (
    AccountScope,
    EnvironmentTier,
    OriginAssurance,
    ProviderApprovalState,
    create_signed_proof_bundle,
    verify_proof_bundle,
)
from n170_verify.crypto import (
    ChainCadencePolicy,
    ContinuityLogLeaf,
    NotaryNodeInfo,
    ProspectiveChainLink,
    PublisherKeyRecord,
    PublisherKeyRegistryDocument,
    TranscriptCommitmentKind,
    create_signed_c2sp_checkpoint,
    create_signed_witness_attestation,
    generate_ed25519_keypair,
)

pub_live = generate_ed25519_keypair()
pub_revoked = generate_ed25519_keypair()
pub_attacker = generate_ed25519_keypair()

notary_a = generate_ed25519_keypair()
notary_b = generate_ed25519_keypair()
notary_same_asn = generate_ed25519_keypair()
notary_same_org = generate_ed25519_keypair()
notary_debug = generate_ed25519_keypair()
witness_cosig = generate_ed25519_keypair()

ckpt = create_signed_c2sp_checkpoint(
    origin="n170.verify/test/v3",
    size=42,
    root_hash_hex=hashlib.sha256(b"ckpt").hexdigest(),
    publisher_kid="pub-live",
    publisher_private_key_hex=pub_live.private_key_hex,
    witness_signers=[("w1", witness_cosig.private_key_hex, witness_cosig.public_key_hex, "2026-04-01T12:00:00Z")],
)

registry = PublisherKeyRegistryDocument(
    updated_at_utc="2026-04-01T12:00:00Z",
    keys=[
        PublisherKeyRecord(
            publisher_kid="pub-live",
            public_key_hex=pub_live.public_key_hex,
            status="active",
            not_before_utc="2026-01-01T00:00:00Z",
            issuer_org="N170",
        ),
        PublisherKeyRecord(
            publisher_kid="pub-revoked",
            public_key_hex=pub_revoked.public_key_hex,
            status="revoked",
            not_before_utc="2025-01-01T00:00:00Z",
            revoked_after_utc="2025-06-01T00:00:00Z",
            issuer_org="N170",
        ),
    ],
    notaries=[
        NotaryNodeInfo(
            notary_id="notary-a",
            operator_org="Org Alpha",
            asn="AS24940",
            public_key_hex=notary_a.public_key_hex,
        ),
        NotaryNodeInfo(
            notary_id="notary-b",
            operator_org="Org Beta",
            asn="AS13030",
            public_key_hex=notary_b.public_key_hex,
        ),
        NotaryNodeInfo(
            notary_id="notary-same-asn",
            operator_org="Org Gamma",
            asn="AS24940",
            public_key_hex=notary_same_asn.public_key_hex,
        ),
        NotaryNodeInfo(
            notary_id="notary-same-org",
            operator_org="Org Alpha",
            asn="AS55001",
            public_key_hex=notary_same_org.public_key_hex,
        ),
        NotaryNodeInfo(
            notary_id="notary-debug",
            operator_org="Org Delta",
            asn="AS60009",
            public_key_hex=notary_debug.public_key_hex,
            is_debug_build=True,
        ),
    ],
    checkpoint=ckpt,
)

base_payloads = {
    "core_metrics": {"twr_decimal": 0.185, "observation_count": 45},
    "indexed_curve": {"base_index": 100.0, "points": [{"timestamp_utc": "2026-01-01T00:00:00Z", "index_value": 100.0, "drawdown_pct": 0.0}]},
    "reconciliation": {"status": "reconciled_within_tolerance"},
    "coaching_and_context": {"odean_pgr_plr_spread": -0.05},
    "capital_bracket": {"capital_bracket": "over_1m"},
    "benchmark_alpha": {"benchmark_symbol": "SPY", "alpha_decimal": 0.09},
    "delayed_closed_trades": {"embargo_days": 7, "trades": []},
}

body_sha = hashlib.sha256(b"statement-bytes-v3").hexdigest()
acct_tag = hashlib.sha256(b"blinded-acct-v3").hexdigest()

def make_att(kp, nid, target="/v2/accounts/[REDACTED]/positions?token=[REDACTED]", commit=TranscriptCommitmentKind.WHOLE_BODY_SHA256):
    return create_signed_witness_attestation(
        notary_private_key_hex=kp.private_key_hex,
        notary_id=nid,
        server_sni="api.alpaca.markets",
        sanitized_request_target=target,
        redacted_headers=["APCA-API-KEY-ID: [REDACTED]"],
        commitment_kind=commit,
        response_body_sha256=body_sha,
        session_timestamp_utc="2026-03-31T23:59:50Z",
    )

def pack_case(name, bundle, reg=registry, chain_hist=None, log_leaves=None, now_utc=None):
    py_res = verify_proof_bundle(
        bundle,
        registry_doc=reg,
        chain_history=chain_hist,
        continuity_log_leaves=log_leaves,
        now_utc=now_utc,
    )
    return {
        "name": name,
        "bundle": bundle.to_dict(),
        "registry": reg.to_dict() if reg is not None else None,
        "chain_history": [b.to_dict() for b in (chain_hist or [])],
        "continuity_log_leaves": [l.to_dict() for l in log_leaves] if log_leaves is not None else None,
        "now_utc": now_utc,
        "python_result": py_res.to_dict(),
    }

cases = []

# 1. Honest k>=2 disjoint notaries
b_honest = create_signed_proof_bundle(
    proof_id="case-honest-k2",
    issued_at_utc="2026-04-01T00:10:00Z",
    publisher_kid="pub-live",
    publisher_private_key_hex=pub_live.private_key_hex,
    broker_id="alpaca",
    blinded_account_tag=acct_tag,
    account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
    environment_tier=EnvironmentTier.LIVE_PRODUCTION,
    claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
    source_body_sha256=body_sha,
    period_start_utc="2026-03-01T00:00:00Z",
    period_end_utc="2026-03-31T23:59:59Z",
    base_currency="USD",
    leaf_payloads=base_payloads,
    witness_attestations=[make_att(notary_a, "notary-a"), make_att(notary_b, "notary-b")],
)
cases.append(pack_case("honest_k2_disjoint_notaries", b_honest))

# 2. Single notary claiming independently_witnessed_tls -> downgraded to operator_retrieved
b_single = create_signed_proof_bundle(
    proof_id="case-single-notary",
    issued_at_utc="2026-04-01T00:10:00Z",
    publisher_kid="pub-live",
    publisher_private_key_hex=pub_live.private_key_hex,
    broker_id="alpaca",
    blinded_account_tag=acct_tag,
    account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
    environment_tier=EnvironmentTier.LIVE_PRODUCTION,
    claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
    source_body_sha256=body_sha,
    period_start_utc="2026-03-01T00:00:00Z",
    period_end_utc="2026-03-31T23:59:59Z",
    base_currency="USD",
    leaf_payloads=base_payloads,
    witness_attestations=[make_att(notary_a, "notary-a")],
)
cases.append(pack_case("single_notary_downgrade", b_single))

# 3. Colocated same-ASN 2-notary bundle -> downgraded to operator_retrieved
b_same_asn = create_signed_proof_bundle(
    proof_id="case-same-asn",
    issued_at_utc="2026-04-01T00:10:00Z",
    publisher_kid="pub-live",
    publisher_private_key_hex=pub_live.private_key_hex,
    broker_id="alpaca",
    blinded_account_tag=acct_tag,
    account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
    environment_tier=EnvironmentTier.LIVE_PRODUCTION,
    claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
    source_body_sha256=body_sha,
    period_start_utc="2026-03-01T00:00:00Z",
    period_end_utc="2026-03-31T23:59:59Z",
    base_currency="USD",
    leaf_payloads=base_payloads,
    witness_attestations=[make_att(notary_a, "notary-a"), make_att(notary_same_asn, "notary-same-asn")],
)
cases.append(pack_case("colocated_same_asn_2_notary_downgrade", b_same_asn))

# 4. Same-org + debug notary -> downgraded to operator_retrieved
b_same_org_debug = create_signed_proof_bundle(
    proof_id="case-same-org-debug",
    issued_at_utc="2026-04-01T00:10:00Z",
    publisher_kid="pub-live",
    publisher_private_key_hex=pub_live.private_key_hex,
    broker_id="alpaca",
    blinded_account_tag=acct_tag,
    account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
    environment_tier=EnvironmentTier.LIVE_PRODUCTION,
    claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
    source_body_sha256=body_sha,
    period_start_utc="2026-03-01T00:00:00Z",
    period_end_utc="2026-03-31T23:59:59Z",
    base_currency="USD",
    leaf_payloads=base_payloads,
    witness_attestations=[
        make_att(notary_a, "notary-a"),
        make_att(notary_same_org, "notary-same-org"),
        make_att(notary_debug, "notary-debug"),
    ],
)
cases.append(pack_case("same_org_and_debug_notary_downgrade", b_same_org_debug))

# 5. Self-signed attacker key claiming official kid -> unrecognized_self_hosted_signer + self_reported
b_attacker = create_signed_proof_bundle(
    proof_id="case-attacker-key",
    issued_at_utc="2026-04-01T00:10:00Z",
    publisher_kid="pub-live",
    publisher_private_key_hex=pub_attacker.private_key_hex,
    broker_id="alpaca",
    blinded_account_tag=acct_tag,
    account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
    environment_tier=EnvironmentTier.LIVE_PRODUCTION,
    claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
    source_body_sha256=body_sha,
    period_start_utc="2026-03-01T00:00:00Z",
    period_end_utc="2026-03-31T23:59:59Z",
    base_currency="USD",
    leaf_payloads=base_payloads,
    witness_attestations=[make_att(notary_a, "notary-a"), make_att(notary_b, "notary-b")],
)
cases.append(pack_case("self_signed_attacker_key", b_attacker))

# 6. Revoked key bundle -> revoked_key + invalid
b_revoked = create_signed_proof_bundle(
    proof_id="case-revoked-key",
    issued_at_utc="2026-04-01T00:10:00Z",
    publisher_kid="pub-revoked",
    publisher_private_key_hex=pub_revoked.private_key_hex,
    broker_id="alpaca",
    blinded_account_tag=acct_tag,
    account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
    environment_tier=EnvironmentTier.LIVE_PRODUCTION,
    claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
    source_body_sha256=body_sha,
    period_start_utc="2026-03-01T00:00:00Z",
    period_end_utc="2026-03-31T23:59:59Z",
    base_currency="USD",
    leaf_payloads=base_payloads,
    witness_attestations=[make_att(notary_a, "notary-a"), make_att(notary_b, "notary-b")],
)
cases.append(pack_case("revoked_publisher_key", b_revoked))

# 7. Selectively redacted CapitalBracket & DelayedClosedTrades
b_redacted = b_honest.redact_leaves(["capital_bracket", "delayed_closed_trades"])
cases.append(pack_case("selectively_redacted_capital_bracket", b_redacted))

# 8. Transcript safety violation (leaked query token & variable-span commitment)
b_leaky = create_signed_proof_bundle(
    proof_id="case-leaky-transcript",
    issued_at_utc="2026-04-01T00:10:00Z",
    publisher_kid="pub-live",
    publisher_private_key_hex=pub_live.private_key_hex,
    broker_id="alpaca",
    blinded_account_tag=acct_tag,
    account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
    environment_tier=EnvironmentTier.LIVE_PRODUCTION,
    claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
    source_body_sha256=body_sha,
    period_start_utc="2026-03-01T00:00:00Z",
    period_end_utc="2026-03-31T23:59:59Z",
    base_currency="USD",
    leaf_payloads=base_payloads,
    witness_attestations=[
        make_att(
            notary_a,
            "notary-a",
            target="/v2/accounts/U998877/positions?token=raw_secret_leak",
            commit=TranscriptCommitmentKind.UNPADDED_VARIABLE_SPAN_REJECTED,
        ),
        make_att(notary_b, "notary-b"),
    ],
)
cases.append(pack_case("transcript_leak_and_variable_span_rejected", b_leaky))

# 9. Broken prospective chain: prev_proof_hash mismatch & mutated cadence
cadence_ok = ChainCadencePolicy(expected_interval_seconds=31 * 86400, grace_window_seconds=86400)
cadence_bad = ChainCadencePolicy(expected_interval_seconds=60 * 86400, grace_window_seconds=86400)

chain_g = create_signed_proof_bundle(
    proof_id="chain-g0",
    issued_at_utc="2026-02-01T01:00:00Z",
    publisher_kid="pub-live",
    publisher_private_key_hex=pub_live.private_key_hex,
    broker_id="alpaca",
    blinded_account_tag=acct_tag,
    account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
    environment_tier=EnvironmentTier.LIVE_PRODUCTION,
    claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
    source_body_sha256=body_sha,
    period_start_utc="2026-01-01T00:00:00Z",
    period_end_utc="2026-01-31T23:59:59Z",
    base_currency="USD",
    leaf_payloads=base_payloads,
    witness_attestations=[make_att(notary_a, "notary-a"), make_att(notary_b, "notary-b")],
    prospective_chain_link=ProspectiveChainLink(
        chain_id="chain-1",
        sequence_number=0,
        prev_proof_hash=None,
        blinded_account_tag=acct_tag,
        enrolled_at_utc="2026-01-01T02:00:00Z",
        period_start_utc="2026-01-01T00:00:00Z",
        period_end_utc="2026-01-31T23:59:59Z",
        issued_at_utc="2026-02-01T01:00:00Z",
        cadence_policy=cadence_ok,
        beginning_index_value=100.0,
        ending_index_value=110.0,
        period_twr_decimal=0.10,
    ),
)

chain_bad_1 = create_signed_proof_bundle(
    proof_id="chain-bad-1",
    issued_at_utc="2026-03-01T01:00:00Z",
    publisher_kid="pub-live",
    publisher_private_key_hex=pub_live.private_key_hex,
    broker_id="alpaca",
    blinded_account_tag=acct_tag,
    account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
    environment_tier=EnvironmentTier.LIVE_PRODUCTION,
    claimed_origin_assurance=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
    source_body_sha256=body_sha,
    period_start_utc="2026-01-31T23:59:59Z",
    period_end_utc="2026-02-28T23:59:59Z",
    base_currency="USD",
    leaf_payloads=base_payloads,
    witness_attestations=[make_att(notary_a, "notary-a"), make_att(notary_b, "notary-b")],
    prospective_chain_link=ProspectiveChainLink(
        chain_id="chain-1",
        sequence_number=1,
        prev_proof_hash="ff" * 32,
        blinded_account_tag=acct_tag,
        enrolled_at_utc="2026-01-01T02:00:00Z",
        period_start_utc="2026-01-31T23:59:59Z",
        period_end_utc="2026-02-28T23:59:59Z",
        issued_at_utc="2026-03-01T01:00:00Z",
        cadence_policy=cadence_bad,
        beginning_index_value=115.0,
        ending_index_value=126.5,
        period_twr_decimal=0.10,
    ),
)
cases.append(pack_case("broken_chain_prev_hash_and_cadence_mutation", chain_bad_1, chain_hist=[chain_g]))

# 10. Broken prospective chain: omitted newer transparency log sequence (truncated tail)
trunc_leaves = [
    ContinuityLogLeaf(
        log_index=0,
        chain_id="chain-1",
        blinded_account_tag=acct_tag,
        sequence_number=0,
        proof_hash=chain_g.proof_hash(),
        logged_at_utc="2026-02-01T01:01:00Z",
    ),
    ContinuityLogLeaf(
        log_index=1,
        chain_id="chain-1",
        blinded_account_tag=acct_tag,
        sequence_number=1,
        proof_hash=hashlib.sha256(b"seq-1-omitted-drawdown-month").hexdigest(),
        logged_at_utc="2026-03-01T01:01:00Z",
    ),
]
cases.append(pack_case("broken_chain_truncated_tail_in_tlog", chain_g, log_leaves=trunc_leaves))

# 11. Enrolled account presenting unenrolled snapshot -> continuity_broken
cases.append(pack_case("enrolled_account_presenting_unenrolled_snapshot", b_honest, log_leaves=trunc_leaves))

print(json.dumps(cases))
`);

  assert.equal(cases.length, 11);

  for (const tc of cases) {
    const tsRes = await verifyProofBundle(tc.bundle, {
      registryDoc: tc.registry,
      chainHistory: tc.chain_history,
      continuityLogLeaves: tc.continuity_log_leaves,
      nowUtc: tc.now_utc,
    });

    assert.equal(
      tsRes.valid,
      tc.python_result.valid,
      `[${tc.name}] valid mismatch: TS=${tsRes.valid} vs PY=${tc.python_result.valid} (TS errors=${JSON.stringify(tsRes.errors)})`,
    );
    assert.equal(tsRes.proof_hash, tc.python_result.proof_hash, `[${tc.name}] proof_hash`);
    assert.equal(
      tsRes.signature_valid,
      tc.python_result.signature_valid,
      `[${tc.name}] signature_valid`,
    );
    assert.equal(
      tsRes.merkle_valid,
      tc.python_result.merkle_valid,
      `[${tc.name}] merkle_valid`,
    );
    assert.equal(
      tsRes.transcript_safety_ok,
      tc.python_result.transcript_safety_ok,
      `[${tc.name}] transcript_safety_ok`,
    );
    assert.equal(
      tsRes.signer_trust_status,
      tc.python_result.signer_trust_status,
      `[${tc.name}] signer_trust_status`,
    );
    assert.equal(
      tsRes.effective_origin_assurance,
      tc.python_result.effective_origin_assurance,
      `[${tc.name}] effective_origin_assurance`,
    );
    assert.equal(
      tsRes.effective_chain_continuity_mode,
      tc.python_result.effective_chain_continuity_mode,
      `[${tc.name}] effective_chain_continuity_mode`,
    );
    assert.deepEqual(
      tsRes.disclosed_leaf_names,
      tc.python_result.disclosed_leaf_names,
      `[${tc.name}] disclosed_leaf_names`,
    );
    assert.deepEqual(
      tsRes.undisclosed_leaf_names,
      tc.python_result.undisclosed_leaf_names,
      `[${tc.name}] undisclosed_leaf_names`,
    );
    assert.equal(
      tsRes.witness_quorum.disjoint_quorum_size,
      tc.python_result.witness_quorum.disjoint_quorum_size,
      `[${tc.name}] disjoint_quorum_size`,
    );
    assert.equal(
      tsRes.witness_quorum.valid_witness_count,
      tc.python_result.witness_quorum.valid_witness_count,
      `[${tc.name}] valid_witness_count`,
    );
    assert.equal(
      tsRes.witness_quorum.distinct_org_count,
      tc.python_result.witness_quorum.distinct_org_count,
      `[${tc.name}] distinct_org_count`,
    );
    assert.equal(
      tsRes.witness_quorum.distinct_asn_count,
      tc.python_result.witness_quorum.distinct_asn_count,
      `[${tc.name}] distinct_asn_count`,
    );
  }
});

test("Tampering with Ed25519 signature, Merkle payload, or schema_version fails closed in WebCrypto", async () => {
  const badSig: VerifyProofBundle = {
    ...BUNDLE_INSTITUTIONAL_FUND,
    signature_hex: "00".repeat(64),
  };
  const rSig = await verifyProofBundle(badSig, {
    registryDoc: DEMO_REGISTRY_DOCUMENT,
  });
  assert.equal(rSig.valid, false);
  assert.equal(rSig.signature_valid, false);

  const tamperedLeafBundle: VerifyProofBundle = {
    ...BUNDLE_INSTITUTIONAL_FUND,
    disclosed_leaves: BUNDLE_INSTITUTIONAL_FUND.disclosed_leaves.map((leaf) =>
      leaf.leaf_name === "core_metrics"
        ? { ...leaf, payload: { ...(leaf.payload as Record<string, unknown>), twr_decimal: 9.99 } }
        : leaf,
    ),
  };
  const rMerkle = await verifyProofBundle(tamperedLeafBundle, {
    registryDoc: DEMO_REGISTRY_DOCUMENT,
  });
  assert.equal(rMerkle.valid, false);
  assert.equal(rMerkle.merkle_valid, false);
  // Header signature still holds over merkle_root, proving leaf commitment catches payload tampering!
  assert.equal(rMerkle.signature_valid, true);

  const badSchema: VerifyProofBundle = {
    ...BUNDLE_INSTITUTIONAL_FUND,
    schema_version: "n170-verify-v1-legacy",
  };
  assert.notEqual(badSchema.schema_version, VERIFY_SCHEMA_VERSION);
  const rSchema = await verifyProofBundle(badSchema, {
    registryDoc: DEMO_REGISTRY_DOCUMENT,
  });
  assert.equal(rSchema.valid, false);
});

test("Well-known registry JSON and typed leaf extractors uphold privacy, PSR gate, and coaching contracts", () => {
  const wellKnownPath = fileURLToPath(
    new URL("../public/.well-known/n170-verify-keys.json", import.meta.url),
  );
  const diskRegistry = JSON.parse(
    readFileSync(wellKnownPath, "utf-8"),
  ) as PublisherKeyRegistryDocument;
  assert.deepEqual(diskRegistry, DEMO_REGISTRY_DOCUMENT);

  for (const profile of SHOWCASE_PROFILES) {
    const leaves = extractTypedLeaves(profile.bundle);
    assert.ok(leaves.coreMetrics, `${profile.proofId} must disclose core_metrics`);
    assert.ok(leaves.indexedCurve.length >= 2, `${profile.proofId} must disclose indexed_curve`);
    // Strictly rebased to 100.0 — zero raw dollar NAV curve!
    assert.equal(leaves.indexedCurve[0]!.index_value, 100.0);
    assert.ok(leaves.reconciliation, `${profile.proofId} must disclose reconciliation`);
    assert.ok(leaves.coaching, `${profile.proofId} must disclose coaching_and_context`);
    assert.equal(leaves.coaching.behaviour.atr_normalized, true);
  }

  // Discrepancy X-Ray enforces T=22 < 30 PSR gate
  const xrayLeaves = extractTypedLeaves(BUNDLE_DISCREPANCY_XRAY);
  assert.equal(xrayLeaves.coreMetrics?.observation_count, 22);
  assert.equal(xrayLeaves.coreMetrics?.psr_sample_eligible, false);
  assert.equal(xrayLeaves.coreMetrics?.probabilistic_sharpe_ratio, null);
  assert.equal(xrayLeaves.coreMetrics?.psr_glm_unsmoothed, null);

  // Coaching studio selectively redacts capital_bracket and delayed_closed_trades
  const coachLeaves = extractTypedLeaves(BUNDLE_COACHING_STUDIO);
  assert.equal(coachLeaves.capitalBracket, null);
  assert.equal(coachLeaves.delayedClosedTrades, null);
  assert.ok((coachLeaves.coaching?.behaviour.odean_pgr_plr_spread ?? 0) > 0.2);
});

test("Web apiClient merges live API C2SP registry and verifies real VerifyApiApplication bundles", async () => {
  const apiPythonDir = fileURLToPath(new URL("../../api", import.meta.url));
  const stdout = execFileSync(
    "python3",
    [
      "-B",
      "-c",
      `
import json
from app.main import VerifyApiApplication, VerifyApiTestClient

xml_text = '''<?xml version="1.0" encoding="UTF-8"?>
<FlexQueryResponse queryName="Synthetic Sample" type="AF">
  <FlexStatements count="1">
    <FlexStatement accountId="REDACT-ME" fromDate="20240102" toDate="20240105" period="Last4Days" baseCurrency="USD">
      <EquitySummaryByReportDateInBase>
        <EquitySummaryByReportDateInBase reportDate="20240102" total="100000.00" />
        <EquitySummaryByReportDateInBase reportDate="20240103" total="102000.00" />
        <EquitySummaryByReportDateInBase reportDate="20240104" total="99040.00" />
        <EquitySummaryByReportDateInBase reportDate="20240105" total="98049.60" />
      </EquitySummaryByReportDateInBase>
      <CashTransactions>
        <CashTransaction accountId="REDACT-ME" reportDate="20240103" currency="USD" amount="1000.00" type="Deposits/Withdrawals" description="Deposit" transactionID="SECRET-1" />
        <CashTransaction accountId="REDACT-ME" reportDate="20240104" currency="USD" amount="-5000.00" type="Deposits/Withdrawals" description="Withdrawal" transactionID="SECRET-2" />
        <CashTransaction accountId="REDACT-ME" reportDate="20240105" currency="USD" amount="25.00" type="Dividends" description="Ordinary dividend" transactionID="SECRET-3" />
      </CashTransactions>
      <Trades>
        <Trade accountId="REDACT-ME" tradeID="SECRET-TRADE-1" tradeDate="20240103" currency="USD" assetCategory="STK" symbol="PRIVATE" buySell="BUY" quantity="10" tradePrice="100" proceeds="-1000" ibCommission="-1" fifoPnlRealized="0" />
        <Trade accountId="REDACT-ME" tradeID="SECRET-TRADE-2" tradeDate="20240105" currency="USD" assetCategory="STK" symbol="PRIVATE" buySell="SELL" quantity="-10" tradePrice="104" proceeds="1040" ibCommission="-1" fifoPnlRealized="38" />
      </Trades>
    </FlexStatement>
  </FlexStatements>
</FlexQueryResponse>'''
app = VerifyApiApplication()
client = VerifyApiTestClient(app)
verify_resp = client.post("/api/v1/verify", json={
    "broker_id": "ibkr_flex_offline",
    "raw_statement": xml_text,
    "publish_proof": True,
    "opt_in_leaderboard": True,
}).json()
pid = verify_resp["proof_bundle"]["proof_id"]
reg_resp = client.get("/.well-known/n170-verify-keys.json").json()
proof_resp = client.get(f"/api/v1/proofs/{pid}").json()
lb_resp = client.get("/api/v1/leaderboard?min_capital_bracket=under_1k").json()
app.close()
print(json.dumps({
    "verify": verify_resp,
    "registry": reg_resp,
    "proof": proof_resp,
    "leaderboard": lb_resp,
}))
`,
    ],
    {
      env: {
        ...process.env,
        PYTHONDONTWRITEBYTECODE: "1",
        PYTHONPATH: `${CORE_PYTHON_DIR}:${apiPythonDir}`,
      },
      encoding: "utf-8",
      maxBuffer: 16 * 1024 * 1024,
    },
  );
  const live = JSON.parse(stdout) as {
    verify: Record<string, unknown>;
    registry: PublisherKeyRegistryDocument;
    proof: Record<string, unknown>;
    leaderboard: Record<string, unknown>;
  };

  const prevEnv = process.env.NEXT_PUBLIC_N170_VERIFY_API_URL;
  process.env.NEXT_PUBLIC_N170_VERIFY_API_URL = "http://127.0.0.1:8080/";
  try {
    const mockFetch: typeof fetch = async (input) => {
      const url = String(input);
      if (url.endsWith("/.well-known/n170-verify-keys.json")) {
        return new Response(JSON.stringify(live.registry), { status: 200 });
      }
      if (url.endsWith("/api/v1/verify")) {
        return new Response(JSON.stringify(live.verify), { status: 200 });
      }
      if (url.includes("/api/v1/leaderboard")) {
        return new Response(JSON.stringify(live.leaderboard), { status: 200 });
      }
      if (url.includes("/api/v1/proofs/")) {
        return new Response(JSON.stringify(live.proof), { status: 200 });
      }
      return new Response("{}", { status: 404 });
    };

    const { registryDoc, liveConnected } = await fetchActiveRegistryDocument(mockFetch);
    assert.equal(liveConnected, true);

    const submitted = await submitOneShotVerification(
      { broker_id: "ibkr_flex_offline", raw_statement: "<xml/>" },
      mockFetch,
    );
    const liveCheck = await verifyProofBundle(submitted.proof_bundle, {
      registryDoc,
    });
    assert.equal(liveCheck.valid, true);
    assert.equal(liveCheck.signer_trust_status, SignerTrustStatus.OFFICIAL_N170_HOSTED);
    assert.equal(liveCheck.checkpoint_verified, true);
    assert.equal(liveCheck.effective_origin_assurance, OriginAssurance.SELF_REPORTED);

    // Merged registry still verifies built-in showcase bundles too!
    const demoCheck = await verifyProofBundle(BUNDLE_INSTITUTIONAL_FUND, {
      registryDoc,
      chainHistory: [BUNDLE_INSTITUTIONAL_SEQ0, BUNDLE_INSTITUTIONAL_SEQ1],
      continuityLogLeaves: DEMO_CONTINUITY_LOG_LEAVES,
    });
    assert.equal(demoCheck.valid, true);
    assert.equal(demoCheck.signer_trust_status, SignerTrustStatus.OFFICIAL_N170_HOSTED);

    const lbProfiles = await fetchLeaderboardProfilesFromApi("under_1k", mockFetch);
    assert.ok(lbProfiles && lbProfiles.length === 1);
    assert.equal(lbProfiles[0]!.proofId, submitted.proof_bundle.proof_id);
    assert.equal(
      getBadgeSvgUrl(submitted.proof_bundle.proof_id),
      `http://127.0.0.1:8080/api/v1/badges/${encodeURIComponent(submitted.proof_bundle.proof_id)}.svg`,
    );
  } finally {
    if (prevEnv === undefined) {
      delete process.env.NEXT_PUBLIC_N170_VERIFY_API_URL;
    } else {
      process.env.NEXT_PUBLIC_N170_VERIFY_API_URL = prevEnv;
    }
  }
});

