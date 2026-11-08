"""End-to-end institutional LP & red-team audit scenarios 9–16 for N170 Verify v3."""

from __future__ import annotations

import ast
import dataclasses
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any, Mapping
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
for _p in (str(REPO_ROOT), str(REPO_ROOT / "core"), str(REPO_ROOT / "api")):
    if Path(_p).exists() and _p not in sys.path:
        sys.path.insert(0, _p)

from app.config import ApiConfig
from app.main import VerifyApiTestClient, create_app
from app.sync_vault import RevocationReceipt
from n170_verify.catalysts import (
    EodhdNewsEvent,
    parse_submissions_payload,
)
from n170_verify.coaching import contains_forbidden_claim
from n170_verify.connectors import (
    ALPACA_BLOCKED_MUTATING_TOOLS,
    DisallowedMcpServerError,
    HttpExchangeResponse,
    McpFirewallError,
    McpToolDisallowedError,
    REJECTED_MCP_SERVERS,
    StreamableHttpMcpFirewallClient,
    TRADING212_BLOCKED_MUTATING_TOOLS,
    TradierReadOnlyAdapter,
)
from n170_verify.contracts import (
    AccountScope,
    AssetClass,
    CanonicalPortfolioLedger,
    CapitalBracket,
    CatalystAlignmentClass,
    ChainContinuityMode,
    EnvironmentTier,
    NormalizedNavPoint,
    NormalizedTrade,
    OriginAssurance,
    PerformanceSummary,
    ProviderApprovalState,
    VerifyProofBundle,
    compute_blinded_account_tag,
    verify_proof_bundle,
)
from n170_verify.crypto import (
    ChainCadencePolicy,
    ChainInvariantViolationCode,
    NotaryNodeInfo,
    ProspectiveChainLink,
    PublisherKeyRecord,
    PublisherKeyRegistryDocument,
    TranscriptCommitmentKind,
    WitnessAttestation,
    compute_salted_leaf_hash,
    create_signed_witness_attestation,
    generate_ed25519_keypair,
)
from n170_verify.pipeline import verify_portfolio
import scripts.public_release_audit as public_release_audit


REPO_ROOT = Path(__file__).resolve().parents[1]
NODE_BIN = (
    "/opt/homebrew/bin/node"
    if Path("/opt/homebrew/bin/node").is_file()
    else (shutil.which("node") or "node")
)


def _synth_ledger(
    *,
    raw_account_id: str = "ACCT-INST-09",
    broker_id: str = "ibkr",
    account_scope: AccountScope = AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    claimed_origin: OriginAssurance = OriginAssurance.OPERATOR_RETRIEVED,
    period_start_utc: str = "2026-01-01T00:00:00Z",
    period_end_utc: str = "2026-01-31T00:00:00Z",
    nav_points: list[NormalizedNavPoint] | None = None,
    trades: list[NormalizedTrade] | None = None,
    salt_hex: str = "bb" * 32,
) -> CanonicalPortfolioLedger:
    pts = nav_points or [
        NormalizedNavPoint(timestamp_utc=period_start_utc, nav_base=250_000.0),
        NormalizedNavPoint(timestamp_utc="2026-01-15T00:00:00Z", nav_base=262_500.0),
        NormalizedNavPoint(timestamp_utc=period_end_utc, nav_base=275_000.0),
    ]
    body_sha = hashlib.sha256(f"{broker_id}:{raw_account_id}:{period_end_utc}".encode()).hexdigest()
    return CanonicalPortfolioLedger(
        blinded_account_tag=compute_blinded_account_tag(broker_id, raw_account_id, salt_hex),
        broker_id=broker_id,
        account_scope=account_scope,
        claimed_origin_assurance=claimed_origin,
        provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
        environment_tier=EnvironmentTier.LIVE_PRODUCTION,
        source_body_sha256=body_sha,
        base_currency="USD",
        period_start_utc=period_start_utc,
        period_end_utc=period_end_utc,
        nav_points=pts,
        trades=trades or [],
    )


class TestInstitutionalAndRedTeamScenarios09To16(unittest.TestCase):
    """End-to-end verification of institutional LP and red-team scenarios 9 through 16."""

    def setUp(self) -> None:
        self.pub_kp = generate_ed25519_keypair(bytes.fromhex("11" * 32))
        self.notary_1_kp = generate_ed25519_keypair(bytes.fromhex("41" * 32))
        self.notary_same_org_kp = generate_ed25519_keypair(bytes.fromhex("42" * 32))
        self.notary_same_asn_kp = generate_ed25519_keypair(bytes.fromhex("43" * 32))
        self.notary_disjoint_kp = generate_ed25519_keypair(bytes.fromhex("44" * 32))
        self.ckpt_witness_kp = generate_ed25519_keypair(bytes.fromhex("51" * 32))

        self.notaries = [
            NotaryNodeInfo(
                notary_id="notary-pse-1",
                operator_org="PSE Foundation",
                asn="AS13335",
                public_key_hex=self.notary_1_kp.public_key_hex,
            ),
            NotaryNodeInfo(
                notary_id="notary-pse-colocated-org",
                operator_org="PSE Foundation",
                asn="AS3303",
                public_key_hex=self.notary_same_org_kp.public_key_hex,
            ),
            NotaryNodeInfo(
                notary_id="notary-colocated-asn",
                operator_org="Zurich Quorum Guild",
                asn="AS13335",
                public_key_hex=self.notary_same_asn_kp.public_key_hex,
            ),
            NotaryNodeInfo(
                notary_id="notary-ch-disjoint",
                operator_org="Helvetia Witness Guild",
                asn="AS3303",
                public_key_hex=self.notary_disjoint_kp.public_key_hex,
            ),
        ]
        self.registry_doc = PublisherKeyRegistryDocument(
            updated_at_utc="2026-02-10T12:00:00Z",
            keys=[
                PublisherKeyRecord(
                    publisher_kid="n170-active-2026",
                    public_key_hex=self.pub_kp.public_key_hex,
                    status="active",
                    not_before_utc="2025-01-01T00:00:00Z",
                )
            ],
            notaries=self.notaries,
        )
        self.config = ApiConfig(
            publisher_keypair=self.pub_kp,
            publisher_kid="n170-active-2026",
            publisher_key_not_before_utc="2025-01-01T00:00:00Z",
            trusted_notaries=self.notaries,
            checkpoint_origin="verify.n170.ai/continuity-log/v3",
            checkpoint_witness_signers=[
                (
                    "witness-cosigner-1",
                    self.ckpt_witness_kp.private_key_hex,
                    self.ckpt_witness_kp.public_key_hex,
                    "2026-02-10T12:00:00Z",
                )
            ],
            hosted_multi_user_mode=True,
            db_path=":memory:",
            sync_db_path=":memory:",
            vault_master_kek_hex="aa" * 32,
            sync_backup_retention_hours=0,
            account_blinding_salt_hex="bb" * 32,
        )
        self.app = create_app(self.config, prefer_fastapi=False)
        self.client = VerifyApiTestClient(self.app)

    def tearDown(self) -> None:
        self.app.close()

    def _att(
        self,
        kp_hex: str,
        notary_id: str,
        body_sha: str,
        *,
        target: str = "/v1/portal/portfolio/accounts",
        headers: tuple[str, ...] = ("authorization", "cookie"),
        kind: TranscriptCommitmentKind = TranscriptCommitmentKind.WHOLE_BODY_SHA256,
    ) -> WitnessAttestation:
        return create_signed_witness_attestation(
            notary_private_key_hex=kp_hex,
            notary_id=notary_id,
            server_sni="api.ibkr.com",
            sanitized_request_target=target,
            redacted_headers=headers,
            commitment_kind=kind,
            response_body_sha256=body_sha,
            session_timestamp_utc="2026-02-10T11:58:00Z",
        )

    # ------------------------------------------------------------------
    # Scenario 9: Dynamic disjoint notary downgrade & side-channel block
    # ------------------------------------------------------------------
    def test_scenario_09_dynamic_disjoint_notary_downgrade_and_side_channel_block(self) -> None:
        ledger = _synth_ledger(claimed_origin=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS)
        att_1 = self._att(self.notary_1_kp.private_key_hex, "notary-pse-1", ledger.source_body_sha256)
        att_same_org = self._att(
            self.notary_same_org_kp.private_key_hex, "notary-pse-colocated-org", ledger.source_body_sha256
        )
        att_same_asn = self._att(
            self.notary_same_asn_kp.private_key_hex, "notary-colocated-asn", ledger.source_body_sha256
        )

        downgrade_cases = {
            "single_notary": [att_1],
            "same_org_two_notaries": [att_1, att_same_org],
            "same_asn_two_notaries": [att_1, att_same_asn],
        }
        bundles_json: dict[str, dict[str, Any]] = {}
        for label, atts in downgrade_cases.items():
            out = verify_portfolio(
                ledger=ledger,
                proof_id=f"prf-s09-{label}",
                issued_at_utc="2026-02-10T12:00:00Z",
                publisher_kid="n170-active-2026",
                publisher_private_key_hex=self.pub_kp.private_key_hex,
                witness_attestations=atts,
                registry_doc=self.registry_doc,
            )
            self.assertTrue(out.verification.valid, out.verification.errors)
            self.assertEqual(out.proof_bundle.claimed_origin_assurance, OriginAssurance.INDEPENDENTLY_WITNESSED_TLS)
            self.assertEqual(out.verification.effective_origin_assurance, OriginAssurance.OPERATOR_RETRIEVED)
            bundles_json[label] = out.proof_bundle.to_dict()

            post_resp = self.client.post("/api/v1/proofs", json={"proof_bundle": out.proof_bundle.to_dict()})
            self.assertEqual(post_resp.status_code, 201, post_resp.text)
            svg_resp = self.client.get(f"/api/v1/badges/{out.proof_bundle.proof_id}.svg")
            self.assertEqual(svg_resp.status_code, 200)
            svg_lower = svg_resp.text.lower()
            self.assertIn("operator", svg_lower)
            self.assertNotIn("independently witnessed", svg_lower)
            self.assertNotIn("independently_witnessed_tls", svg_lower)

        # Cross-runtime parity across Node MCP verifier and TypeScript WebCrypto verifier (when web/ is present)
        has_web = (REPO_ROOT / "web/src/lib/browserVerify.ts").is_file()
        js_driver = (
            "import fs from 'node:fs';"
            "import { verifyProofBundle as mcpVerify } from './mcp/server.js';"
            + ("import { verifyProofBundle as webVerify } from './web/src/lib/browserVerify.ts';" if has_web else "")
            + "const payload = JSON.parse(fs.readFileSync(0, 'utf8'));"
            "const out = {};"
            "for (const [k, b] of Object.entries(payload.bundles)) {"
            "  const m = await mcpVerify(b, { registryDoc: payload.reg, nowUtc: '2026-02-10T12:05:00Z' });"
            + ("  const w = await webVerify(b, { registryDoc: payload.reg, nowUtc: '2026-02-10T12:05:00Z' });" if has_web else "  const w = m;")
            + "  out[k] = { mcpValid: m.valid, mcpOrigin: m.effective_origin_assurance, webValid: w.valid, webOrigin: w.effective_origin_assurance };"
            "}"
            "process.stdout.write(JSON.stringify(out));"
        )
        proc = subprocess.run(
            [NODE_BIN, "--experimental-strip-types", "--input-type=module", "-e", js_driver],
            input=json.dumps({"bundles": bundles_json, "reg": self.registry_doc.to_dict()}).encode("utf-8"),
            cwd=str(REPO_ROOT),
            capture_output=True,
            check=True,
        )
        parity = json.loads(proc.stdout.decode("utf-8"))
        for label in downgrade_cases:
            self.assertEqual(
                parity[label],
                {
                    "mcpValid": True,
                    "mcpOrigin": OriginAssurance.OPERATOR_RETRIEVED.value,
                    "webValid": True,
                    "webOrigin": OriginAssurance.OPERATOR_RETRIEVED.value,
                },
            )

        # Transcript side-channel & leakage rejections
        unsafe_attestations = [
            self._att(
                self.notary_1_kp.private_key_hex,
                "notary-pse-1",
                ledger.source_body_sha256,
                kind=TranscriptCommitmentKind.UNPADDED_VARIABLE_SPAN_REJECTED,
            ),
            self._att(
                self.notary_1_kp.private_key_hex,
                "notary-pse-1",
                ledger.source_body_sha256,
                headers=("Authorization: Bearer leaked-secret-123",),
            ),
            self._att(
                self.notary_1_kp.private_key_hex,
                "notary-pse-1",
                ledger.source_body_sha256,
                target="/Universal/servlet/FlexStatementService.SendRequest?t=99887766&q=1",
            ),
            self._att(
                self.notary_1_kp.private_key_hex,
                "notary-pse-1",
                ledger.source_body_sha256,
                target="/v1/accounts/12345/balances",
            ),
        ]
        for idx, bad_att in enumerate(unsafe_attestations):
            bad_out = verify_portfolio(
                ledger=ledger,
                proof_id=f"prf-s09-bad-{idx}",
                issued_at_utc="2026-02-10T12:00:00Z",
                publisher_kid="n170-active-2026",
                publisher_private_key_hex=self.pub_kp.private_key_hex,
                witness_attestations=[bad_att],
                registry_doc=self.registry_doc,
            )
            self.assertFalse(bad_out.verification.transcript_safety_ok)
            self.assertFalse(bad_out.verification.valid)

    # ------------------------------------------------------------------
    # Scenario 10: Multi-account survivorship disclosure & leaderboard filter
    # ------------------------------------------------------------------
    def test_scenario_10_multi_account_survivorship_disclosure(self) -> None:
        all_four = ["6VA10001", "6VA10002", "6VA10003", "6VA10004"]

        def tradier_transport(method: str, url: str, headers: Mapping[str, str], body: bytes | None) -> HttpExchangeResponse:
            self.assertEqual(method, "GET")
            if url.endswith("/v1/user/profile"):
                payload: dict[str, Any] = {
                    "profile": {
                        "account": [{"account_number": acct, "classification": "individual"} for acct in all_four]
                    }
                }
            elif "/balances" in url:
                payload = {"balances": {"total_equity": 150_000.0, "total_cash": 50_000.0}}
            elif "/positions" in url:
                payload = {"positions": {"position": [{"symbol": "SPY", "quantity": 200, "cost_basis": 95_000.0, "market_value": 100_000.0}]}}
            else:
                payload = {"history": {"event": []}}
            return HttpExchangeResponse(200, {"Content-Type": "application/json"}, json.dumps(payload).encode("utf-8"))

        adapter = TradierReadOnlyAdapter(access_token="tradier-ro-tok-10", http_transport=tradier_transport)
        subset_ledger = adapter.fetch_canonical_ledger(
            blinding_salt_hex="bb" * 32,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            selected_account_numbers=["6VA10001"],
        )
        subset_ledger.nav_points.insert(
            0, NormalizedNavPoint(timestamp_utc="2026-01-01T00:00:00Z", nav_base=140_000.0)
        )
        self.assertEqual(subset_ledger.enumerated_subaccount_count, 4)
        self.assertEqual(subset_ledger.connected_subaccount_count, 1)
        subset_out = verify_portfolio(
            ledger=subset_ledger,
            proof_id="prf-s10-subset-1of4",
            issued_at_utc="2026-02-10T12:00:00Z",
            publisher_kid="n170-active-2026",
            publisher_private_key_hex=self.pub_kp.private_key_hex,
            registry_doc=self.registry_doc,
        )
        self.assertEqual(subset_out.proof_bundle.account_scope, AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED)

        full_ledger = adapter.fetch_canonical_ledger(
            blinding_salt_hex="bb" * 32,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            selected_account_numbers=all_four,
        )
        full_ledger.nav_points.insert(
            0, NormalizedNavPoint(timestamp_utc="2026-01-01T00:00:00Z", nav_base=560_000.0)
        )
        full_out = verify_portfolio(
            ledger=full_ledger,
            proof_id="prf-s10-full-4of4",
            issued_at_utc="2026-02-10T12:00:00Z",
            publisher_kid="n170-active-2026",
            publisher_private_key_hex=self.pub_kp.private_key_hex,
            registry_doc=self.registry_doc,
        )
        self.assertEqual(full_out.proof_bundle.account_scope, AccountScope.ALL_ENUMERATED_SUBACCOUNTS)

        for b in (subset_out.proof_bundle, full_out.proof_bundle):
            r = self.client.post("/api/v1/proofs", json={"proof_bundle": b.to_dict(), "opt_in_leaderboard": True})
            self.assertEqual(r.status_code, 201, r.text)

        lb_strict = self.client.get("/api/v1/leaderboard?account_scope=all_enumerated_subaccounts")
        self.assertEqual(lb_strict.status_code, 200, lb_strict.text)
        strict_ids = [row["proof_id"] for row in lb_strict.json()["entries"]]
        self.assertIn("prf-s10-full-4of4", strict_ids)
        self.assertNotIn("prf-s10-subset-1of4", strict_ids)

    # ------------------------------------------------------------------
    # Scenario 11: All five prospective chain invariants
    # ------------------------------------------------------------------
    def test_scenario_11_all_five_prospective_chain_invariants(self) -> None:
        cadence = ChainCadencePolicy(expected_interval_seconds=30 * 86400, grace_window_seconds=5 * 86400)
        base_ledger = _synth_ledger(raw_account_id="ACCT-CHAIN-11")
        tag = base_ledger.blinded_account_tag

        def make_chain_bundle(
            proof_id: str,
            link: ProspectiveChainLink,
            *,
            raw_acct: str = "ACCT-CHAIN-11",
        ) -> VerifyProofBundle:
            ldg = _synth_ledger(
                raw_account_id=raw_acct,
                period_start_utc=link.period_start_utc,
                period_end_utc=link.period_end_utc,
            )
            return verify_portfolio(
                ledger=ldg,
                proof_id=proof_id,
                issued_at_utc=link.issued_at_utc,
                publisher_kid="n170-active-2026",
                publisher_private_key_hex=self.pub_kp.private_key_hex,
                prospective_chain_link=link,
                registry_doc=self.registry_doc,
            ).proof_bundle

        # (a) >24h genesis enrollment -> RETROSPECTIVE_BACKFILL
        backfill_b0 = make_chain_bundle(
            "prf-s11-backfill-0",
            ProspectiveChainLink(
                chain_id="chn-s11-backfill",
                sequence_number=0,
                prev_proof_hash=None,
                blinded_account_tag=tag,
                enrolled_at_utc="2026-01-05T00:00:00Z",  # 96h after period_start_utc (> 24h)
                period_start_utc="2026-01-01T00:00:00Z",
                period_end_utc="2026-01-31T00:00:00Z",
                issued_at_utc="2026-02-01T12:00:00Z",
                cadence_policy=cadence,
                beginning_index_value=100.0,
                ending_index_value=110.0,
                period_twr_decimal=0.10,
            ),
        )
        res_backfill = verify_proof_bundle(backfill_b0, registry_doc=self.registry_doc)
        self.assertEqual(res_backfill.effective_chain_continuity_mode, ChainContinuityMode.RETROSPECTIVE_BACKFILL)
        self.assertIn(
            ChainInvariantViolationCode.GENESIS_BACKFILL_WINDOW_EXCEEDED,
            res_backfill.chain_verification.violation_codes,
        )

        # Valid prospective #0 and #1 enrolled via API
        b0 = make_chain_bundle(
            "prf-s11-0",
            ProspectiveChainLink(
                chain_id="chn-s11-live",
                sequence_number=0,
                prev_proof_hash=None,
                blinded_account_tag=tag,
                enrolled_at_utc="2026-01-01T06:00:00Z",
                period_start_utc="2026-01-01T00:00:00Z",
                period_end_utc="2026-01-31T00:00:00Z",
                issued_at_utc="2026-01-31T12:00:00Z",
                cadence_policy=cadence,
                beginning_index_value=100.0,
                ending_index_value=110.0,
                period_twr_decimal=0.10,
            ),
        )
        enroll_resp = self.client.post(
            "/api/v1/chains",
            json={"proof_bundle": b0.to_dict(), "now_utc": "2026-01-31T12:05:00Z"},
        )
        self.assertEqual(enroll_resp.status_code, 201, enroll_resp.text)

        b1 = make_chain_bundle(
            "prf-s11-1",
            ProspectiveChainLink(
                chain_id="chn-s11-live",
                sequence_number=1,
                prev_proof_hash=b0.proof_hash(),
                blinded_account_tag=tag,
                enrolled_at_utc="2026-01-01T06:00:00Z",
                period_start_utc="2026-01-31T00:00:00Z",
                period_end_utc="2026-03-02T00:00:00Z",
                issued_at_utc="2026-03-02T12:00:00Z",
                cadence_policy=cadence,
                beginning_index_value=110.0,
                ending_index_value=121.0,
                period_twr_decimal=0.10,
            ),
        )
        append_resp = self.client.post(
            "/api/v1/chains/chn-s11-live/append",
            json={"proof_bundle": b1.to_dict(), "now_utc": "2026-03-02T12:05:00Z"},
        )
        self.assertEqual(append_resp.status_code, 200, append_resp.text)

        # (b) Spliced blinded_account_tag -> ACCOUNT_CONTINUITY_VIOLATION
        other_tag = compute_blinded_account_tag("ibkr", "ACCT-SPLICED-99", "bb" * 32)
        b1_spliced = make_chain_bundle(
            "prf-s11-spliced",
            ProspectiveChainLink(
                chain_id="chn-s11-live",
                sequence_number=1,
                prev_proof_hash=b0.proof_hash(),
                blinded_account_tag=other_tag,
                enrolled_at_utc="2026-01-01T06:00:00Z",
                period_start_utc="2026-01-31T00:00:00Z",
                period_end_utc="2026-03-02T00:00:00Z",
                issued_at_utc="2026-03-02T12:00:00Z",
                cadence_policy=cadence,
                beginning_index_value=110.0,
                ending_index_value=121.0,
                period_twr_decimal=0.10,
            ),
            raw_acct="ACCT-SPLICED-99",
        )
        res_spliced = verify_proof_bundle(b1_spliced, registry_doc=self.registry_doc, chain_history=[b0, b1_spliced])
        self.assertFalse(res_spliced.valid)
        self.assertIn(
            ChainInvariantViolationCode.ACCOUNT_CONTINUITY_VIOLATION,
            res_spliced.chain_verification.violation_codes,
        )

        # (c) Skipped month & index jump -> MISSED_INTERVAL_DETECTED
        b1_skipped = make_chain_bundle(
            "prf-s11-skipped",
            ProspectiveChainLink(
                chain_id="chn-s11-live",
                sequence_number=1,
                prev_proof_hash=b0.proof_hash(),
                blinded_account_tag=tag,
                enrolled_at_utc="2026-01-01T06:00:00Z",
                period_start_utc="2026-03-05T00:00:00Z",  # skipped February!
                period_end_utc="2026-04-04T00:00:00Z",
                issued_at_utc="2026-04-04T12:00:00Z",
                cadence_policy=cadence,
                beginning_index_value=125.0,  # jumped from 110.0!
                ending_index_value=137.5,
                period_twr_decimal=0.10,
            ),
        )
        res_skipped = verify_proof_bundle(b1_skipped, registry_doc=self.registry_doc, chain_history=[b0, b1_skipped])
        self.assertFalse(res_skipped.valid)
        self.assertIn(
            ChainInvariantViolationCode.MISSED_INTERVAL_DETECTED,
            res_skipped.chain_verification.violation_codes,
        )

        # (d) Parallel #0 reset on /api/v1/chains -> HTTP 409 + truncated tail vs continuity log
        b0_reset = make_chain_bundle(
            "prf-s11-parallel-reset",
            ProspectiveChainLink(
                chain_id="chn-s11-reset-attempt",
                sequence_number=0,
                prev_proof_hash=None,
                blinded_account_tag=tag,
                enrolled_at_utc="2026-02-01T01:00:00Z",
                period_start_utc="2026-02-01T00:00:00Z",
                period_end_utc="2026-03-03T00:00:00Z",
                issued_at_utc="2026-03-03T12:00:00Z",
                cadence_policy=cadence,
                beginning_index_value=100.0,
                ending_index_value=110.0,
                period_twr_decimal=0.10,
            ),
        )
        reset_resp = self.client.post(
            "/api/v1/chains",
            json={"proof_bundle": b0_reset.to_dict(), "now_utc": "2026-03-03T12:05:00Z"},
        )
        self.assertEqual(reset_resp.status_code, 409, reset_resp.text)

        log_leaves = self.app.store.get_continuity_leaves_for_account(tag)
        self.assertEqual(len(log_leaves), 2)
        res_truncated = verify_proof_bundle(
            b0,
            registry_doc=self.registry_doc,
            chain_history=[b0],
            continuity_log_leaves=log_leaves,
            now_utc="2026-03-05T00:00:00Z",
        )
        self.assertFalse(res_truncated.valid)
        self.assertIn(
            ChainInvariantViolationCode.STALE_OR_TRUNCATED_TAIL,
            res_truncated.chain_verification.violation_codes,
        )

    # ------------------------------------------------------------------
    # Scenario 12: GLM return unsmoothing & T < 30 PSR sample gate
    # ------------------------------------------------------------------
    def test_scenario_12_glm_return_unsmoothing_and_t_lt_30_psr_gate(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        smoothed_nav = [NormalizedNavPoint(timestamp_utc=start.isoformat().replace("+00:00", "Z"), nav_base=100_000.0)]
        nav = 100_000.0
        prev_r = 0.004
        for i in range(1, 61):  # T = 60 >= 30 strongly positively autocorrelated returns -> xi_hat < 0.80
            shock = 0.003 * math.sin(i * 0.55)
            r = 0.002 + 0.65 * (prev_r - 0.002) + shock
            prev_r = r
            nav *= 1.0 + r
            ts = (start + timedelta(days=i)).isoformat().replace("+00:00", "Z")
            smoothed_nav.append(NormalizedNavPoint(timestamp_utc=ts, nav_base=nav))

        out_60 = verify_portfolio(
            ledger=_synth_ledger(
                period_start_utc=smoothed_nav[0].timestamp_utc,
                period_end_utc=smoothed_nav[-1].timestamp_utc,
                nav_points=smoothed_nav,
            ),
            publisher_kid="n170-active-2026",
            publisher_private_key_hex=self.pub_kp.private_key_hex,
            registry_doc=self.registry_doc,
        )
        perf_60 = out_60.performance
        self.assertTrue(perf_60.psr_sample_eligible)
        self.assertGreaterEqual(perf_60.observation_count, 30)
        self.assertIsNotNone(perf_60.smoothing_index_xi)
        self.assertLess(perf_60.smoothing_index_xi, 0.80)
        self.assertIsNotNone(perf_60.probabilistic_sharpe_ratio)
        self.assertIsNotNone(perf_60.psr_glm_unsmoothed)
        self.assertLess(perf_60.psr_glm_unsmoothed, perf_60.probabilistic_sharpe_ratio)

        # T = 18 < 30 observations -> psr_sample_eligible == False and PSR withheld (None)
        short_nav = smoothed_nav[:19]  # 19 NAV points -> 18 period returns
        out_18 = verify_portfolio(
            ledger=_synth_ledger(
                period_start_utc=short_nav[0].timestamp_utc,
                period_end_utc=short_nav[-1].timestamp_utc,
                nav_points=short_nav,
            ),
            publisher_kid="n170-active-2026",
            publisher_private_key_hex=self.pub_kp.private_key_hex,
            registry_doc=self.registry_doc,
        )
        perf_18 = out_18.performance
        self.assertEqual(perf_18.observation_count, 18)
        self.assertFalse(perf_18.psr_sample_eligible)
        self.assertIsNone(perf_18.probabilistic_sharpe_ratio)
        self.assertIsNone(perf_18.psr_glm_unsmoothed)

    # ------------------------------------------------------------------
    # Scenario 13: Salted Merkle brute-force resistance & 7-day trade guard
    # ------------------------------------------------------------------
    def test_scenario_13_salted_merkle_bruteforce_resistance_and_7day_trade_guard(self) -> None:
        trades = [
            # Closed 15 days before period_end (2026-01-16 vs 2026-01-31) -> >= 7 days old -> included
            NormalizedTrade(
                venue="ibkr", native_entry_id="t-old-open", symbol="AAPL", asset_class=AssetClass.EQUITY,
                side="buy", quantity=50.0, price=180.0, timestamp_utc="2026-01-10T15:00:00Z",
            ),
            NormalizedTrade(
                venue="ibkr", native_entry_id="t-old-close", symbol="AAPL", asset_class=AssetClass.EQUITY,
                side="sell", quantity=50.0, price=190.0, timestamp_utc="2026-01-16T15:00:00Z",
            ),
            # Closed 2 days before period_end (2026-01-29 vs 2026-01-31) -> < 7 days old -> stripped!
            NormalizedTrade(
                venue="ibkr", native_entry_id="t-recent-open", symbol="NVDA", asset_class=AssetClass.EQUITY,
                side="buy", quantity=20.0, price=500.0, timestamp_utc="2026-01-28T15:00:00Z",
            ),
            NormalizedTrade(
                venue="ibkr", native_entry_id="t-recent-close", symbol="NVDA", asset_class=AssetClass.EQUITY,
                side="sell", quantity=20.0, price=520.0, timestamp_utc="2026-01-29T15:00:00Z",
            ),
        ]
        out = verify_portfolio(
            ledger=_synth_ledger(trades=trades),
            issued_at_utc="2026-01-31T12:00:00Z",
            publisher_kid="n170-active-2026",
            publisher_private_key_hex=self.pub_kp.private_key_hex,
            registry_doc=self.registry_doc,
        )
        self.assertEqual(out.stripped_recent_closed_trades_count, 1)
        delayed_leaf = out.proof_bundle.get_disclosed_payload("delayed_closed_trades")
        symbols_disclosed = [t["symbol"] for t in delayed_leaf["trades"]]
        self.assertEqual(symbols_disclosed, ["AAPL"])
        self.assertNotIn("NVDA", symbols_disclosed)

        orig_bracket_leaf = next(
            lf for lf in out.proof_bundle.disclosed_leaves if lf.leaf_name == "capital_bracket"
        )
        committed_hash = compute_salted_leaf_hash(
            "capital_bracket", orig_bracket_leaf.salt_hex, orig_bracket_leaf.payload
        )
        redacted = out.proof_bundle.redact_leaves(["capital_bracket"])
        self.assertTrue(all(lf.leaf_name != "capital_bracket" for lf in redacted.disclosed_leaves))
        serialized_redacted = json.dumps(redacted.to_dict())
        self.assertNotIn(orig_bracket_leaf.salt_hex, serialized_redacted)
        self.assertNotIn(CapitalBracket.BRACKET_100K_1M.value, serialized_redacted)

        res_redacted = verify_proof_bundle(redacted, registry_doc=self.registry_doc)
        self.assertTrue(res_redacted.valid, res_redacted.errors)
        self.assertTrue(res_redacted.signature_valid)
        self.assertTrue(res_redacted.merkle_valid)
        self.assertIn("capital_bracket", res_redacted.undisclosed_leaf_names)

        # Brute-force across all 5 CapitalBracket enums with guessed/zero salts fails to match committed_hash
        for candidate in CapitalBracket:
            for guessed_salt in ("00" * 32, "ff" * 32, "aa" * 32):
                guess_hash = compute_salted_leaf_hash(
                    "capital_bracket",
                    guessed_salt,
                    {"capital_bracket": candidate.value, "valuation_currency": "USD"},
                )
                self.assertNotEqual(guess_hash, committed_hash)

    # ------------------------------------------------------------------
    # Scenario 14: SEC EDGAR bogus-"Z" ET->UTC & press wire before Form 8-K
    # ------------------------------------------------------------------
    def test_scenario_14_sec_edgar_z_strip_et_to_utc_and_press_wire_before_8k(self) -> None:
        submissions_json = {
            "cik": "320193",
            "tickers": ["AAPL"],
            "filings": {
                "recent": {
                    "accessionNumber": ["0000320193-26-000014"],
                    "filingDate": ["2026-01-15"],
                    # SEC EDGAR bogus trailing "Z" on Eastern Time 10:00:00 EST -> 15:00:00Z UTC
                    "acceptanceDateTime": ["2026-01-15T10:00:00.000Z"],
                    "form": ["8-K"],
                    "items": ["2.02"],
                    "primaryDocDescription": ["8-K EARNINGS RELEASE"],
                }
            },
        }
        filings = parse_submissions_payload(submissions_json, symbol="AAPL")
        self.assertEqual(len(filings), 1)
        self.assertEqual(filings[0].acceptance_timestamp_utc, "2026-01-15T15:00:00Z")

        # EODHD press wire at 08:20 ET (13:20 UTC); trade 20 min later at 08:40 ET (13:40 UTC) < 8-K (15:00 UTC)
        press_wire = EodhdNewsEvent(
            symbol="AAPL",
            eodhd_symbol="AAPL.US",
            published_utc="2026-01-15T13:20:00Z",
            title="Apple Reports Record Q1 Results on Business Wire",
            source_wire="Business Wire",
            is_press_wire=True,
        )
        trades = [
            NormalizedTrade(
                venue="ibkr", native_entry_id="t-14-buy", symbol="AAPL", asset_class=AssetClass.EQUITY,
                side="buy", quantity=100.0, price=185.0, timestamp_utc="2026-01-15T13:40:00Z",
            ),
            NormalizedTrade(
                venue="ibkr", native_entry_id="t-14-sell", symbol="AAPL", asset_class=AssetClass.EQUITY,
                side="sell", quantity=100.0, price=192.0, timestamp_utc="2026-01-16T16:00:00Z",
            ),
        ]
        out = verify_portfolio(
            ledger=_synth_ledger(trades=trades),
            sec_filings=filings,
            eodhd_news=[press_wire],
            issued_at_utc="2026-02-05T12:00:00Z",
            publisher_kid="n170-active-2026",
            publisher_private_key_hex=self.pub_kp.private_key_hex,
            registry_doc=self.registry_doc,
        )
        obs = out.coaching.event_observations
        self.assertGreaterEqual(len(obs), 1)
        self.assertEqual(obs[0].alignment_class, CatalystAlignmentClass.AMBIGUOUS_PUBLIC_WINDOW)
        self.assertTrue(obs[0].timestamp_uncertainty_note)
        coaching_blob = json.dumps(out.coaching.to_dict())
        self.assertFalse(contains_forbidden_claim(coaching_blob))

    # ------------------------------------------------------------------
    # Scenario 15: MCP Streamable HTTP POST allowlist firewall
    # ------------------------------------------------------------------
    def test_scenario_15_mcp_streamable_http_post_allowlist_firewall(self) -> None:
        self.assertEqual(len(ALPACA_BLOCKED_MUTATING_TOOLS), 18)
        self.assertIn("update_account_config", ALPACA_BLOCKED_MUTATING_TOOLS)
        self.assertEqual(len(TRADING212_BLOCKED_MUTATING_TOOLS), 10)
        self.assertIn("request_csv_export", TRADING212_BLOCKED_MUTATING_TOOLS)

        seen_posts: list[tuple[str, str]] = []
        secret_tok = "ALPACA-LIVE-SECRET-TOKEN-DO-NOT-LEAK-777"

        def alpaca_mcp_transport(
            method: str, url: str, body: bytes, headers: Mapping[str, str]
        ) -> tuple[int, dict[str, str], bytes]:
            seen_posts.append((method, url))
            req = json.loads(body.decode("utf-8"))
            rpc_method = req["method"]
            if rpc_method == "initialize":
                res: dict[str, Any] = {
                    "protocolVersion": "2025-11-25",
                    "serverInfo": {"name": "alpaca-mcp-server", "version": "1.0.0"},
                    "capabilities": {"tools": {}},
                }
            else:
                res = {"content": [{"type": "text", "text": '{"status":"ACTIVE","currency":"USD"}'}]}
            resp_bytes = json.dumps({"jsonrpc": "2.0", "id": req.get("id", 1), "result": res}).encode("utf-8")
            return 200, {"Content-Type": "application/json", "Mcp-Session-Id": "sess-15"}, resp_bytes

        alpaca_client = StreamableHttpMcpFirewallClient(
            server_id="alpaca",
            endpoint_url="https://mcp.alpaca.markets/mcp",
            auth_headers={"Authorization": f"Bearer {secret_tok}"},
            http_transport=alpaca_mcp_transport,
        )
        alpaca_client.initialize()
        ro_res = alpaca_client.call_tool("get_account_info", {})
        self.assertIn("ACTIVE", json.dumps(ro_res))
        self.assertTrue(all(m == "POST" for m, _ in seen_posts))

        # Block all 18 Alpaca mutating tools before hitting transport
        post_count_before = len(seen_posts)
        for bad_tool in ALPACA_BLOCKED_MUTATING_TOOLS:
            with self.assertRaises(McpToolDisallowedError):
                alpaca_client.call_tool(bad_tool, {})
        self.assertEqual(len(seen_posts), post_count_before)

        # Block all 10 Trading 212 mutating tools before hitting transport
        t212_client = StreamableHttpMcpFirewallClient(
            server_id="trading212",
            endpoint_url="https://mcp.trading212.com/mcp",
            http_transport=alpaca_mcp_transport,
        )
        for bad_tool in TRADING212_BLOCKED_MUTATING_TOOLS:
            with self.assertRaises(McpToolDisallowedError):
                t212_client.call_tool(bad_tool, {})

        # Reject community CCXT MCP servers
        for ccxt_srv in REJECTED_MCP_SERVERS:
            with self.assertRaises(DisallowedMcpServerError):
                StreamableHttpMcpFirewallClient(
                    server_id=ccxt_srv,
                    endpoint_url="https://mcp.example.com/mcp",
                    http_transport=alpaca_mcp_transport,
                )

        # Secret redaction on upstream transport failure
        def failing_transport(
            method: str, url: str, body: bytes, headers: Mapping[str, str]
        ) -> tuple[int, dict[str, str], bytes]:
            raise RuntimeError(f"Upstream proxy rejected Authorization Bearer {secret_tok}")

        err_client = StreamableHttpMcpFirewallClient(
            server_id="alpaca",
            endpoint_url="https://mcp.alpaca.markets/mcp",
            auth_headers={"Authorization": f"Bearer {secret_tok}"},
            http_transport=failing_transport,
        )
        with self.assertRaises(McpFirewallError) as ctx:
            err_client.call_tool("get_account_info", {})
        self.assertNotIn(secret_tok, str(ctx.exception))

    # ------------------------------------------------------------------
    # Scenario 16: Clean-source isolation, revocation receipt & release gate
    # ------------------------------------------------------------------
    def test_scenario_16_clean_source_subprocess_isolation_revocation_and_release_gate(self) -> None:
        # 1. Subprocess-isolated one-shot POST /api/v1/verify
        verify_resp = self.client.post(
            "/api/v1/verify",
            json={
                "broker_id": "ibkr_flex",
                "raw_account_id": "U777888999",
                "ephemeral_credentials": {"flex_token": "ephemeral-tok-16"},
                "period_start_utc": "2026-01-01T00:00:00Z",
                "period_end_utc": "2026-01-31T00:00:00Z",
                "issued_at_utc": "2026-02-10T12:00:00Z",
                "nav_points": [
                    {"timestamp_utc": "2026-01-01T00:00:00Z", "nav_base": 200_000.0},
                    {"timestamp_utc": "2026-01-31T00:00:00Z", "nav_base": 212_000.0},
                ],
                "persist_sync": False,
            },
        )
        self.assertEqual(verify_resp.status_code, 200, verify_resp.text)
        receipt_iso = verify_resp.json()["isolation_receipt"]
        self.assertEqual(receipt_iso["execution_mode"], "ephemeral_spawn_subprocess")
        self.assertNotEqual(receipt_iso["worker_pid"], os.getpid())
        self.assertEqual(receipt_iso["rlimit_core"], [0, 0])
        with self.assertRaises(ProcessLookupError):
            os.kill(int(receipt_iso["worker_pid"]), 0)
        self.assertEqual(self.app.store.total_row_counts(), {"proofs": 0, "chains": 0, "continuity_log": 0})
        self.assertEqual(self.app.sync_vault.connection_count(), 0)

        # 2. Opt-in sync enrollment + DELETE /api/v1/sync/{id} cryptographic RevocationReceipt
        sync_resp = self.client.post(
            "/api/v1/sync",
            json={
                "broker_id": "alpaca",
                "raw_account_id": "ALP-LIVE-16",
                "credentials": {"access_token": "alpaca-ro-sync-16"},
                "capabilities": ["read_account_profile", "read_balances", "fetch_positions"],
            },
        )
        self.assertEqual(sync_resp.status_code, 201, sync_resp.text)
        conn_id = sync_resp.json()["connection"]["connection_id"]
        del_resp = self.client.delete(f"/api/v1/sync/{conn_id}")
        self.assertEqual(del_resp.status_code, 200, del_resp.text)
        rev_receipt = RevocationReceipt.from_dict(del_resp.json()["revocation_receipt"])
        self.assertTrue(rev_receipt.verify_signature())
        self.assertTrue(rev_receipt.primary_ciphertext_overwritten_and_deleted)
        self.assertEqual(self.app.sync_vault.connection_count(), 0)

        # 3. Clean-source AST scan: zero legacy runtime imports; zero single-account deflated ratio
        forbidden_roots = {"n170"}
        for pkg_dir in (
            REPO_ROOT / "core" / "n170_verify",
            REPO_ROOT / "api" / "app",
        ):
            for py_file in pkg_dir.rglob("*.py"):
                tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            self.assertNotIn(alias.name.split(".")[0], forbidden_roots, str(py_file))
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        self.assertNotIn(node.module.split(".")[0], forbidden_roots, str(py_file))

        perf_fields = {f.name.lower() for f in dataclasses.fields(PerformanceSummary)}
        forbidden_sr_tok = "d" + "sr"
        self.assertTrue(all(forbidden_sr_tok not in name and "deflated" not in name for name in perf_fields))

        # 4. Repository-wide public release gate returns [] with require_license=True
        if (REPO_ROOT / ".git").exists() or os.environ.get("GITHUB_ACTIONS") == "true":
            entries = public_release_audit._tracked_entries(REPO_ROOT)
            initial = []
        else:
            entries, initial = public_release_audit._tree_entries(REPO_ROOT)
        findings = public_release_audit.audit_release(
            REPO_ROOT,
            entries,
            initial_findings=initial,
            require_license=True,
        )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
