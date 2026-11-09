"""Comprehensive security, bounds, XSS/CSP, dynamic C2SP verification, and isolated worker tests for viral routes."""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import quote
import xml.etree.ElementTree as ET

from app.config import ApiConfig
from app.main import VerifyApiTestClient, create_app
from app.routes_viral import (
    MAX_PLAUSIBILITY_BODY_BYTES,
    MAX_STATEMENT_UPLOAD_BYTES,
    handle_get_ibkr_flex_guide,
    handle_post_plausibility,
)
from n170_verify.connectors import detect_and_parse_statement
from n170_verify.contracts import (
    AccountScope,
    CapitalBracket,
    EnvironmentTier,
    IndexedCurvePoint,
    OriginAssurance,
    PerformanceSummary,
    ProviderApprovalState,
    ReconciliationReport,
    ReconciliationStatus,
    compute_blinded_account_tag,
    create_signed_proof_bundle,
)
from n170_verify.crypto import (
    CANONICAL_LEAF_NAMES,
    NotaryNodeInfo,
    PublisherKeyRecord,
    build_salted_merkle_tree,
    create_signed_witness_attestation,
    generate_ed25519_keypair,
)


SYNTHETIC_LIVE_IBKR_FLEX_XML = """<?xml version="1.0" encoding="UTF-8"?>
<FlexQueryResponse queryName="N170VerifyLive" type="AF">
  <FlexStatements count="1">
    <FlexStatement accountId="U7654321" fromDate="20260102" toDate="20260130" period="Last30CalendarDays">
      <AccountInformation accountId="U7654321" currency="USD" accountType="INDIVIDUAL" />
      <EquitySummaryInBase>
        <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="20260102" cash="987654.32" stock="0.00" total="987654.32" />
        <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="20260115" cash="995120.10" stock="0.00" total="995120.10" />
        <EquitySummaryByReportDateInBase accountId="U7654321" reportDate="20260130" cash="1029410.88" stock="0.00" total="1029410.88" />
      </EquitySummaryInBase>
      <PriorPeriodPositions />
      <OpenPositions />
      <Trades>
        <Trade accountId="U7654321" assetCategory="STK" symbol="AAPL" currency="USD" tradeDate="20260105" dateTime="20260105;101500" buySell="BUY" quantity="100" tradePrice="180.00" ibCommission="-1.00" transactionID="TX-OPEN-1" />
        <Trade accountId="U7654321" assetCategory="STK" symbol="AAPL" currency="USD" tradeDate="20260112" dateTime="20260112;151000" buySell="SELL" quantity="-100" tradePrice="192.50" ibCommission="-1.00" transactionID="TX-CLOSE-1" />
        <Trade accountId="U7654321" assetCategory="STK" symbol="MSFT" currency="USD" tradeDate="20260128" dateTime="20260128;100000" buySell="BUY" quantity="50" tradePrice="410.00" ibCommission="-1.00" transactionID="TX-OPEN-2" />
        <Trade accountId="U7654321" assetCategory="STK" symbol="MSFT" currency="USD" tradeDate="20260129" dateTime="20260129;153000" buySell="SELL" quantity="-50" tradePrice="418.00" ibCommission="-1.00" transactionID="TX-CLOSE-2" />
      </Trades>
      <CashTransactions />
      <Transfers />
      <CorporateActions />
      <OptionEAE />
      <ConversionRates />
    </FlexStatement>
  </FlexStatements>
</FlexQueryResponse>
"""

SYNTHETIC_PAPER_IBKR_FLEX_XML = """<?xml version="1.0" encoding="UTF-8"?>
<FlexQueryResponse queryName="PaperDemo" type="AF">
  <FlexStatements count="1">
    <FlexStatement accountId="DU1234567" fromDate="20260102" toDate="20260110">
      <EquitySummaryInBase>
        <EquitySummaryByReportDateInBase accountId="DU1234567" reportDate="20260102" total="100000.00" />
        <EquitySummaryByReportDateInBase accountId="DU1234567" reportDate="20260110" total="105000.00" />
      </EquitySummaryInBase>
    </FlexStatement>
  </FlexStatements>
</FlexQueryResponse>
"""

SYNTHETIC_XXE_IBKR_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE FlexQueryResponse [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<FlexQueryResponse>&xxe;</FlexQueryResponse>
"""

SYNTHETIC_ROBINHOOD_CSV = """Activity Date,Process Date,Settle Date,Instrument,Description,Trans Code,Quantity,Price,Amount
01/03/2026,01/03/2026,01/05/2026,,ACH Deposit,ACH,,,$54321.99
01/06/2026,01/06/2026,01/07/2026,NVDA,NVIDIA Corp,Buy,20,$135.00,-$2700.00
01/14/2026,01/14/2026,01/15/2026,NVDA,NVIDIA Corp,Sell,20,$148.50,$2970.00
"""

SYNTHETIC_TRADERSYNC_CSV = """Symbol,Open Date,Open Time,Close Date,Close Time,Side,Size,Entry Price,Exit Price,Return $,Return %,Setups,Mistakes
TSLA,2026-01-05,09:35:00,2026-01-05,10:15:00,LONG,50,250.00,262.00,$600.00,4.80%,ORB Breakout;VWAP Reclaim,Chased Entry $450.25;<script>alert(1)</script>
AMD,2026-01-08,10:00:00,2026-01-08,11:20:00,LONG,100,140.00,144.20,$420.00,3.00%,Opening Drive,Oversized Account 99887766
"""


def _wrap_pure_asgi(asgi_callable):
    """Strip direct ``.verify_app`` attribute so ``VerifyApiTestClient`` exercises full ASGI / FastAPI routing."""

    async def _app(scope, receive, send):
        await asgi_callable(scope, receive, send)

    return _app


def _build_multipart_body(
    *,
    boundary: str,
    file_field: str,
    filename: str,
    file_bytes: bytes,
    file_content_type: str = "text/csv",
    extra_fields: dict[str, str] | None = None,
) -> tuple[bytes, str]:
    chunks: list[bytes] = []
    for k, v in (extra_fields or {}).items():
        chunks.append(f"--{boundary}\r\n".encode("ascii"))
        chunks.append(f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode("utf-8"))
        chunks.append(v.encode("utf-8") + b"\r\n")
    chunks.append(f"--{boundary}\r\n".encode("ascii"))
    chunks.append(
        f'Content-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'.encode(
            "utf-8"
        )
    )
    chunks.append(f"Content-Type: {file_content_type}\r\n\r\n".encode("ascii"))
    chunks.append(file_bytes + b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode("ascii"))
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


def _make_signed_test_bundle(
    *,
    proof_id: str,
    publisher_kid: str,
    private_key_hex: str,
    blinding_salt_hex: str,
    broker_id: str = "ibkr_flex",
    account_id: str = "U10001",
    account_scope: AccountScope = AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    claimed_origin: OriginAssurance = OriginAssurance.OPERATOR_RETRIEVED,
    recon_status: ReconciliationStatus = ReconciliationStatus.RECONCILED_WITHIN_TOLERANCE,
    capital_bracket: CapitalBracket = CapitalBracket.BRACKET_100K_1M,
    base_currency: str = "USD",
    period_start_utc: str = "2026-01-01T00:00:00Z",
    period_end_utc: str = "2026-01-31T00:00:00Z",
    issued_at_utc: str = "2026-02-01T12:00:00Z",
    twr_decimal: float = 0.142,
    xirr_decimal: float | None = 0.85,
    max_dd_decimal: float = -0.035,
    psr: float | None = 0.982,
    observation_count: int = 40,
    curve_points: list[IndexedCurvePoint] | None = None,
    witness_attestations: list | None = None,
    extra_core_metrics: dict | None = None,
    override_core_metrics: dict | None = None,
):
    if curve_points is None:
        mid_idx = round(100.0 * (1.0 + twr_decimal * 0.45), 6)
        end_idx = round(100.0 * (1.0 + twr_decimal), 6)
        curve_points = [
            IndexedCurvePoint(timestamp_utc=period_start_utc, index_value=100.0, drawdown_pct=0.0),
            IndexedCurvePoint(
                timestamp_utc="2026-01-15T00:00:00Z",
                index_value=mid_idx,
                drawdown_pct=round(max_dd_decimal * 100.0, 6),
            ),
            IndexedCurvePoint(timestamp_utc=period_end_utc, index_value=end_idx, drawdown_pct=0.0),
        ]

    psr_eligible = observation_count >= 30
    perf = PerformanceSummary(
        twr_decimal=twr_decimal,
        xirr_decimal=xirr_decimal,
        probabilistic_sharpe_ratio=psr if psr_eligible else None,
        psr_sample_eligible=psr_eligible,
        observation_count=observation_count,
        max_drawdown_decimal=max_dd_decimal,
        capital_bracket=capital_bracket,
        benchmark_symbol="SPY",
        benchmark_twr_decimal=0.03,
        alpha_decimal=round(twr_decimal - 0.03, 8),
        indexed_curve=curve_points,
    )
    recon = ReconciliationReport(
        status=recon_status,
        reference_provider="eodhd",
        ledger_completeness_ok=(recon_status != ReconciliationStatus.INSUFFICIENT_SECTIONS),
        checks_evaluated=10,
        discrepancy_count=0,
        summary_text="Test reconciliation report.",
    )
    perf_d = perf.to_dict()
    core_leaf = {
        "twr_decimal": perf_d["twr_decimal"],
        "twr_pct": perf_d["twr_pct"],
        "xirr_decimal": perf_d["xirr_decimal"],
        "cagr_decimal": perf_d["cagr_decimal"],
        "cagr_pct": perf_d["cagr_pct"],
        "probabilistic_sharpe_ratio": perf_d["probabilistic_sharpe_ratio"],
        "psr_glm_unsmoothed": perf_d["psr_glm_unsmoothed"],
        "psr_sample_eligible": perf_d["psr_sample_eligible"],
        "observation_count": perf_d["observation_count"],
        "max_drawdown_decimal": perf_d["max_drawdown_decimal"],
        "max_drawdown_pct": perf_d["max_drawdown_pct"],
        "non_iid_caveat": perf_d["non_iid_caveat"],
    }
    if extra_core_metrics:
        core_leaf.update(extra_core_metrics)
    if override_core_metrics is not None:
        core_leaf = dict(override_core_metrics)

    leaf_payloads = {
        "core_metrics": core_leaf,
        "indexed_curve": {"base_index": 100.0, "points": [pt.to_dict() for pt in curve_points]},
        "reconciliation": recon.to_dict(),
        "coaching_and_context": {
            "style_summary": "Liquid equity momentum profile",
            "imported_journal_tags": [],
        },
        "capital_bracket": {"capital_bracket": capital_bracket.value},
        "benchmark_alpha": {
            "benchmark_symbol": "SPY",
            "benchmark_twr_decimal": 0.03,
            "alpha_decimal": round(twr_decimal - 0.03, 8),
        },
        "delayed_closed_trades": [],
    }
    tree = build_salted_merkle_tree(leaf_payloads)
    blinded_tag = compute_blinded_account_tag(broker_id, account_id, blinding_salt_hex)
    return create_signed_proof_bundle(
        proof_id=proof_id,
        issued_at_utc=issued_at_utc,
        publisher_kid=publisher_kid,
        publisher_private_key_hex=private_key_hex,
        broker_id=broker_id,
        blinded_account_tag=blinded_tag,
        account_scope=account_scope,
        provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
        environment_tier=EnvironmentTier.LIVE_PRODUCTION,
        claimed_origin_assurance=claimed_origin,
        source_body_sha256="aa" * 32,
        period_start_utc=period_start_utc,
        period_end_utc=period_end_utc,
        base_currency=base_currency,
        merkle_tree=tree,
        disclose_leaf_names=list(CANONICAL_LEAF_NAMES),
        witness_attestations=witness_attestations or (),
    )


class TestViralDistributionAndComparisonRoutes(unittest.TestCase):
    """End-to-end verification suite for W4-D viral distribution & comparison API routes."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        tmp_root = self._tmpdir.name
        self.proof_db_path = os.path.join(tmp_root, "proofs.sqlite3")
        self.sync_db_path = os.path.join(tmp_root, "sync.sqlite3")

        self.pub_kp = generate_ed25519_keypair(bytes.fromhex("11" * 32))
        self.revoked_kp = generate_ed25519_keypair(bytes.fromhex("33" * 32))
        self.notary_1_kp = generate_ed25519_keypair(bytes.fromhex("41" * 32))
        self.notary_2_kp = generate_ed25519_keypair(bytes.fromhex("42" * 32))
        self.ckpt_witness_kp = generate_ed25519_keypair(bytes.fromhex("51" * 32))

        notaries = [
            NotaryNodeInfo(
                notary_id="notary-pse-1",
                operator_org="PSE Foundation",
                asn="AS13335",
                public_key_hex=self.notary_1_kp.public_key_hex,
                is_debug_build=False,
                attestation_type="production",
            ),
            NotaryNodeInfo(
                notary_id="notary-ch-2",
                operator_org="Helvetia Witness Guild",
                asn="AS3303",
                public_key_hex=self.notary_2_kp.public_key_hex,
                is_debug_build=False,
                attestation_type="production",
            ),
        ]

        self.config = ApiConfig(
            db_path=self.proof_db_path,
            sync_db_path=self.sync_db_path,
            publisher_kid="pub-active-2026",
            publisher_keypair=self.pub_kp,
            publisher_key_not_before_utc="2025-01-01T00:00:00Z",
            additional_registry_keys=[
                PublisherKeyRecord(
                    publisher_kid="pub-revoked-2025",
                    public_key_hex=self.revoked_kp.public_key_hex,
                    status="revoked",
                    not_before_utc="2025-01-01T00:00:00Z",
                    revoked_after_utc="2025-09-01T00:00:00Z",
                ),
            ],
            trusted_notaries=notaries,
            checkpoint_origin="verify.n170.ai/continuity-log/v3",
            checkpoint_witness_signers=[
                (
                    "witness-c2sp-1",
                    self.ckpt_witness_kp.private_key_hex,
                    self.ckpt_witness_kp.public_key_hex,
                    "2026-02-10T12:00:00Z",
                )
            ],
            hosted_multi_user_mode=True,
            account_blinding_salt_hex="ab" * 32,
            vault_master_kek_hex="cd" * 32,
            sync_backup_retention_hours=0,
        )

        self.stdlib_app = create_app(self.config, prefer_fastapi=False)
        self.fastapi_app = create_app(
            self.config,
            store=self.stdlib_app.store,
            sync_vault=self.stdlib_app.sync_vault,
            prefer_fastapi=True,
        )
        self.stdlib_client = VerifyApiTestClient(self.stdlib_app)
        self.fastapi_client = VerifyApiTestClient(_wrap_pure_asgi(self.fastapi_app))
        self.clients = [
            ("stdlib", self.stdlib_client),
            ("fastapi_asgi", self.fastapi_client),
        ]

    def tearDown(self) -> None:
        self.stdlib_app.close()
        self._tmpdir.cleanup()

    # ------------------------------------------------------------------
    # 1. POST /api/v1/tools/plausibility
    # ------------------------------------------------------------------

    def test_plausibility_valid_calculations_and_t_alias_across_stdlib_and_fastapi(self) -> None:
        for mode_name, client in self.clients:
            with self.subTest(mode=mode_name):
                opt_resp = client.options("/api/v1/tools/plausibility")
                self.assertEqual(opt_resp.status_code, 204)

                get_resp = client.get("/api/v1/tools/plausibility")
                self.assertEqual(get_resp.status_code, 405)

                # High Sharpe over large sample (statistically supported)
                resp_ok = client.post(
                    "/api/v1/tools/plausibility",
                    json={
                        "claimed_sharpe": 2.5,
                        "observed_periods": 756,
                        "annualization_factor": 252,
                        "skewness": -0.25,
                        "excess_kurtosis": 3.0,
                        "benchmark_sharpe": 0.5,
                    },
                )
                self.assertEqual(resp_ok.status_code, 200, resp_ok.text)
                body = resp_ok.json()
                self.assertEqual(body["claimed_sharpe"], 2.5)
                self.assertEqual(body["observed_periods"], 756)
                self.assertEqual(body["annualization_factor"], 252)
                self.assertGreater(body["implied_psr"], 0.99)
                self.assertIsNotNone(body["required_min_trl_periods_95pct"])
                self.assertLess(body["required_min_trl_periods_95pct"], 756.0)
                self.assertGreaterEqual(len(body["bell_curve_points"]), 30)
                self.assertTrue(body["plain_english_summary"])

                # Alias T with T < 30 gate
                resp_short = client.post(
                    "/api/v1/tools/plausibility",
                    json={"claimed_sharpe": 4.8, "T": 14},
                )
                self.assertEqual(resp_short.status_code, 200, resp_short.text)
                short_body = resp_short.json()
                self.assertEqual(short_body["observed_periods"], 14)
                self.assertEqual(short_body["excess_kurtosis"], 3.0)
                self.assertEqual(short_body["benchmark_sharpe"], 0.0)
                self.assertIn("NOISE", short_body["sufficiency_tier"].upper())

                # Claimed Sharpe <= benchmark Sharpe -> MinTRL unattainable (None)
                resp_below = client.post(
                    "/api/v1/tools/plausibility",
                    json={"claimed_sharpe": -0.5, "observed_periods": 120, "benchmark_sharpe": 0.5},
                )
                self.assertEqual(resp_below.status_code, 200, resp_below.text)
                self.assertIsNone(resp_below.json()["required_min_trl_periods_95pct"])

                # Exact inclusive boundary edges succeed
                resp_edges = client.post(
                    "/api/v1/tools/plausibility",
                    json={
                        "claimed_sharpe": 50.0,
                        "observed_periods": 25000,
                        "benchmark_sharpe": 20.0,
                        "skewness": -10.0,
                        "excess_kurtosis": -2.0,
                        "annualization_factor": 10000,
                    },
                )
                self.assertEqual(resp_edges.status_code, 200, resp_edges.text)

    def test_plausibility_strict_dos_and_numeric_overflow_bounds_never_500(self) -> None:
        raw_bad_payloads: list[tuple[str, bytes]] = [
            ("empty", b""),
            ("malformed_json", b"{not-valid-json"),
            ("array_json", b"[1, 2, 3]"),
            ("string_json", b'"just a string"'),
            ("number_json", b"42"),
            ("null_json", b"null"),
            ("nan_constant", b'{"claimed_sharpe": NaN, "observed_periods": 100}'),
            ("inf_constant", b'{"claimed_sharpe": Infinity, "observed_periods": 100}'),
            ("neg_inf_constant", b'{"claimed_sharpe": -Infinity, "observed_periods": 100}'),
            ("float_1e308", b'{"claimed_sharpe": 1e308, "observed_periods": 100}'),
            ("float_1e500_overflow", b'{"claimed_sharpe": 1e500, "observed_periods": 100}'),
            (
                "oversized_dos_body",
                b'{"claimed_sharpe": 2.0, "observed_periods": 100, "pad": "'
                + (b"x" * (MAX_PLAUSIBILITY_BODY_BYTES + 1024))
                + b'"}',
            ),
        ]

        dict_bad_payloads: list[tuple[str, dict]] = [
            ("missing_required", {"claimed_sharpe": 2.0}),
            ("bool_sharpe_true", {"claimed_sharpe": True, "observed_periods": 100}),
            ("bool_sharpe_false", {"claimed_sharpe": False, "observed_periods": 100}),
            ("bool_periods", {"claimed_sharpe": 1.5, "observed_periods": True}),
            ("bool_T_alias", {"claimed_sharpe": 1.5, "T": False}),
            ("bool_ann_factor", {"claimed_sharpe": 1.5, "observed_periods": 60, "annualization_factor": True}),
            ("bool_skewness", {"claimed_sharpe": 1.5, "observed_periods": 60, "skewness": False}),
            ("bool_kurtosis", {"claimed_sharpe": 1.5, "observed_periods": 60, "excess_kurtosis": True}),
            ("bool_benchmark", {"claimed_sharpe": 1.5, "observed_periods": 60, "benchmark_sharpe": True}),
            ("float_periods", {"claimed_sharpe": 1.5, "observed_periods": 60.5}),
            ("float_ann_factor", {"claimed_sharpe": 1.5, "observed_periods": 60, "annualization_factor": 252.5}),
            ("conflicting_T_alias", {"claimed_sharpe": 1.5, "observed_periods": 60, "T": 90}),
            ("periods_below_min", {"claimed_sharpe": 1.5, "observed_periods": 1}),
            ("periods_above_max", {"claimed_sharpe": 1.5, "observed_periods": 25001}),
            ("sharpe_below_min", {"claimed_sharpe": -20.01, "observed_periods": 100}),
            ("sharpe_above_max", {"claimed_sharpe": 50.01, "observed_periods": 100}),
            ("benchmark_below_min", {"claimed_sharpe": 1.5, "observed_periods": 100, "benchmark_sharpe": -10.01}),
            ("benchmark_above_max", {"claimed_sharpe": 1.5, "observed_periods": 100, "benchmark_sharpe": 20.01}),
            ("skew_below_min", {"claimed_sharpe": 1.5, "observed_periods": 100, "skewness": -10.01}),
            ("skew_above_max", {"claimed_sharpe": 1.5, "observed_periods": 100, "skewness": 10.01}),
            ("kurtosis_below_min", {"claimed_sharpe": 1.5, "observed_periods": 100, "excess_kurtosis": -2.01}),
            ("kurtosis_above_max", {"claimed_sharpe": 1.5, "observed_periods": 100, "excess_kurtosis": 50.01}),
            ("ann_below_min", {"claimed_sharpe": 1.5, "observed_periods": 100, "annualization_factor": 0}),
            ("ann_above_max", {"claimed_sharpe": 1.5, "observed_periods": 100, "annualization_factor": 10001}),
        ]

        for mode_name, client in self.clients:
            for case_name, raw_bytes in raw_bad_payloads:
                with self.subTest(mode=mode_name, raw_case=case_name):
                    resp = client.post(
                        "/api/v1/tools/plausibility",
                        content=raw_bytes,
                        headers={"Content-Type": "application/json"},
                    )
                    self.assertIn(resp.status_code, (400, 422), f"{case_name} returned {resp.status_code}: {resp.text}")
                    self.assertIn("error", resp.json())

            for case_name, bad_dict in dict_bad_payloads:
                with self.subTest(mode=mode_name, dict_case=case_name):
                    resp = client.post("/api/v1/tools/plausibility", json=bad_dict)
                    self.assertIn(resp.status_code, (400, 422), f"{case_name} returned {resp.status_code}: {resp.text}")
                    self.assertIn("error", resp.json())

    # ------------------------------------------------------------------
    # 2. GET /api/v1/vs/{proof_a}/{proof_b}
    # ------------------------------------------------------------------

    def test_head_to_head_vs_dynamic_reverification_synchronized_series_and_warnings(self) -> None:
        # Proof A overclaims INDEPENDENTLY_WITNESSED_TLS with only 1 notary signature -> dynamically downgraded!
        single_att = create_signed_witness_attestation(
            notary_private_key_hex=self.notary_1_kp.private_key_hex,
            notary_id="notary-pse-1",
            server_sni="ndcdyn.interactivebrokers.com",
            sanitized_request_target="/AccountManagement/FlexWebService/GetStatement",
            redacted_headers=["Authorization: [REDACTED]"],
            response_body_sha256="aa" * 32,
            session_timestamp_utc="2026-01-31T23:55:00Z",
        )
        curve_a = [
            IndexedCurvePoint(timestamp_utc="2026-01-01T00:00:00Z", index_value=100.0, drawdown_pct=0.0),
            IndexedCurvePoint(timestamp_utc="2026-01-10T00:00:00Z", index_value=105.0, drawdown_pct=0.0),
            IndexedCurvePoint(timestamp_utc="2026-01-20T00:00:00Z", index_value=102.9, drawdown_pct=-2.0),
            IndexedCurvePoint(timestamp_utc="2026-01-31T00:00:00Z", index_value=118.0, drawdown_pct=0.0),
        ]
        bundle_a = _make_signed_test_bundle(
            proof_id="prf-alpha-01",
            publisher_kid="pub-active-2026",
            private_key_hex=self.pub_kp.private_key_hex,
            blinding_salt_hex=self.config.account_blinding_salt_hex,
            account_id="U-ALPHA",
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            claimed_origin=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
            period_start_utc="2026-01-01T00:00:00Z",
            period_end_utc="2026-01-31T00:00:00Z",
            twr_decimal=0.18,
            xirr_decimal=0.92,
            max_dd_decimal=-0.02,
            psr=0.991,
            observation_count=45,
            curve_points=curve_a,
            witness_attestations=[single_att],
        )

        # Proof B has partial date overlap (Jan 10 .. Feb 10), EUR currency, T=18 (<30 PSR gate), SELF_REPORTED
        curve_b = [
            IndexedCurvePoint(timestamp_utc="2026-01-10T00:00:00Z", index_value=100.0, drawdown_pct=0.0),
            IndexedCurvePoint(timestamp_utc="2026-01-20T00:00:00Z", index_value=108.0, drawdown_pct=0.0),
            IndexedCurvePoint(timestamp_utc="2026-01-31T00:00:00Z", index_value=104.76, drawdown_pct=-3.0),
            IndexedCurvePoint(timestamp_utc="2026-02-10T00:00:00Z", index_value=112.0, drawdown_pct=0.0),
        ]
        bundle_b = _make_signed_test_bundle(
            proof_id="prf-beta-02",
            publisher_kid="pub-active-2026",
            private_key_hex=self.pub_kp.private_key_hex,
            blinding_salt_hex=self.config.account_blinding_salt_hex,
            broker_id="degiro",
            account_id="ACC-BETA",
            account_scope=AccountScope.UNKNOWN_OFFLINE_SCOPE,
            claimed_origin=OriginAssurance.SELF_REPORTED,
            recon_status=ReconciliationStatus.INSUFFICIENT_SECTIONS,
            capital_bracket=CapitalBracket.BRACKET_10K_100K,
            base_currency="EUR",
            period_start_utc="2026-01-10T00:00:00Z",
            period_end_utc="2026-02-10T00:00:00Z",
            twr_decimal=0.12,
            xirr_decimal=0.61,
            max_dd_decimal=-0.03,
            psr=0.97,
            observation_count=18,
            curve_points=curve_b,
        )

        self.stdlib_app.store.store_proof(bundle_a)
        self.stdlib_app.store.store_proof(bundle_b)

        for mode_name, client in self.clients:
            with self.subTest(mode=mode_name):
                resp = client.get("/api/v1/vs/prf-alpha-01/prf-beta-02")
                self.assertEqual(resp.status_code, 200, resp.text)
                data = resp.json()
                self.assertTrue(data["realized_metrics_only"])

                pa = data["proof_a"]
                pb = data["proof_b"]
                self.assertEqual(pa["bundle_id"], "prf-alpha-01")
                self.assertEqual(pa["merkle_root"], bundle_a.merkle_root)
                # Spoofed INDEPENDENTLY_WITNESSED_TLS was dynamically downgraded!
                self.assertNotEqual(pa["origin_assurance"], "independently_witnessed_tls")
                self.assertEqual(pa["origin_assurance"], "operator_retrieved")
                self.assertEqual(pa["signer_trust"], "official_n170_hosted")
                self.assertEqual(pa["reconciliation_status"], "reconciled_within_tolerance")
                self.assertEqual(pa["account_scope"], "all_enumerated_subaccounts")
                self.assertAlmostEqual(pa["twr"], 0.18, places=6)
                self.assertAlmostEqual(pa["xirr"], 0.92, places=6)
                self.assertAlmostEqual(pa["max_drawdown"], -0.02, places=6)
                self.assertAlmostEqual(pa["psr"], 0.991, places=6)

                # Proof B respects T >= 30 gate
                self.assertEqual(pb["origin_assurance"], "self_reported")
                self.assertEqual(pb["account_scope"], "unknown_offline_scope")
                self.assertIsNone(pb["psr"])
                self.assertEqual(pb["psr_display"], "Insufficient N (<30)")

                # Synchronized overlapping wealth & underwater series (Jan 10 .. Jan 31)
                sync = data["synchronized_series"]
                self.assertTrue(sync["disclosed"])
                self.assertTrue(sync["overlap"])
                self.assertEqual(sync["overlap_start_utc"], "2026-01-10T00:00:00Z")
                self.assertEqual(sync["overlap_end_utc"], "2026-01-31T00:00:00Z")
                self.assertEqual(len(sync["wealth_series"]), 3)
                self.assertEqual(sync["wealth_series"][0]["proof_a_index"], 100.0)
                self.assertEqual(sync["wealth_series"][0]["proof_b_index"], 100.0)
                # On Jan 20, proof A dropped from 105.0 -> 102.9 (-2.0% underwater)
                self.assertAlmostEqual(sync["underwater_series"][1]["proof_a_drawdown_pct"], -2.0, places=4)
                # On Jan 31, proof B dropped from 108.0 -> 104.76 (-3.0% underwater)
                self.assertAlmostEqual(sync["underwater_series"][2]["proof_b_drawdown_pct"], -3.0, places=4)

                joined_warnings = " | ".join(data["comparability_warnings"])
                self.assertIn("Measurement periods differ", joined_warnings)
                self.assertIn("origin assurance", joined_warnings)
                self.assertIn("survivorship scope", joined_warnings)
                self.assertIn("base currencies", joined_warnings)
                self.assertIn("T >= 30", joined_warnings)

    def test_head_to_head_vs_rejects_invalid_ids_missing_tampered_revoked_and_simulated_metrics(self) -> None:
        clean_bundle = _make_signed_test_bundle(
            proof_id="prf-clean-01",
            publisher_kid="pub-active-2026",
            private_key_hex=self.pub_kp.private_key_hex,
            blinding_salt_hex=self.config.account_blinding_salt_hex,
        )
        self.stdlib_app.store.store_proof(clean_bundle)

        # Bundle whose core_metrics leaf contains ONLY hypothetical twin & bootstrap fields (no realized twr/xirr)
        sim_only_bundle = _make_signed_test_bundle(
            proof_id="prf-sim-guard-02",
            publisher_kid="pub-active-2026",
            private_key_hex=self.pub_kp.private_key_hex,
            blinding_salt_hex=self.config.account_blinding_salt_hex,
            account_id="U-SIM-GUARD",
            override_core_metrics={
                "observation_count": 45,
                "psr_sample_eligible": True,
                "counterfactual_twin": {
                    "is_hypothetical_simulation": True,
                    "zero_friction_twr_decimal": 0.999,
                    "zero_friction_ending_index": 199.9,
                },
                "bootstrap_summary": {
                    "is_simulated_bootstrap": True,
                    "median_terminal_return": 0.888,
                },
            },
        )
        self.stdlib_app.store.store_proof(sim_only_bundle)

        for mode_name, client in self.clients:
            with self.subTest(mode=mode_name):
                # 1. Simulated fields NEVER masquerade as realized twr/xirr
                sim_resp = client.get("/api/v1/vs/prf-clean-01/prf-sim-guard-02")
                self.assertEqual(sim_resp.status_code, 200, sim_resp.text)
                pb_sim = sim_resp.json()["proof_b"]
                self.assertIsNone(pb_sim["twr"])
                self.assertIsNone(pb_sim["twr_pct"])
                self.assertIsNone(pb_sim["xirr"])

                # 2. Invalid characters in proof_a or proof_b -> 400
                for bad_url in (
                    "/api/v1/vs/..prf-evil/prf-clean-01",
                    "/api/v1/vs/prf-clean-01/%3Cscript%3E",
                    "/api/v1/vs/bad%2Fid/prf-clean-01",
                    "/api/v1/vs//prf-clean-01",
                    "/api/v1/vs/prf-clean-01/prf-b/extra",
                ):
                    r_bad = client.get(bad_url)
                    self.assertEqual(r_bad.status_code, 400, f"{bad_url} -> {r_bad.status_code}: {r_bad.text}")

                # 3. Missing proof -> 404
                r_404 = client.get("/api/v1/vs/prf-clean-01/prf-does-not-exist")
                self.assertEqual(r_404.status_code, 404)

                # 4. Wrong method -> 405
                self.assertEqual(client.post("/api/v1/vs/prf-clean-01/prf-sim-guard-02", json={}).status_code, 405)

        # 5. Tamper stored proof directly in SQLite -> live C2SP verification at read time returns 422!
        tamper_bundle = _make_signed_test_bundle(
            proof_id="prf-tampered-03",
            publisher_kid="pub-active-2026",
            private_key_hex=self.pub_kp.private_key_hex,
            blinding_salt_hex=self.config.account_blinding_salt_hex,
            account_id="U-TAMPER",
        )
        self.stdlib_app.store.store_proof(tamper_bundle)

        mutated_dict = tamper_bundle.to_dict()
        for leaf in mutated_dict["disclosed_leaves"]:
            if leaf["leaf_name"] == "core_metrics":
                leaf["payload"]["twr_decimal"] = 9.99
        conn = sqlite3.connect(self.proof_db_path)
        try:
            conn.execute(
                "UPDATE proofs SET bundle_json = ? WHERE proof_id = ?",
                (json.dumps(mutated_dict), "prf-tampered-03"),
            )
            conn.commit()
        finally:
            conn.close()

        for mode_name, client in self.clients:
            with self.subTest(mode=mode_name):
                r_tamp = client.get("/api/v1/vs/prf-clean-01/prf-tampered-03")
                self.assertEqual(r_tamp.status_code, 422, r_tamp.text)
                self.assertIn("prf-tampered-03", r_tamp.json()["failed_proof_ids"])

    # ------------------------------------------------------------------
    # 3. GET /api/v1/challenge-card
    # ------------------------------------------------------------------

    def test_challenge_card_xss_escaping_truncation_and_privacy_copy(self) -> None:
        xss_handle = (
            '<script>alert("xss")</script>@everyone @alpha_trader" '
            "onload=evil() javascript:alert(1) \x00\x07" + ("Z" * 80)
        )
        xss_period = "<img src=x onerror=alert(1)>2026 YTD 'quote'"

        for mode_name, client in self.clients:
            with self.subTest(mode=mode_name):
                resp = client.get(
                    "/api/v1/challenge-card",
                    params={
                        "handle": xss_handle,
                        "claimed_return_pct": "185.4",
                        "claimed_sharpe": "4.25",
                        "period_label": xss_period,
                    },
                )
                self.assertEqual(resp.status_code, 200, resp.text)
                self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
                self.assertIn("default-src 'none'", resp.headers.get("Content-Security-Policy", ""))

                raw_text = resp.text
                self.assertNotIn("<script>", raw_text)
                self.assertNotIn("onload=", raw_text.lower())
                self.assertNotIn("onerror=", raw_text.lower())
                self.assertNotIn("javascript:", raw_text.lower())
                self.assertNotIn("@everyone", raw_text.lower())

                body = resp.json()
                self.assertLessEqual(len(body["handle"]), 64)
                self.assertLessEqual(len(body["period_label"]), 64)
                self.assertTrue(body["non_defamatory"])
                self.assertEqual(body["estimated_verification_seconds"], 60)

                msg = body["invitation_message"]
                self.assertIn("60 seconds", msg)
                self.assertIn("RFC 6962", msg)
                self.assertIn("HMAC-SHA256", msg)
                self.assertIn("7-day", msg)

                # Invalid numeric query params return 422 (never 500)
                bad_q = client.get("/api/v1/challenge-card", params={"claimed_sharpe": "NaN"})
                self.assertEqual(bad_q.status_code, 422)
                bad_q2 = client.get("/api/v1/challenge-card", params={"claimed_sharpe": "999.0"})
                self.assertEqual(bad_q2.status_code, 422)

    # ------------------------------------------------------------------
    # 4. Discord Embed, QR Payload, & Hardened SVG Badge CSP/XSS
    # ------------------------------------------------------------------

    def test_discord_embed_qr_payload_and_svg_badge_csp_and_xss_hardening(self) -> None:
        # Proof with T < 30 and hostile broker_id string to verify sanitization & PSR gate
        hostile_proof_id = "prf-xss-card-01"
        bundle_short = _make_signed_test_bundle(
            proof_id=hostile_proof_id,
            publisher_kid="pub-active-2026",
            private_key_hex=self.pub_kp.private_key_hex,
            blinding_salt_hex=self.config.account_blinding_salt_hex,
            broker_id='ibkr<script>onload=1</script>@everyone[evil](javascript:1)',
            account_id="U-SHORT-1",
            claimed_origin=OriginAssurance.SELF_REPORTED,
            recon_status=ReconciliationStatus.INSUFFICIENT_SECTIONS,
            twr_decimal=0.245,
            observation_count=12,
        )
        self.stdlib_app.store.store_proof(bundle_short)

        for mode_name, client in self.clients:
            with self.subTest(mode=mode_name):
                # A. Discord / Telegram rich embed
                d_resp = client.get(f"/api/v1/proofs/{quote(hostile_proof_id, safe='')}/discord-embed")
                self.assertEqual(d_resp.status_code, 200, d_resp.text)
                self.assertEqual(d_resp.headers.get("X-Content-Type-Options"), "nosniff")
                self.assertEqual(
                    d_resp.headers.get("Content-Security-Policy"),
                    "default-src 'none'; frame-ancestors *",
                )
                self.assertNotIn("<script>", d_resp.text)
                self.assertNotIn("onload=", d_resp.text.lower())
                self.assertNotIn("javascript:", d_resp.text.lower())
                self.assertNotIn("@everyone", d_resp.text.lower())

                d_body = d_resp.json()
                self.assertEqual(d_body["metrics"]["psr"], "Insufficient N (<30)")
                self.assertEqual(d_body["trust_chips"]["origin_assurance"], "self_reported")
                self.assertEqual(d_body["trust_chips"]["signer_trust"], "official_n170_hosted")
                self.assertEqual(d_body["trust_chips"]["reconciliation_status"], "insufficient_sections")
                self.assertEqual(d_body["trust_chips"]["account_scope"], "all_enumerated_subaccounts")
                self.assertEqual(len(d_body["embeds"]), 1)
                self.assertIn("Insufficient N (<30)", d_body["telegram_markdown"])

                # B. QR Payload & Share Card specs
                q_resp = client.get(f"/api/v1/proofs/{quote(hostile_proof_id, safe='')}/qr-payload")
                self.assertEqual(q_resp.status_code, 200, q_resp.text)
                self.assertEqual(q_resp.headers.get("X-Content-Type-Options"), "nosniff")
                self.assertEqual(
                    q_resp.headers.get("Content-Security-Policy"),
                    "default-src 'none'; frame-ancestors *",
                )
                q_body = q_resp.json()
                self.assertTrue(q_body["offline_verification_uri"].startswith("n170verify://v3/"))
                self.assertEqual(q_body["proof_path"], f"/p/{hostile_proof_id}")
                self.assertEqual(q_body["merkle_root"], bundle_short.merkle_root)
                self.assertEqual(q_body["ed25519_key_id"], "pub-active-2026")
                self.assertEqual(len(q_body["signature_fingerprint"]), 32)
                self.assertEqual(
                    set(q_body["trust_enums"].keys()),
                    {"origin_assurance", "signer_trust", "reconciliation_status", "account_scope"},
                )
                self.assertEqual(q_body["share_cards"]["16:9"]["width"], 1600)
                self.assertEqual(q_body["share_cards"]["9:16"]["height"], 1920)

                # Missing proof returns 404 on both endpoints
                self.assertEqual(client.get("/api/v1/proofs/missing-id/discord-embed").status_code, 404)
                self.assertEqual(client.get("/api/v1/proofs/missing-id/qr-payload").status_code, 404)

                # C. SVG Badge XSS & strict CSP headers
                b_resp = client.get(
                    f"/api/v1/badges/{quote(hostile_proof_id, safe='')}.svg",
                    params={"label": '<script>alert(1)</script>" onload="bad() \x00\x1f'},
                )
                self.assertEqual(b_resp.status_code, 200)
                self.assertEqual(
                    b_resp.headers.get("Content-Security-Policy"),
                    "default-src 'none'; style-src 'unsafe-inline'; sandbox",
                )
                self.assertEqual(b_resp.headers.get("X-Content-Type-Options"), "nosniff")
                svg_text = b_resp.text
                self.assertNotIn("<script>", svg_text)
                self.assertIn("&lt;script&gt;", svg_text)
                # Prove valid well-formed XML
                parsed_xml = ET.fromstring(b_resp.content)
                self.assertTrue(parsed_xml.tag.endswith("svg"))

    # ------------------------------------------------------------------
    # 5. POST /api/v1/verify/auto-detect & GET /api/v1/connect/ibkr-flex-guide
    # ------------------------------------------------------------------

    def test_verify_auto_detect_ephemeral_worker_isolation_formats_and_zero_leakage(self) -> None:
        baseline_counts = self.stdlib_app.store.total_row_counts()

        # 1. JSON IBKR Flex XML upload -> isolated spawn worker, zero $ NAV / account ID leakage
        ibkr_resp = self.fastapi_client.post(
            "/api/v1/verify/auto-detect",
            json={
                "raw_statement_text": SYNTHETIC_LIVE_IBKR_FLEX_XML,
                "filename": "ibkr_activity_2026.xml",
                "issued_at_utc": "2026-01-31T12:00:00Z",
            },
        )
        self.assertEqual(ibkr_resp.status_code, 200, ibkr_resp.text)
        raw_out = ibkr_resp.text
        # Zero raw dollar NAVs, zero raw account IDs, zero raw XML statement bytes!
        for forbidden_secret in ("987654.32", "995120.10", "1029410.88", "U7654321", "<FlexQueryResponse"):
            self.assertNotIn(forbidden_secret, raw_out)

        ibkr_data = ibkr_resp.json()
        self.assertEqual(ibkr_data["detected_format"], "ibkr_flex_xml")
        self.assertEqual(ibkr_data["origin_assurance"], "self_reported")
        self.assertTrue(ibkr_data["verification"]["valid"])
        self.assertIn("spawn", ibkr_data["isolation_receipt"]["execution_mode"])
        self.assertTrue(ibkr_data["isolation_receipt"]["worker_terminated"])
        self.assertEqual(ibkr_data["isolation_receipt"]["worker_exitcode"], 0)
        self.assertTrue(ibkr_data["isolation_receipt"]["sanitized_child_env"])
        self.assertNotEqual(ibkr_data["isolation_receipt"]["worker_pid"], os.getpid())
        self.assertEqual(ibkr_data["isolation_receipt"]["rlimit_core"], [0, 0])
        self.assertEqual(ibkr_data["isolation_receipt"]["retention_mode"], "no_persistent_storage")
        self.assertEqual(ibkr_data["isolation_receipt"]["persistent_rows_written"], 0)
        # Recent MSFT closed trade (2026-01-29 vs issued_at 2026-01-31, < 7 days) stripped!
        self.assertGreaterEqual(ibkr_data["stripped_recent_closed_trades_count"], 1)
        self.assertEqual(self.stdlib_app.store.total_row_counts(), baseline_counts)

        # 2. Multipart/form-data TraderSync journal CSV -> INSUFFICIENT_SECTIONS + sanitized tags
        mp_body, mp_ct = _build_multipart_body(
            boundary="----N170ViralBoundary789",
            file_field="file",
            filename="tradersync_trades.csv",
            file_bytes=SYNTHETIC_TRADERSYNC_CSV.encode("utf-8"),
            extra_fields={"base_currency": "USD", "issued_at_utc": "2026-02-01T00:00:00Z"},
        )
        ts_resp = self.stdlib_client.post(
            "/api/v1/verify/auto-detect",
            content=mp_body,
            headers={"Content-Type": mp_ct},
        )
        self.assertEqual(ts_resp.status_code, 200, ts_resp.text)
        ts_text = ts_resp.text
        for forbidden_journal_secret in ("$600.00", "$450.25", "99887766", "<script>"):
            self.assertNotIn(forbidden_journal_secret, ts_text)
        ts_data = ts_resp.json()
        self.assertIn("tradersync", ts_data["detected_format"].lower())
        self.assertEqual(ts_data["origin_assurance"], "self_reported")
        self.assertEqual(ts_data["reconciliation_status"], "insufficient_sections")
        self.assertTrue(any("ORB Breakout" in t for t in ts_data["imported_journal_tags"]))

        # Suppressing journal tags with include_journal_tags=False yields empty list
        ts_notags = self.stdlib_client.post(
            "/api/v1/verify/auto-detect",
            json={
                "raw_statement_b64": base64.b64encode(SYNTHETIC_TRADERSYNC_CSV.encode("utf-8")).decode("ascii"),
                "filename": "tradersync_trades.csv",
                "include_journal_tags": False,
                "issued_at_utc": "2026-02-01T00:00:00Z",
            },
        )
        self.assertEqual(ts_notags.status_code, 200, ts_notags.text)
        self.assertEqual(ts_notags.json()["imported_journal_tags"], [])

        # 3. Raw CSV body upload (Robinhood CSV)
        rh_resp = self.fastapi_client.post(
            "/api/v1/verify/auto-detect?base_currency=USD&issued_at_utc=2026-02-01T00:00:00Z",
            content=SYNTHETIC_ROBINHOOD_CSV.encode("utf-8"),
            headers={"Content-Type": "text/csv", "X-Filename": "robinhood_activity.csv"},
        )
        self.assertEqual(rh_resp.status_code, 200, rh_resp.text)
        self.assertNotIn("54321.99", rh_resp.text)
        self.assertEqual(rh_resp.json()["detected_format"], "robinhood_csv")
        self.assertEqual(rh_resp.json()["origin_assurance"], "self_reported")

        # 4. Paper IBKR account & is_paper=True rejected with 422
        paper_xml_resp = self.stdlib_client.post(
            "/api/v1/verify/auto-detect",
            json={"raw_statement_text": SYNTHETIC_PAPER_IBKR_FLEX_XML},
        )
        self.assertEqual(paper_xml_resp.status_code, 422, paper_xml_resp.text)
        self.assertEqual(paper_xml_resp.json()["error"], "paper_or_sandbox_rejected")

        paper_flag_resp = self.stdlib_client.post(
            "/api/v1/verify/auto-detect",
            json={"raw_statement_text": SYNTHETIC_ROBINHOOD_CSV, "is_paper": True},
        )
        self.assertEqual(paper_flag_resp.status_code, 422)

        # 5. XXE XML payload rejected with 422
        xxe_resp = self.stdlib_client.post(
            "/api/v1/verify/auto-detect",
            content=SYNTHETIC_XXE_IBKR_XML.encode("utf-8"),
            headers={"Content-Type": "application/xml"},
        )
        self.assertEqual(xxe_resp.status_code, 422, xxe_resp.text)

        # 6. > 25 MB upload rejected with 413 BEFORE spawning worker subprocess!
        oversized_bytes = b"A" * (MAX_STATEMENT_UPLOAD_BYTES + 2048)
        with patch("app.routes_viral.run_isolated_one_shot_verification") as mock_worker:
            over_resp = self.stdlib_client.post(
                "/api/v1/verify/auto-detect",
                content=oversized_bytes,
                headers={"Content-Type": "text/csv"},
            )
            self.assertEqual(over_resp.status_code, 413)
            mock_worker.assert_not_called()

        # 7. IBKR Flex read-only setup guide endpoint
        guide_resp = self.fastapi_client.get("/api/v1/connect/ibkr-flex-guide")
        self.assertEqual(guide_resp.status_code, 200, guide_resp.text)
        self.assertTrue(guide_resp.json())

        # Verify zero persistent rows were ever written during one-shot verifications
        self.assertEqual(self.stdlib_app.store.total_row_counts(), baseline_counts)

    def test_direct_core_delegation_remains_consistent(self) -> None:
        status_plaus, plaus = handle_post_plausibility(
            {
                "claimed_sharpe": 2.2,
                "observed_periods": 120,
                "annualization_factor": 252,
                "skewness": -0.1,
                "excess_kurtosis": 3.0,
                "benchmark_sharpe": 0.0,
            }
        )
        self.assertEqual(status_plaus, 200)
        self.assertGreater(plaus["implied_psr"], 0.90)
        self.assertTrue(plaus["bell_curve_points"])

        det = detect_and_parse_statement(
            SYNTHETIC_TRADERSYNC_CSV.encode("utf-8"),
            filename="tradersync.csv",
            blinding_salt_hex="ab" * 32,
            base_currency="USD",
        )
        self.assertEqual(det.detected_format, "tradersync_journal")
        self.assertEqual(det.reconciliation_status_override, ReconciliationStatus.INSUFFICIENT_SECTIONS)

        status_guide, guide = handle_get_ibkr_flex_guide()
        self.assertEqual(status_guide, 200)
        self.assertEqual(guide["broker_id"], "ibkr")

    def test_dynamic_key_revocation_blocks_vs_discord_embed_and_qr_payload(self) -> None:
        temp_kp = generate_ed25519_keypair(bytes.fromhex("77" * 32))
        self.config.additional_registry_keys.append(
            PublisherKeyRecord(
                publisher_kid="pub-ephemeral-rotatable",
                public_key_hex=temp_kp.public_key_hex,
                status="active",
                not_before_utc="2025-01-01T00:00:00Z",
            )
        )
        b_active = _make_signed_test_bundle(
            proof_id="prf-anchor-live",
            publisher_kid="pub-active-2026",
            private_key_hex=self.pub_kp.private_key_hex,
            blinding_salt_hex=self.config.account_blinding_salt_hex,
            account_id="U-ANCHOR",
        )
        b_rot = _make_signed_test_bundle(
            proof_id="prf-later-revoked",
            publisher_kid="pub-ephemeral-rotatable",
            private_key_hex=temp_kp.private_key_hex,
            blinding_salt_hex=self.config.account_blinding_salt_hex,
            account_id="U-ROT",
            issued_at_utc="2026-02-01T12:00:00Z",
        )
        self.stdlib_app.store.store_proof(b_active)
        self.stdlib_app.store.store_proof(b_rot)

        # Before revocation: all three read-time endpoints verify 200
        self.assertEqual(self.fastapi_client.get("/api/v1/vs/prf-anchor-live/prf-later-revoked").status_code, 200)
        self.assertEqual(self.fastapi_client.get("/api/v1/proofs/prf-later-revoked/discord-embed").status_code, 200)
        self.assertEqual(self.fastapi_client.get("/api/v1/proofs/prf-later-revoked/qr-payload").status_code, 200)

        # Dynamically revoke key in C2SP registry retroactive before issued_at_utc
        self.config.additional_registry_keys = [
            k
            for k in self.config.additional_registry_keys
            if k.publisher_kid != "pub-ephemeral-rotatable"
        ] + [
            PublisherKeyRecord(
                publisher_kid="pub-ephemeral-rotatable",
                public_key_hex=temp_kp.public_key_hex,
                status="revoked",
                not_before_utc="2025-01-01T00:00:00Z",
                revoked_after_utc="2026-01-15T00:00:00Z",
            )
        ]

        # After revocation: dynamic C2SP re-verification rejects on all three endpoints with 422
        for mode_name, client in self.clients:
            with self.subTest(mode=mode_name):
                self.assertEqual(client.get("/api/v1/vs/prf-anchor-live/prf-later-revoked").status_code, 422)
                self.assertEqual(client.get("/api/v1/proofs/prf-later-revoked/discord-embed").status_code, 422)
                self.assertEqual(client.get("/api/v1/proofs/prf-later-revoked/qr-payload").status_code, 422)


if __name__ == "__main__":
    unittest.main()
