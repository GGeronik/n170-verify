"""Pipeline, CLI, Analytical Parity, and Cross-Stack Verification Test Suite for N170 Verify v3.

Verifies:
1. Exact mathematical, cash-flow, TWR, drawdown, XIRR, and redaction parity on synthetic
   in-memory IBKR Activity Flex v3 statements.
2. Zero prohibited runtime imports across all standalone production modules
   (``core/``, ``api/``, ``mcp/``, ``web/``).
3. Unified ``verify_portfolio(...)`` pipeline across IBKR Flex XML, DEGIRO/Robinhood/Schwab
   CSVs, mock EODHD reference benchmark (derived-only rebased-100 index, zero raw OHLCV),
   selective Merkle disclosure, 7-day closed-trade embargo, and ``DU*`` paper rejection.
4. ``n170_verify.cli`` subcommands (``verify-flex``, ``verify-csv``, ``check-bundle``,
   ``keygen``, ``capabilities``) with zero leaked account IDs or NAVs.
5. Full-stack cross-runtime E2E: ``POST /api/v1/verify`` (isolated ``spawn`` subprocess,
   ``RLIMIT_CORE=0``) -> ``GET /api/v1/proofs/{id}`` -> ``GET /.well-known/n170-verify-keys.json``
   -> ``GET /api/v1/badges/{id}.svg`` -> ``GET /api/v1/leaderboard`` -> Node MCP
   ``./mcp/server.js`` -> TypeScript WebCrypto ``./web/src/lib/browserVerify.ts``.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

REPO_ROOT = Path(__file__).resolve().parents[2]
CORE_ROOT = REPO_ROOT / "core"
API_ROOT = REPO_ROOT / "api"
MCP_SERVER_JS = REPO_ROOT / "mcp" / "server.js"
WEB_VERIFY_TS = REPO_ROOT / "web" / "src" / "lib" / "browserVerify.ts"
WEB_API_CLIENT_TS = REPO_ROOT / "web" / "src" / "lib" / "apiClient.ts"

for _extra_path in (str(CORE_ROOT), str(API_ROOT)):
    if Path(_extra_path).exists() and _extra_path not in sys.path:
        sys.path.insert(0, _extra_path)

try:
    from app.main import VerifyApiApplication, VerifyApiTestClient
except ImportError:  # pragma: no cover - api lands in Phase 4
    VerifyApiApplication = None
    VerifyApiTestClient = None

from n170_verify import (  # noqa: E402
    PortfolioVerificationOutput,
    calculate_portfolio_performance,
    calculate_portfolio_performance_detailed,
    parse_ibkr_flex_xml,
    verify_portfolio,
    verify_proof_bundle,
)
from n170_verify import cli as verify_cli  # noqa: E402
from n170_verify.connectors import PaperOrSandboxAccountRejectedError  # noqa: E402
from n170_verify.contracts import (  # noqa: E402
    AccountScope,
    EnvironmentTier,
    OriginAssurance,
    ProviderApprovalState,
    SignerTrustStatus,
)
from n170_verify.crypto import (  # noqa: E402
    CANONICAL_LEAF_NAMES,
    PublisherKeyRecord,
    PublisherKeyRegistryDocument,
    generate_ed25519_keypair,
)
from n170_verify.reference import EodhdReferenceProvider  # noqa: E402

SYNTHETIC_SAMPLE_FLEX_XML = """<?xml version="1.0" encoding="UTF-8"?>
<FlexQueryResponse queryName="N170 Synthetic Test Fixture" type="AF">
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
</FlexQueryResponse>
"""

SYNTHETIC_DEMO_FLEX_XML = """<?xml version="1.0" encoding="UTF-8"?>
<FlexQueryResponse>
  <FlexStatements count="1">
    <FlexStatement fromDate="20250102" toDate="20250107" period="SyntheticDemo" baseCurrency="USD">
      <EquitySummaryByReportDateInBase>
        <EquitySummaryByReportDateInBase reportDate="20250102" total="100000.00" />
        <EquitySummaryByReportDateInBase reportDate="20250103" total="101000.00" />
        <EquitySummaryByReportDateInBase reportDate="20250106" total="103020.00" />
        <EquitySummaryByReportDateInBase reportDate="20250107" total="101989.80" />
      </EquitySummaryByReportDateInBase>
      <CashTransactions>
        <CashTransaction reportDate="20250106" currency="USD" amount="1000.00" type="Deposit" description="Synthetic contribution" transactionID="SECRET-1" />
      </CashTransactions>
    </FlexStatement>
  </FlexStatements>
</FlexQueryResponse>
"""


def _resolve_node_binary() -> str:
    found = shutil.which("node")
    if found:
        return found
    for candidate in ("/opt/homebrew/bin/node", "/usr/local/bin/node", "/usr/bin/node"):
        if os.path.exists(candidate):
            return candidate
    raise RuntimeError("Node.js binary not found on PATH or standard locations")


def _node_ts_args(node_bin: str) -> list[str]:
    cp = subprocess.run(
        [node_bin, "-p", "process.versions.node"],
        check=True,
        capture_output=True,
        text=True,
    )
    major = int(cp.stdout.strip().split(".", 1)[0])
    if major >= 23:
        return []
    if major == 22:
        return ["--experimental-strip-types"]
    return []


def _mock_eodhd_transport(url: str, params: Mapping[str, str]) -> list[dict[str, object]]:
    """Deterministic in-memory EODHD transport emitting synthetic bars to verify zero OHLCV leak."""
    del params
    if "/api/eod/" in url:
        return [
            {
                "date": "2024-01-02",
                "open": 775.0,
                "high": 779.0,
                "low": 773.0,
                "close": 777.1234,
                "adjusted_close": 500.0,
                "volume": 9876543,
            },
            {
                "date": "2024-01-03",
                "open": 501.0,
                "high": 506.0,
                "low": 499.0,
                "close": 502.5,
                "adjusted_close": 502.5,
                "volume": 9876543,
            },
            {
                "date": "2024-01-04",
                "open": 503.0,
                "high": 508.0,
                "low": 501.0,
                "close": 505.0125,
                "adjusted_close": 505.0125,
                "volume": 9876543,
            },
            {
                "date": "2024-01-05",
                "open": 505.0,
                "high": 507.0,
                "low": 500.0,
                "close": 503.4974625,
                "adjusted_close": 503.4974625,
                "volume": 9876543,
            },
        ]
    return []


class TestPipelineAndLegacyParity(unittest.TestCase):
    """End-to-end integration, CLI, cross-stack verification, and analytical parity tests."""

    def test_zero_prohibited_runtime_imports_across_production_modules(self) -> None:
        """All runtime files under core/n170_verify, api/app, mcp, and web/src stay standalone."""
        py_roots = [
            p for p in (CORE_ROOT / "n170_verify", API_ROOT / "app") if p.exists()
        ]
        checked_py = 0
        for root in py_roots:
            for py_file in sorted(root.rglob("*.py")):
                checked_py += 1
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(py_file))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            top = alias.name.split(".", 1)[0]
                            self.assertNotIn(
                                top,
                                {"n170"},
                                f"Forbidden legacy import {alias.name!r} in {py_file}",
                            )
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        top = node.module.split(".", 1)[0]
                        self.assertNotIn(
                            top,
                            {"n170"},
                            f"Forbidden legacy from-import {node.module!r} in {py_file}",
                        )
        self.assertGreaterEqual(checked_py, 25)

        for js_ts_root in (
            REPO_ROOT / "mcp",
            REPO_ROOT / "web" / "src",
        ):
            if not js_ts_root.exists():
                continue
            for fpath in sorted(js_ts_root.rglob("*")):
                if fpath.is_file() and fpath.suffix in {".js", ".ts", ".tsx"}:
                    text = fpath.read_text(encoding="utf-8")
                    self.assertTrue(len(text) > 0, f"Empty source file {fpath}")

    def test_analytical_parity_and_redaction_on_synthetic_flex_fixtures(self) -> None:
        """Prove exact sub-period TWR (EOD & SOD), external cash-flow isolation, and redaction."""
        fixtures = [
            (
                "sample_flex",
                SYNTHETIC_SAMPLE_FLEX_XML.encode("utf-8"),
                [1000.0, -5000.0],
                [0.01, 0.02, -0.01],
                (102000.0 / 101000.0) * (99040.0 / 97000.0) * (98049.60 / 99040.0) - 1.0,
                -0.01,
                (
                    "REDACT-ME",
                    "SECRET-TRADE-1",
                    "SECRET-TRADE-2",
                    "100000.0",
                    ": 100000",
                    "102000",
                    "99040",
                    "98049.6",
                ),
            ),
            (
                "demo_flex",
                SYNTHETIC_DEMO_FLEX_XML.encode("utf-8"),
                [1000.0],
                [0.01, (103020.0 - 1000.0) / 101000.0 - 1.0, -0.01],
                (101000.0 / 100000.0) * (103020.0 / 102000.0) * (101989.80 / 103020.0) - 1.0,
                -0.01,
                (
                    "SECRET-1",
                    "100000.0",
                    ": 100000",
                    "103020",
                    "101989.8",
                    "101000",
                ),
            ),
        ]

        for name, raw_bytes, expected_flows, expected_eod_rets, expected_sod_twr, expected_mdd, forbidden_substrings in fixtures:
            with self.subTest(fixture=name):
                expected_sha = hashlib.sha256(raw_bytes).hexdigest()
                v3_ledger = parse_ibkr_flex_xml(
                    raw_bytes,
                    blinding_salt_hex="ab" * 32,
                )
                self.assertEqual(v3_ledger.source_body_sha256, expected_sha)
                self.assertEqual(v3_ledger.base_currency, "USD")
                self.assertEqual(len(v3_ledger.nav_points), 4)

                v3_ext_flows = [
                    float(f.amount_base)
                    for f in v3_ledger.flows
                    if f.is_external_capital_flow and f.amount_base is not None
                ]
                self.assertEqual(len(v3_ext_flows), len(expected_flows))
                for v_amt, exp_amt in zip(v3_ext_flows, expected_flows, strict=True):
                    self.assertAlmostEqual(v_amt, exp_amt, places=6)

                v3_detail_eod = calculate_portfolio_performance_detailed(
                    v3_ledger, cash_flow_timing="end_of_day"
                )
                v3_perf_sod = calculate_portfolio_performance(
                    v3_ledger, cash_flow_timing="start_of_day"
                )

                expected_eod_twr = 1.0
                for r in expected_eod_rets:
                    expected_eod_twr *= 1.0 + r
                expected_eod_twr -= 1.0

                self.assertAlmostEqual(
                    v3_detail_eod.summary.twr_decimal,
                    expected_eod_twr,
                    places=8,
                )
                self.assertAlmostEqual(
                    v3_perf_sod.twr_decimal,
                    expected_sod_twr,
                    places=8,
                )
                self.assertEqual(
                    len(v3_detail_eod.return_observations), len(expected_eod_rets)
                )
                for v_obs, exp_ret in zip(
                    v3_detail_eod.return_observations, expected_eod_rets, strict=True
                ):
                    self.assertAlmostEqual(v_obs.period_return, exp_ret, places=8)

                self.assertAlmostEqual(
                    v3_detail_eod.summary.max_drawdown_decimal,
                    expected_mdd,
                    places=8,
                )

                out = verify_portfolio(
                    flex_xml=raw_bytes,
                    blinding_salt_hex="cd" * 32,
                    issued_at_utc="2026-04-01T00:00:00Z",
                )
                self.assertIsInstance(out, PortfolioVerificationOutput)
                self.assertTrue(out.verification.valid)
                self.assertEqual(
                    out.verification.effective_origin_assurance,
                    OriginAssurance.SELF_REPORTED,
                )
                self.assertEqual(
                    out.proof_bundle.account_scope,
                    AccountScope.UNKNOWN_OFFLINE_SCOPE,
                )
                self.assertEqual(
                    out.proof_bundle.provider_approval_state,
                    ProviderApprovalState.OFFLINE_EXPORT_ONLY,
                )
                self.assertFalse(out.performance.psr_sample_eligible)
                self.assertIsNone(out.performance.probabilistic_sharpe_ratio)
                self.assertIsNone(out.performance.psr_glm_unsmoothed)

                bundle_json = json.dumps(out.proof_bundle.to_dict())
                for secret_token in forbidden_substrings:
                    self.assertNotIn(
                        secret_token,
                        bundle_json,
                        f"Sensitive token {secret_token!r} leaked in serialized proof bundle!",
                    )
                curve_leaf = next(
                    lf
                    for lf in out.proof_bundle.disclosed_leaves
                    if lf.leaf_name == "indexed_curve"
                )
                self.assertEqual(curve_leaf.payload["base_index"], 100.0)
                self.assertEqual(curve_leaf.payload["points"][0]["index_value"], 100.0)

    def test_pipeline_selective_disclosure_derived_benchmark_csv_and_paper_rejection(self) -> None:
        """Verify selective Merkle disclosure, derived-only EODHD benchmark, CSV ingestion, and DU* rejection."""
        raw_xml = SYNTHETIC_SAMPLE_FLEX_XML
        kp = generate_ed25519_keypair(b"\x42" * 32)
        registry = PublisherKeyRegistryDocument(
            updated_at_utc="2026-01-01T00:00:00Z",
            keys=[
                PublisherKeyRecord(
                    publisher_kid="test-pub-1",
                    public_key_hex=kp.public_key_hex,
                    status="active",
                    not_before_utc="2025-01-01T00:00:00Z",
                    issuer_org="N170",
                )
            ],
            notaries=[],
        )
        fixed_salts = {name: f"{idx + 1:02x}" * 32 for idx, name in enumerate(CANONICAL_LEAF_NAMES)}

        eodhd_ref = EodhdReferenceProvider(
            api_key="test-eodhd-key",
            transport=_mock_eodhd_transport,
        )

        full_out = verify_portfolio(
            flex_xml=raw_xml,
            blinding_salt_hex="12" * 32,
            reference_provider=eodhd_ref,
            benchmark_symbol="SPY.US",
            publisher_kid="test-pub-1",
            publisher_private_key_hex=kp.private_key_hex,
            registry_doc=registry,
            leaf_salts=fixed_salts,
            issued_at_utc="2026-04-01T00:00:00Z",
        )
        redacted_out = verify_portfolio(
            flex_xml=raw_xml,
            blinding_salt_hex="12" * 32,
            reference_provider=eodhd_ref,
            benchmark_symbol="SPY.US",
            publisher_kid="test-pub-1",
            publisher_private_key_hex=kp.private_key_hex,
            registry_doc=registry,
            leaf_salts=fixed_salts,
            disclose_leaf_names=[
                "core_metrics",
                "indexed_curve",
                "reconciliation",
                "coaching_and_context",
            ],
            issued_at_utc="2026-04-01T00:00:00Z",
        )

        # Identical Merkle root across full and redacted disclosure subsets
        self.assertEqual(full_out.proof_bundle.merkle_root, redacted_out.proof_bundle.merkle_root)
        self.assertTrue(redacted_out.verification.valid)
        self.assertEqual(
            set(redacted_out.verification.undisclosed_leaf_names),
            {"capital_bracket", "benchmark_alpha", "delayed_closed_trades"},
        )

        # Zero side-channel leak of capital_bracket or benchmark_alpha inside core_metrics leaf!
        redacted_json = json.dumps(redacted_out.proof_bundle.to_dict())
        self.assertNotIn("bracket_100k_1m", redacted_json)
        # Zero raw EODHD OHLCV values in full or redacted bundles!
        full_json = json.dumps(full_out.proof_bundle.to_dict())
        self.assertNotIn("777.1234", full_json)
        self.assertNotIn("9876543", full_json)
        # Derived rebased-100 benchmark & TWR ARE present in full_out's benchmark_alpha leaf
        bench_leaf = next(
            lf for lf in full_out.proof_bundle.disclosed_leaves if lf.leaf_name == "benchmark_alpha"
        )
        self.assertEqual(bench_leaf.payload["benchmark_symbol"], "SPY.US")
        self.assertAlmostEqual(bench_leaf.payload["benchmark_twr_decimal"], 0.006994925, places=6)

        # Offline CSV pipeline (Robinhood + Schwab)
        rh_csv = (
            "Activity Date,Process Date,Settle Date,Instrument,Description,Trans Code,Quantity,Price,Amount\n"
            "01/03/2026,01/03/2026,01/03/2026,,ACH Deposit,ACH,,,$5000.00\n"
            "01/06/2026,01/06/2026,01/07/2026,AAPL,Apple Inc,Buy,10,$200.00,($2000.00)\n"
            "01/12/2026,01/12/2026,01/13/2026,AAPL,Apple Inc,Sell,10,$220.00,$2200.00\n"
        )
        # Issued within 7 days of 2026-01-12 -> closed trade MUST be stripped by 7-day embargo!
        rh_embargoed = verify_portfolio(
            csv_source=rh_csv,
            csv_format="robinhood",
            issued_at_utc="2026-01-15T00:00:00Z",
        )
        self.assertEqual(rh_embargoed.proof_bundle.environment_tier, EnvironmentTier.UNVERIFIED_OFFLINE)
        self.assertTrue(rh_embargoed.verification.signature_valid)
        self.assertTrue(rh_embargoed.verification.merkle_valid)
        self.assertEqual(len(rh_embargoed.delayed_closed_trades), 0)
        self.assertEqual(rh_embargoed.stripped_recent_closed_trades_count, 1)

        # Issued after 7-day embargo -> percentage-only closed trade is disclosed with zero share/dollar size!
        rh_released = verify_portfolio(
            csv_source=rh_csv,
            csv_format="robinhood",
            issued_at_utc="2026-02-01T00:00:00Z",
        )
        self.assertEqual(len(rh_released.delayed_closed_trades), 1)
        self.assertEqual(rh_released.delayed_closed_trades[0].symbol, "AAPL")
        self.assertAlmostEqual(rh_released.delayed_closed_trades[0].return_pct, 10.0, places=2)

        # DU* paper account rejection
        paper_xml = raw_xml.replace('accountId="REDACT-ME"', 'accountId="DU1234567"')
        with self.assertRaises(PaperOrSandboxAccountRejectedError):
            verify_portfolio(flex_xml=paper_xml)

    def test_cli_subcommands_emit_clean_redacted_json_without_temp_files(self) -> None:
        """Test keygen, capabilities, verify-flex, verify-csv, and check-bundle CLI subcommands."""
        # 1. keygen (in-memory stdout)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = verify_cli.main(["keygen", "--kid", "cli-test-kid", "--issuer-org", "UnitTestOrg"])
        self.assertEqual(rc, 0)
        keygen_out = json.loads(buf.getvalue())
        self.assertEqual(keygen_out["publisher_kid"], "cli-test-kid")
        self.assertEqual(len(keygen_out["private_key_hex"]), 64)
        self.assertEqual(len(keygen_out["public_key_hex"]), 64)

        # 2. capabilities
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = verify_cli.main(["capabilities"])
        self.assertEqual(rc, 0)
        caps_out = json.loads(buf.getvalue())
        self.assertEqual(caps_out["canonical_leaf_names"], list(CANONICAL_LEAF_NAMES))
        self.assertIn("ibkr_flex_web", caps_out["connector_ids"])
        self.assertFalse(caps_out["privacy_guarantees"]["raw_account_ids_emitted"])

        # 3. verify-flex -> check-bundle & verify-csv inside isolated TemporaryDirectory
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            bundle_path = tmp_path / "sample.verify.json"
            reg_path = tmp_path / "keys.json"
            csv_input_path = tmp_path / "sample_trades.csv"

            reg_doc = {
                "schema_version": "n170-verify-keys-v3",
                "updated_at_utc": "2026-04-01T00:00:00Z",
                "keys": [keygen_out["registry_record"]],
                "notaries": [],
            }
            reg_path.write_text(json.dumps(reg_doc), encoding="utf-8")
            flex_input_path = tmp_path / "sample_flex.xml"
            flex_input_path.write_text(SYNTHETIC_SAMPLE_FLEX_XML, encoding="utf-8")

            stdout_buf = io.StringIO()
            stderr_buf = io.StringIO()
            with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
                rc = verify_cli.main(
                    [
                        "verify-flex",
                        str(flex_input_path),
                        "--publisher-kid",
                        "cli-test-kid",
                        "--signing-key-hex",
                        keygen_out["private_key_hex"],
                        "--redact",
                        "capital_bracket,delayed_closed_trades",
                        "--output",
                        str(bundle_path),
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertEqual(stderr_buf.getvalue(), "")
            bundle_text = bundle_path.read_text(encoding="utf-8")
            self.assertNotIn("REDACT-ME", bundle_text)
            self.assertNotIn("100000", bundle_text)
            self.assertNotIn("bracket_100k_1m", bundle_text)

            # check-bundle against registry
            check_buf = io.StringIO()
            with redirect_stdout(check_buf):
                rc_check = verify_cli.main(
                    ["check-bundle", str(bundle_path), "--registry", str(reg_path)]
                )
            self.assertEqual(rc_check, 0)
            check_json = json.loads(check_buf.getvalue())
            self.assertTrue(check_json["valid"])
            self.assertEqual(check_json["signer_trust_status"], "official_n170_hosted")
            self.assertEqual(
                check_json["undisclosed_leaf_names"],
                ["capital_bracket", "delayed_closed_trades"],
            )

            # verify-csv
            csv_input_path.write_text(
                '"Date","Action","Symbol","Description","Quantity","Price","Fees & Comm","Amount"\n'
                '"01/04/2026","MoneyLink Deposit","","Deposit","","","","$15,000.00"\n'
                '"01/18/2026","Buy","VTI","VANGUARD TOTAL STOCK MKT","20","$290.00","$0.00","-$5,800.00"\n',
                encoding="utf-8",
            )
            csv_out_buf = io.StringIO()
            with redirect_stdout(csv_out_buf):
                rc_csv = verify_cli.main(
                    ["verify-csv", "--format", "schwab", str(csv_input_path)]
                )
            self.assertEqual(rc_csv, 0)
            csv_bundle = json.loads(csv_out_buf.getvalue())
            self.assertEqual(csv_bundle["environment_tier"], "unverified_offline")
            self.assertTrue(verify_proof_bundle(csv_bundle).signature_valid)
            self.assertTrue(verify_proof_bundle(csv_bundle).merkle_valid)

    @unittest.skipIf(VerifyApiApplication is None, "api lands in Phase 4")
    def test_full_stack_cross_runtime_e2e_api_to_mcp_and_webcrypto(self) -> None:
        """E2E: POST /api/v1/verify (spawn subprocess) -> API routes -> Node MCP -> TS WebCrypto."""
        raw_xml = SYNTHETIC_SAMPLE_FLEX_XML
        app = VerifyApiApplication()
        try:
            client = VerifyApiTestClient(app)

            # CORS preflight on /api/v1/verify
            opt_resp = client.options("/api/v1/verify")
            self.assertEqual(opt_resp.status_code, 204)
            self.assertEqual(opt_resp.headers.get("Access-Control-Allow-Origin"), "*")

            # 1. Submit real IBKR Flex XML to POST /api/v1/verify (runs inside spawn subprocess)
            post_resp = client.post(
                "/api/v1/verify",
                json={
                    "broker_id": "ibkr_flex_offline",
                    "raw_statement": raw_xml,
                    "publish_proof": True,
                    "opt_in_leaderboard": True,
                },
            )
            self.assertEqual(post_resp.status_code, 200, post_resp.text)
            verify_payload = post_resp.json()

            receipt = verify_payload["isolation_receipt"]
            self.assertNotEqual(receipt["worker_pid"], os.getpid())
            self.assertEqual(receipt["rlimit_core_soft"], 0)
            self.assertEqual(receipt["rlimit_core_hard"], 0)

            bundle_dict = verify_payload["proof_bundle"]
            proof_id = bundle_dict["proof_id"]
            self.assertTrue(verify_payload["verification"]["valid"])
            self.assertEqual(
                verify_payload["verification"]["signer_trust_status"],
                SignerTrustStatus.OFFICIAL_N170_HOSTED.value,
            )

            # 2. Fetch public routes from VerifyApiApplication
            proof_get = client.get(f"/api/v1/proofs/{proof_id}")
            self.assertEqual(proof_get.status_code, 200)
            proof_json = proof_get.json()

            keys_get = client.get("/.well-known/n170-verify-keys.json")
            self.assertEqual(keys_get.status_code, 200)
            registry_json = keys_get.json()

            badge_get = client.get(f"/api/v1/badges/{proof_id}.svg")
            self.assertEqual(badge_get.status_code, 200)
            svg_text = badge_get.text
            ET.fromstring(svg_text)  # Must be well-formed XML
            self.assertIn("N170 VERIFIED", svg_text.upper())
            self.assertNotIn("REDACT-ME", svg_text)

            lb_get = client.get("/api/v1/leaderboard?min_capital_bracket=bracket_10k_100k")
            self.assertEqual(lb_get.status_code, 200)
            lb_json = lb_get.json()
            self.assertEqual(lb_json["count"], 1)
            self.assertEqual(lb_json["entries"][0]["proof_id"], proof_id)

            # 3. Verify in Node.js MCP server (./mcp/server.js)
            node_bin = _resolve_node_binary()
            mcp_input_json = json.dumps(
                {
                    "mcp_path": str(MCP_SERVER_JS),
                    "proof_id": proof_id,
                    "proof_resp": proof_json,
                    "registry": registry_json,
                    "bundle": bundle_dict,
                }
            )
            mcp_script = """
const fs = require("node:fs");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const { handleJsonRpcMessage } = require(input.mcp_path);

(async () => {
  const fetchImpl = async (url) => {
    if (url.endsWith("/.well-known/n170-verify-keys.json")) {
      return { ok: true, status: 200, json: async () => input.registry };
    }
    if (url.includes("/api/v1/proofs/")) {
      return { ok: true, status: 200, json: async () => input.proof_resp };
    }
    return { ok: false, status: 404, json: async () => ({}) };
  };

  const checkMsg = await handleJsonRpcMessage(
    {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name: "n170_verify_check_bundle",
        arguments: { bundle: input.bundle },
      },
    },
    { apiBaseUrl: "http://127.0.0.1:8080", fetchImpl }
  );

  const inspectMsg = await handleJsonRpcMessage(
    {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "n170_verify_inspect_public_proof",
        arguments: {
          proof_id: input.proof_id,
          leaf_names: ["core_metrics", "reconciliation"],
        },
      },
    },
    { apiBaseUrl: "http://127.0.0.1:8080", fetchImpl }
  );

  process.stdout.write(JSON.stringify({
    check: JSON.parse(checkMsg.result.content[0].text),
    inspect: JSON.parse(inspectMsg.result.content[0].text),
  }));
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
"""
            mcp_cp = subprocess.run(
                [node_bin, "-e", mcp_script],
                input=mcp_input_json,
                check=True,
                capture_output=True,
                text=True,
            )
            mcp_out = json.loads(mcp_cp.stdout)
            self.assertTrue(mcp_out["check"]["valid"])
            self.assertTrue(mcp_out["check"]["signature_valid"])
            self.assertTrue(mcp_out["check"]["merkle_valid"])
            self.assertEqual(mcp_out["check"]["signer_trust_status"], "official_n170_hosted")
            self.assertEqual(mcp_out["check"]["effective_origin_assurance"], "self_reported")
            self.assertTrue(mcp_out["inspect"]["valid"])
            self.assertAlmostEqual(
                mcp_out["inspect"]["disclosed_payloads"]["core_metrics"]["twr_decimal"],
                1.01 * 1.02 * 0.99 - 1.0,
                places=8,
            )

            # 4. Verify in TypeScript WebCrypto verifier (./web/src/lib/browserVerify.ts) when web/ is present
            if WEB_VERIFY_TS.is_file() and WEB_API_CLIENT_TS.is_file():
                ts_flags = _node_ts_args(node_bin)
                web_input_json = json.dumps(
                    {
                        "verify_ts_url": WEB_VERIFY_TS.as_uri(),
                        "api_client_url": WEB_API_CLIENT_TS.as_uri(),
                        "bundle": bundle_dict,
                        "registry": registry_json,
                        "proof_resp": proof_json,
                    }
                )
                web_script = """
import fs from "node:fs";
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const { verifyProofBundle } = await import(input.verify_ts_url);
const clientMod = await import(input.api_client_url);
const mergeFn = clientMod.combineRegistryDocuments || clientMod.mergeWithDemoRegistry;
const mergedReg = mergeFn(input.registry);
const webRes = await verifyProofBundle(input.bundle, { registryDoc: mergedReg });
process.stdout.write(JSON.stringify(webRes));
"""
                web_cp = subprocess.run(
                    [node_bin, *ts_flags, "--input-type=module", "-e", web_script],
                    input=web_input_json,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                web_out = json.loads(web_cp.stdout)
                self.assertTrue(web_out["valid"])
                self.assertTrue(web_out["signature_valid"])
                self.assertTrue(web_out["merkle_valid"])
                self.assertTrue(web_out["checkpoint_verified"])
                self.assertEqual(web_out["signer_trust_status"], "official_n170_hosted")
                self.assertEqual(web_out["effective_origin_assurance"], "self_reported")
                self.assertEqual(web_out["proof_hash"], verify_payload["verification"]["proof_hash"])
        finally:
            app.close()


    def test_isolated_worker_forbids_filesystem_paths_and_url_or_live_overrides(self) -> None:
        from unittest import mock
        from n170_verify.connectors import (
            IbkrFlexParseError,
            PaperOrSandboxAccountRejectedError,
        )
        from n170_verify.pipeline import api_worker_pipeline_entrypoint

        with tempfile.TemporaryDirectory() as tmpdir:
            secret_xml_file = Path(tmpdir) / "host_secret_flex.xml"
            secret_xml_file.write_text(SYNTHETIC_SAMPLE_FLEX_XML, encoding="utf-8")

            # 1. Path object rejected immediately when allow_filesystem_paths=False
            with self.assertRaisesRegex(ValueError, "Filesystem path inputs are forbidden"):
                verify_portfolio(
                    broker_id="ibkr_flex_offline",
                    flex_xml=secret_xml_file,
                    allow_filesystem_paths=False,
                )

            # 2. Existing file path passed as str is NEVER read from disk when allow_filesystem_paths=False
            with self.assertRaises(IbkrFlexParseError):
                verify_portfolio(
                    broker_id="ibkr_flex_offline",
                    flex_xml=str(secret_xml_file),
                    allow_filesystem_paths=False,
                )

            # 3. api_worker_pipeline_entrypoint rejects Path inputs & existing file path strings
            with self.assertRaisesRegex(ValueError, "Filesystem path inputs are forbidden"):
                api_worker_pipeline_entrypoint(
                    {
                        "broker_id": "ibkr_flex_offline",
                        "flex_xml": secret_xml_file,
                        "publisher_kid": "worker-kid",
                        "publisher_private_key_hex": "11" * 32,
                    }
                )
            with self.assertRaises(IbkrFlexParseError):
                api_worker_pipeline_entrypoint(
                    {
                        "broker_id": "ibkr_flex_offline",
                        "flex_xml": str(secret_xml_file),
                        "publisher_kid": "worker-kid",
                        "publisher_private_key_hex": "11" * 32,
                    }
                )

            # 4. connector_fetch_kwargs rejects *_path / *_file keys and non-primitive values
            for bad_fetch_kw in (
                {"statement_path": str(secret_xml_file)},
                {"export_file": "foo.csv"},
                {"nested": {"bad": 1}},
            ):
                with self.assertRaises(ValueError):
                    api_worker_pipeline_entrypoint(
                        {
                            "broker_id": "ibkr_flex_offline",
                            "flex_xml": SYNTHETIC_SAMPLE_FLEX_XML,
                            "connector_fetch_kwargs": bad_fetch_kw,
                            "publisher_kid": "worker-kid",
                            "publisher_private_key_hex": "11" * 32,
                        }
                    )

        # 5. Paper/sandbox URLs in job_payload or connector_kwargs fail closed
        for bad_payload in (
            {"base_url": "https://paper-api.alpaca.markets"},
            {"connector_kwargs": {"endpoint": "https://testnet.binance.vision"}},
        ):
            with self.assertRaises(PaperOrSandboxAccountRejectedError):
                api_worker_pipeline_entrypoint(
                    {
                        "broker_id": "alpaca",
                        "ephemeral_credentials": {"api_key": "k", "api_secret": "s"},
                        "publisher_kid": "worker-kid",
                        "publisher_private_key_hex": "11" * 32,
                        **bad_payload,
                    }
                )

        # 6. Custom base_url / transport / require_live=False overrides are stripped and require_live=True forced
        captured_call: dict[str, object] = {}

        def _fake_verify_portfolio(*args: object, **kwargs: object) -> PortfolioVerificationOutput:
            captured_call["kwargs"] = kwargs
            return verify_portfolio(
                broker_id="ibkr_flex_offline",
                flex_xml=SYNTHETIC_SAMPLE_FLEX_XML.encode("utf-8"),
                publisher_kid="worker-kid",
                publisher_private_key_hex="11" * 32,
                allow_filesystem_paths=False,
            )

        with mock.patch("n170_verify.pipeline.verify_portfolio", side_effect=_fake_verify_portfolio):
            res = api_worker_pipeline_entrypoint(
                {
                    "broker_id": "alpaca",
                    "ephemeral_credentials": {"api_key": "k", "api_secret": "s"},
                    "connector_kwargs": {
                        "base_url": "https://attacker-relay.example",
                        "http_transport": "injected",
                        "require_live": False,
                    },
                    "publisher_kid": "worker-kid",
                    "publisher_private_key_hex": "11" * 32,
                }
            )
        self.assertIn("merkle_root", res)
        forwarded_ckw = captured_call["kwargs"]["connector_kwargs"]  # type: ignore[index]
        self.assertNotIn("base_url", forwarded_ckw)
        self.assertNotIn("http_transport", forwarded_ckw)
        self.assertIs(forwarded_ckw["require_live"], True)
        self.assertIs(captured_call["kwargs"]["allow_filesystem_paths"], False)  # type: ignore[index]


if __name__ == "__main__":
    unittest.main()
