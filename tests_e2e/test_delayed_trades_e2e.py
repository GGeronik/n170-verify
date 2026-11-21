"""End-to-end regression test: verify_portfolio() -> POST /api/v1/proofs -> GET /api/v1/proofs/{id} preserves delayed_closed_trades."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

_BOOT_ROOT = Path(__file__).resolve().parents[1]
for _p in (str(_BOOT_ROOT), str(_BOOT_ROOT / "core"), str(_BOOT_ROOT / "api")):
    if Path(_p).exists() and _p not in sys.path:
        sys.path.insert(0, _p)

from app.config import ApiConfig
from app.main import VerifyApiTestClient, create_app
from n170_verify.contracts import (
    AccountScope,
    AssetClass,
    CanonicalPortfolioLedger,
    EnvironmentTier,
    NormalizedNavPoint,
    NormalizedTrade,
    OriginAssurance,
    ProviderApprovalState,
    VerifyProofBundle,
    compute_blinded_account_tag,
)
from n170_verify.crypto import generate_ed25519_keypair
from n170_verify.pipeline import verify_portfolio


_ALL_SECTIONS = [
    "EquitySummaryByReportDateInBase",
    "Trades",
    "OpenPositions",
    "PriorPeriodPositions",
    "CashTransactions",
    "Transfers",
    "CorporateActions",
    "OptionEAE",
]


class TestDelayedClosedTradesE2E(unittest.TestCase):
    def test_verify_portfolio_delayed_closed_trades_survives_publish_and_fetch(self) -> None:
        publisher = generate_ed25519_keypair(bytes.fromhex("33" * 32))
        salt_hex = "77" * 32
        raw_account_id = "U9876543"
        tag = compute_blinded_account_tag("ibkr", raw_account_id, salt_hex)

        ledger = CanonicalPortfolioLedger(
            blinded_account_tag=tag,
            broker_id="ibkr",
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            source_body_sha256="ab" * 32,
            base_currency="USD",
            period_start_utc="2026-01-02T20:00:00Z",
            period_end_utc="2026-02-20T20:00:00Z",
            enabled_sections=list(_ALL_SECTIONS),
            nav_points=[
                NormalizedNavPoint(timestamp_utc="2026-01-02T20:00:00Z", nav_base=50_000.0, cash_base=50_000.0, positions_base=0.0),
                NormalizedNavPoint(timestamp_utc="2026-01-16T20:00:00Z", nav_base=51_800.0, cash_base=51_800.0, positions_base=0.0),
                NormalizedNavPoint(timestamp_utc="2026-02-06T20:00:00Z", nav_base=53_200.0, cash_base=53_200.0, positions_base=0.0),
                NormalizedNavPoint(timestamp_utc="2026-02-20T20:00:00Z", nav_base=53_600.0, cash_base=53_600.0, positions_base=0.0),
            ],
            trades=[
                # Round-trip 1 (NVDA): closed 37 days before issued_at -> MUST survive
                NormalizedTrade(
                    venue="NASDAQ",
                    native_entry_id="E2E-1",
                    symbol="NVDA",
                    asset_class=AssetClass.EQUITY,
                    side="buy",
                    quantity=100.0,
                    price=120.0,
                    timestamp_utc="2026-01-05T15:00:00Z",
                ),
                NormalizedTrade(
                    venue="NASDAQ",
                    native_entry_id="E2E-2",
                    symbol="NVDA",
                    asset_class=AssetClass.EQUITY,
                    side="sell",
                    quantity=100.0,
                    price=138.0,
                    timestamp_utc="2026-01-15T19:00:00Z",
                ),
                # Round-trip 2 (AAPL): closed 16 days before issued_at -> MUST survive
                NormalizedTrade(
                    venue="NASDAQ",
                    native_entry_id="E2E-3",
                    symbol="AAPL",
                    asset_class=AssetClass.EQUITY,
                    side="buy",
                    quantity=50.0,
                    price=200.0,
                    timestamp_utc="2026-01-20T15:00:00Z",
                ),
                NormalizedTrade(
                    venue="NASDAQ",
                    native_entry_id="E2E-4",
                    symbol="AAPL",
                    asset_class=AssetClass.EQUITY,
                    side="sell",
                    quantity=50.0,
                    price=228.0,
                    timestamp_utc="2026-02-05T19:00:00Z",
                ),
                # Round-trip 3 (MSFT): closed 2 days before issued_at -> MUST be embargo-stripped by pipeline
                NormalizedTrade(
                    venue="NASDAQ",
                    native_entry_id="E2E-5",
                    symbol="MSFT",
                    asset_class=AssetClass.EQUITY,
                    side="buy",
                    quantity=20.0,
                    price=400.0,
                    timestamp_utc="2026-02-16T15:00:00Z",
                ),
                NormalizedTrade(
                    venue="NASDAQ",
                    native_entry_id="E2E-6",
                    symbol="MSFT",
                    asset_class=AssetClass.EQUITY,
                    side="sell",
                    quantity=20.0,
                    price=420.0,
                    timestamp_utc="2026-02-19T19:00:00Z",
                ),
            ],
        )

        out = verify_portfolio(
            ledger=ledger,
            proof_id="prf-e2e-delayed-trades",
            issued_at_utc="2026-02-21T12:00:00Z",
            publisher_kid="n170-active-2026",
            publisher_private_key_hex=publisher.private_key_hex,
            embargo_days=7,
            disclose_leaf_names=[
                "core_metrics",
                "indexed_curve",
                "reconciliation",
                "coaching_and_context",
                "capital_bracket",
                "benchmark_alpha",
                "delayed_closed_trades",
            ],
        )
        self.assertTrue(out.verification.valid)
        self.assertEqual(out.stripped_recent_closed_trades_count, 1)
        pipeline_leaf = out.proof_bundle.get_disclosed_payload("delayed_closed_trades")
        self.assertIsInstance(pipeline_leaf, dict)
        self.assertEqual(pipeline_leaf["embargo_days"], 7)
        self.assertEqual(pipeline_leaf["stripped_recent_count"], 1)
        self.assertEqual({t["symbol"] for t in pipeline_leaf["trades"]}, {"NVDA", "AAPL"})

        # Publish via HTTP API (both stdlib VerifyApiApplication and FastAPI)
        for prefer_fastapi in (False, True):
            with self.subTest(prefer_fastapi=prefer_fastapi):
                cfg = ApiConfig(
                    publisher_keypair=publisher,
                    publisher_kid="n170-active-2026",
                    publisher_key_not_before_utc="2025-01-01T00:00:00Z",
                    hosted_multi_user_mode=True,
                    db_path=":memory:",
                    sync_db_path=":memory:",
                    vault_master_kek_hex="aa" * 32,
                    account_blinding_salt_hex=salt_hex,
                )
                client = VerifyApiTestClient(create_app(cfg, prefer_fastapi=prefer_fastapi))
                post_resp = client.post(
                    "/api/v1/proofs",
                    json={"proof_bundle": out.proof_bundle.to_dict()},
                )
                self.assertEqual(post_resp.status_code, 201, post_resp.text)

                get_resp = client.get(f"/api/v1/proofs/{out.proof_bundle.proof_id}")
                self.assertEqual(get_resp.status_code, 200, get_resp.text)
                body = get_resp.json()
                self.assertTrue(body["verification"]["valid"])
                self.assertTrue(body["verification"]["merkle_valid"])

                stored_bundle = VerifyProofBundle.from_dict(body["proof_bundle"])
                self.assertNotIn("delayed_closed_trades", stored_bundle.undisclosed_leaf_hashes)
                stored_leaf = stored_bundle.get_disclosed_payload("delayed_closed_trades")
                self.assertEqual(stored_leaf["embargo_days"], 7)
                self.assertEqual(stored_leaf["stripped_recent_count"], 1)
                disclosed_symbols = {t["symbol"] for t in stored_leaf["trades"]}
                self.assertEqual(disclosed_symbols, {"NVDA", "AAPL"})
                self.assertNotIn("MSFT", disclosed_symbols)
                self.assertNotIn(raw_account_id, get_resp.text)
                for tr in stored_leaf["trades"]:
                    for forbidden in ("quantity", "shares", "dollar", "usd", "nav", "notional", "cost_basis"):
                        self.assertNotIn(forbidden, tr)


if __name__ == "__main__":
    unittest.main()
