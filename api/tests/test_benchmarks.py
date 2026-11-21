"""Unit and HTTP API tests for daily total-return ETF benchmark routes (SPY, QQQ, VWCE, VT, GLD)."""

from __future__ import annotations

from collections.abc import Mapping
import unittest
from typing import Any

from app.config import ApiConfig
from app.main import VerifyApiTestClient, create_app
from app.routes_benchmarks import clear_benchmark_cache
from n170_verify.crypto import generate_ed25519_keypair


class TestBenchmarkRoutes(unittest.TestCase):
    def setUp(self) -> None:
        clear_benchmark_cache()
        self.publisher = generate_ed25519_keypair(bytes.fromhex("41" * 32))
        self.config = ApiConfig(
            publisher_keypair=self.publisher,
            publisher_kid="n170-active-2026",
            publisher_key_not_before_utc="2025-01-01T00:00:00Z",
            hosted_multi_user_mode=True,
            db_path=":memory:",
            sync_db_path=":memory:",
            vault_master_kek_hex="aa" * 32,
            account_blinding_salt_hex="bb" * 32,
            eodhd_api_key="",
        )
        self.client = VerifyApiTestClient(create_app(self.config, prefer_fastapi=False))

    def test_catalog_lists_all_five_etfs_and_currencies(self) -> None:
        for prefer_fastapi in (False, True):
            with self.subTest(prefer_fastapi=prefer_fastapi):
                client = VerifyApiTestClient(create_app(self.config, prefer_fastapi=prefer_fastapi))
                resp = client.get("/api/v1/benchmarks")
                self.assertEqual(resp.status_code, 200, resp.text)
                body = resp.json()
                self.assertEqual(body["supported_currencies"], ["EUR", "EUR_HEDGED", "USD"])
                symbols = [b["symbol"] for b in body["benchmarks"]]
                self.assertEqual(symbols, ["SPY", "QQQ", "VWCE", "VT", "GLD"])
                vwce = next(b for b in body["benchmarks"] if b["symbol"] == "VWCE")
                self.assertEqual(vwce["native_currency"], "EUR")

    def test_multi_symbol_series_slices_and_rebases_to_100(self) -> None:
        resp = self.client.get(
            "/api/v1/benchmarks/series",
            params={
                "symbols": "SPY,QQQ,VWCE,VT,GLD",
                "currency": "USD",
                "start_date": "2024-09-01",
                "end_date": "2026-02-01",
            },
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertEqual(body["currency"], "USD")
        self.assertEqual(set(body["series"].keys()), {"SPY", "QQQ", "VWCE", "VT", "GLD"})

        for sym, item in body["series"].items():
            pts = item["points"]
            self.assertGreater(len(pts), 250, f"{sym} should have >250 trading days")
            self.assertAlmostEqual(pts[0]["index_value"], 100.0, places=6)
            dates = [p["date"] for p in pts]
            self.assertEqual(dates, sorted(dates))
            self.assertLessEqual(dates[-1], "2026-02-01")
            self.assertTrue(all(p["index_value"] > 0 for p in pts))

    def test_single_symbol_includes_top_level_convenience_fields(self) -> None:
        resp = self.client.get(
            "/api/v1/benchmarks/series",
            params={"symbol": "spy", "currency": "USD", "start_date": "2025-01-02", "end_date": "2025-06-30"},
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertEqual(body["symbol"], "SPY")
        self.assertEqual(body["native_currency"], "USD")
        self.assertEqual(body["points"], body["series"]["SPY"]["points"])
        self.assertAlmostEqual(body["points"][0]["index_value"], 100.0, places=6)

    def test_currency_awareness_usd_eur_and_eur_hedged(self) -> None:
        params_base = {"start_date": "2024-09-02", "end_date": "2025-12-31"}

        spy_usd = self.client.get("/api/v1/benchmarks/series", params={**params_base, "symbol": "SPY", "currency": "USD"}).json()
        spy_eur = self.client.get("/api/v1/benchmarks/series", params={**params_base, "symbol": "SPY", "currency": "EUR"}).json()
        spy_hedged = self.client.get("/api/v1/benchmarks/series", params={**params_base, "symbol": "SPY", "currency": "EUR_HEDGED"}).json()

        # EUR_HEDGED preserves local-currency total return; unhedged EUR reflects EUR/USD move
        self.assertEqual(spy_usd["points"], spy_hedged["points"])
        self.assertNotAlmostEqual(
            spy_usd["points"][-1]["index_value"],
            spy_eur["points"][-1]["index_value"],
            places=2,
        )

        # VWCE is native EUR: EUR_HEDGED == EUR, while USD converts via EUR/USD
        vwce_eur = self.client.get("/api/v1/benchmarks/series", params={**params_base, "symbol": "VWCE", "currency": "EUR"}).json()
        vwce_usd = self.client.get("/api/v1/benchmarks/series", params={**params_base, "symbol": "VWCE", "currency": "USD"}).json()
        vwce_hedged = self.client.get("/api/v1/benchmarks/series", params={**params_base, "symbol": "VWCE", "currency": "EUR_HEDGED"}).json()

        self.assertEqual(vwce_eur["points"], vwce_hedged["points"])
        self.assertNotAlmostEqual(
            vwce_eur["points"][-1]["index_value"],
            vwce_usd["points"][-1]["index_value"],
            places=2,
        )

    def test_live_eodhd_transport_computes_exact_total_return_and_fx_translation(self) -> None:
        def mock_eodhd(url: str, params: Mapping[str, str]) -> Any:
            if url.endswith("/api/eod/SPY.US"):
                return [
                    {"date": "2025-01-02", "open": 500.0, "high": 502.0, "low": 499.0, "close": 500.0, "adjusted_close": 500.0, "volume": 10_000_000},
                    {"date": "2025-01-03", "open": 510.0, "high": 512.0, "low": 508.0, "close": 505.0, "adjusted_close": 550.0, "volume": 10_000_000},
                ]
            if url.endswith("/api/eod/EURUSD.FOREX"):
                return [
                    {"date": "2025-01-02", "open": 1.00, "high": 1.01, "low": 0.99, "close": 1.00, "adjusted_close": 1.00},
                    {"date": "2025-01-03", "open": 1.10, "high": 1.11, "low": 1.09, "close": 1.10, "adjusted_close": 1.10},
                ]
            return []

        cfg = ApiConfig(
            publisher_keypair=self.publisher,
            publisher_kid="n170-active-2026",
            publisher_key_not_before_utc="2025-01-01T00:00:00Z",
            hosted_multi_user_mode=True,
            db_path=":memory:",
            sync_db_path=":memory:",
            vault_master_kek_hex="aa" * 32,
            account_blinding_salt_hex="bb" * 32,
            eodhd_api_key="UNIT_TEST_EODHD_KEY",
        )
        client = VerifyApiTestClient(
            create_app(cfg, eodhd_http_transport=mock_eodhd, prefer_fastapi=True)
        )

        # In USD: adjusted_close went 500 -> 550 (+10%) => index 100 -> 110
        resp_usd = client.get(
            "/api/v1/benchmarks/series",
            params={"symbol": "SPY", "currency": "USD", "start_date": "2025-01-02", "end_date": "2025-01-03"},
        )
        self.assertEqual(resp_usd.status_code, 200, resp_usd.text)
        body_usd = resp_usd.json()
        self.assertEqual(body_usd["source"], "eodhd_total_return")
        self.assertAlmostEqual(body_usd["points"][0]["index_value"], 100.0, places=6)
        self.assertAlmostEqual(body_usd["points"][1]["index_value"], 110.0, places=6)

        # In EUR: EUR strengthened 1.00 -> 1.10 (+10%), so SPY in EUR is 550/1.10 = 500 => flat 100.0!
        resp_eur = client.get(
            "/api/v1/benchmarks/series",
            params={"symbol": "SPY", "currency": "EUR", "start_date": "2025-01-02", "end_date": "2025-01-03"},
        )
        self.assertEqual(resp_eur.status_code, 200, resp_eur.text)
        body_eur = resp_eur.json()
        self.assertEqual(body_eur["source"], "eodhd_total_return")
        self.assertAlmostEqual(body_eur["points"][0]["index_value"], 100.0, places=6)
        self.assertAlmostEqual(body_eur["points"][1]["index_value"], 100.0, places=6)

    def test_eodhd_failure_gracefully_falls_back_to_bundled_reference(self) -> None:
        def failing_transport(url: str, params: Mapping[str, str]) -> Any:
            raise RuntimeError("upstream EODHD timeout")

        cfg = ApiConfig(
            publisher_keypair=self.publisher,
            publisher_kid="n170-active-2026",
            publisher_key_not_before_utc="2025-01-01T00:00:00Z",
            hosted_multi_user_mode=True,
            db_path=":memory:",
            sync_db_path=":memory:",
            vault_master_kek_hex="aa" * 32,
            account_blinding_salt_hex="bb" * 32,
            eodhd_api_key="UNIT_TEST_EODHD_KEY",
        )
        client = VerifyApiTestClient(
            create_app(cfg, eodhd_http_transport=failing_transport, prefer_fastapi=False)
        )
        resp = client.get(
            "/api/v1/benchmarks/series",
            params={"symbol": "QQQ", "currency": "USD", "start_date": "2025-01-02", "end_date": "2025-03-01"},
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        self.assertIn(body["source"], {"bundled_reference", "yahoo_total_return", "eodhd_total_return"})
        self.assertGreater(len(body["points"]), 20)

    def test_validation_and_method_restrictions(self) -> None:
        bad_sym = self.client.get("/api/v1/benchmarks/series", params={"symbol": "DOGECOIN"})
        self.assertEqual(bad_sym.status_code, 422)
        self.assertEqual(bad_sym.json()["error"], "unsupported_benchmark_symbol")

        bad_ccy = self.client.get("/api/v1/benchmarks/series", params={"symbol": "SPY", "currency": "CHF"})
        self.assertEqual(bad_ccy.status_code, 422)
        self.assertEqual(bad_ccy.json()["error"], "unsupported_currency")

        bad_date = self.client.get("/api/v1/benchmarks/series", params={"symbol": "SPY", "start_date": "2025/01/02"})
        self.assertEqual(bad_date.status_code, 422)

        inverted = self.client.get(
            "/api/v1/benchmarks/series",
            params={"symbol": "SPY", "start_date": "2025-06-01", "end_date": "2025-01-01"},
        )
        self.assertEqual(inverted.status_code, 422)

        empty_syms = self.client.get("/api/v1/benchmarks/series", params={"symbols": " , , "})
        self.assertEqual(empty_syms.status_code, 422)

        for prefer_fastapi in (False, True):
            with self.subTest(prefer_fastapi=prefer_fastapi):
                cl = VerifyApiTestClient(create_app(self.config, prefer_fastapi=prefer_fastapi))
                blank_syms = cl.get("/api/v1/benchmarks/series", params={"symbols": ""})
                self.assertEqual(blank_syms.status_code, 422, blank_syms.text)
                blank_sym = cl.get("/api/v1/benchmarks/series", params={"symbol": ""})
                self.assertEqual(blank_sym.status_code, 422, blank_sym.text)

        self.assertEqual(self.client.post("/api/v1/benchmarks", json={}).status_code, 405)
        self.assertEqual(self.client.post("/api/v1/benchmarks/series", json={}).status_code, 405)
        self.assertEqual(self.client.options("/api/v1/benchmarks/series").status_code, 204)

    def test_missing_fx_series_raises_instead_of_returning_unconverted_marks(self) -> None:
        from app.routes_benchmarks import _convert_series_currency

        with self.assertRaises(ValueError):
            _convert_series_currency(
                [("2025-01-02", 100.0), ("2025-01-03", 105.0)],
                native_currency="USD",
                target_currency="EUR",
                eurusd_by_date=[],
            )

    def test_per_ticker_cache_reuses_series_across_windows_and_never_inverts_eodhd_range(self) -> None:
        from app.routes_benchmarks import _LIVE_SERIES_CACHE, _fetch_eodhd_daily_marks

        eod_calls: list[tuple[str, dict[str, str]]] = []

        def mock_eodhd(url: str, params: Mapping[str, str]) -> Any:
            eod_calls.append((url, dict(params)))
            if url.endswith("/api/eod/SPY.US"):
                return [
                    {"date": "2024-01-02", "open": 470.0, "high": 471.0, "low": 469.0, "close": 470.0, "adjusted_close": 470.0},
                    {"date": "2025-01-02", "open": 580.0, "high": 581.0, "low": 579.0, "close": 580.0, "adjusted_close": 580.0},
                    {"date": "2025-06-30", "open": 620.0, "high": 621.0, "low": 619.0, "close": 620.0, "adjusted_close": 620.0},
                ]
            return []

        clear_benchmark_cache()
        marks1 = _fetch_eodhd_daily_marks(
            "SPY.US",
            api_key="UNIT_TEST_EODHD_KEY",
            start_date="2024-01-02",
            end_date="2025-06-30",
            transport=mock_eodhd,
            use_cache=True,
        )
        self.assertEqual(len(marks1), 3)
        calls_after_first = len(eod_calls)
        self.assertIn("SPY.US", _LIVE_SERIES_CACHE)

        # Sub-window hits cached ticker series with ZERO additional EODHD calls
        marks2 = _fetch_eodhd_daily_marks(
            "SPY.US",
            api_key="UNIT_TEST_EODHD_KEY",
            start_date="2025-01-02",
            end_date="2025-06-30",
            transport=mock_eodhd,
            use_cache=True,
        )
        self.assertEqual(marks2, marks1)
        self.assertEqual(len(eod_calls), calls_after_first)
        self.assertEqual(len(_LIVE_SERIES_CACHE), 1)

        # Requesting end_date prior to 2024-01-02 with no start_date never sends inverted from > to
        pre2024_calls: list[tuple[str, dict[str, str]]] = []

        def spy_pre2024(url: str, params: Mapping[str, str]) -> Any:
            pre2024_calls.append((url, dict(params)))
            if url.endswith("/api/eod/SPY.US"):
                return [
                    {"date": "2023-01-03", "open": 380.0, "high": 381.0, "low": 379.0, "close": 380.0, "adjusted_close": 380.0},
                    {"date": "2023-12-29", "open": 475.0, "high": 476.0, "low": 474.0, "close": 475.0, "adjusted_close": 475.0},
                ]
            return []

        cfg = ApiConfig(
            publisher_keypair=self.publisher,
            publisher_kid="n170-active-2026",
            publisher_key_not_before_utc="2025-01-01T00:00:00Z",
            hosted_multi_user_mode=True,
            db_path=":memory:",
            sync_db_path=":memory:",
            vault_master_kek_hex="aa" * 32,
            account_blinding_salt_hex="bb" * 32,
            eodhd_api_key="UNIT_TEST_EODHD_KEY",
        )
        c_eod = VerifyApiTestClient(create_app(cfg, eodhd_http_transport=spy_pre2024, prefer_fastapi=False))
        r_pre = c_eod.get("/api/v1/benchmarks/series", params={"symbol": "SPY", "end_date": "2023-12-31"})
        self.assertEqual(r_pre.status_code, 200, r_pre.text)
        eod_req = next(p for u, p in pre2024_calls if "/api/eod/" in u)
        self.assertLessEqual(eod_req["from"], eod_req["to"])

    def test_benchmark_comparison_math_and_proof_id_endpoint(self) -> None:
        from app.routes_benchmarks import compute_benchmark_comparison
        from n170_verify.contracts import (
            AccountScope,
            EnvironmentTier,
            OriginAssurance,
            ProviderApprovalState,
            create_signed_proof_bundle,
        )

        try:
            from tests.test_api_lifecycle_and_security import _build_leaf_payloads
        except ImportError:  # pragma: no cover
            from test_api_lifecycle_and_security import _build_leaf_payloads

        # Pure math check: benchmark moves +10%, -10%, +10%; trader has exact beta=1.0 + 1% per step alpha
        bench = [
            ("2025-01-01", 100.0),
            ("2025-05-01", 110.0),
            ("2025-09-01", 99.0),
            ("2026-01-01", 108.9),
        ]
        # Period returns for bench: +0.10, -0.10, +0.10
        # Period returns for trader: +0.11, -0.09, +0.11
        trader = [
            ("2025-01-01", 100.0),
            ("2025-05-01", 111.0),
            ("2025-09-01", 111.0 * 0.91),
            ("2026-01-01", 111.0 * 0.91 * 1.11),
        ]
        comp = compute_benchmark_comparison(trader, bench)
        self.assertIsNotNone(comp)
        assert comp is not None
        self.assertEqual(comp["aligned_observation_count"], 4)
        self.assertAlmostEqual(comp["beta"], 1.0, places=5)
        # 3 periods over 365 days -> obs_per_year ≈ 3.00205, mean alpha/period = +0.01 -> ~+0.03002
        self.assertAlmostEqual(comp["annualized_alpha_decimal"], 0.030021, places=4)
        self.assertAlmostEqual(comp["trader_max_drawdown_decimal"], -0.09, places=6)
        self.assertAlmostEqual(comp["benchmark_max_drawdown_decimal"], -0.10, places=6)
        self.assertAlmostEqual(comp["max_drawdown_delta_decimal"], 0.01, places=6)
        self.assertAlmostEqual(
            comp["cumulative_excess_return_decimal"],
            comp["trader_twr_decimal"] - comp["benchmark_twr_decimal"],
            places=7,
        )

        # End-to-end HTTP GET /api/v1/benchmarks/series?proof_id=...
        leaves = _build_leaf_payloads()
        leaves["indexed_curve"] = {
            "base_index": 100.0,
            "points": [
                {"timestamp_utc": "2025-01-02T20:00:00Z", "index_value": 100.0, "drawdown_pct": 0.0},
                {"timestamp_utc": "2025-03-03T20:00:00Z", "index_value": 106.5, "drawdown_pct": 0.0},
                {"timestamp_utc": "2025-04-08T20:00:00Z", "index_value": 98.0, "drawdown_pct": -7.9812},
                {"timestamp_utc": "2025-06-30T20:00:00Z", "index_value": 115.2, "drawdown_pct": 0.0},
            ],
        }
        bundle = create_signed_proof_bundle(
            proof_id="prf-bench-comp-1",
            issued_at_utc="2025-07-05T12:00:00Z",
            publisher_kid=self.config.publisher_kid,
            publisher_private_key_hex=self.publisher.private_key_hex,
            broker_id="ibkr_flex",
            blinded_account_tag="56" * 32,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            source_body_sha256="78" * 32,
            period_start_utc="2025-01-02T00:00:00Z",
            period_end_utc="2025-06-30T00:00:00Z",
            base_currency="EUR",
            leaf_payloads=leaves,
        )
        self.assertEqual(
            self.client.post("/api/v1/proofs", json={"proof_bundle": bundle.to_dict()}).status_code,
            201,
        )
        r_comp = self.client.get(
            "/api/v1/benchmarks/series",
            params={"symbol": "SPY", "proof_id": "prf-bench-comp-1"},
        )
        self.assertEqual(r_comp.status_code, 200, r_comp.text)
        body = r_comp.json()
        self.assertEqual(body["proof_id"], "prf-bench-comp-1")
        self.assertEqual(body["currency"], "EUR")  # defaulted from proof's base_currency
        self.assertEqual(body["currency_basis"], "fx_translated_eur")
        self.assertEqual(body["comparison"]["aligned_observation_count"], 4)
        self.assertAlmostEqual(body["comparison"]["trader_twr_decimal"], 0.152, places=6)
        self.assertEqual(
            [p["date"] for p in body["comparison"]["aligned_benchmark_points"]],
            ["2025-01-02", "2025-03-03", "2025-04-08", "2025-06-30"],
        )

        # Missing proof_id -> 404; redacted indexed_curve -> 422
        self.assertEqual(
            self.client.get("/api/v1/benchmarks/series", params={"symbol": "SPY", "proof_id": "prf-missing"}).status_code,
            404,
        )
        redacted = bundle.redact_leaves(["indexed_curve"])
        redacted_bundle = create_signed_proof_bundle(
            proof_id="prf-bench-redacted",
            issued_at_utc="2025-07-05T12:00:00Z",
            publisher_kid=self.config.publisher_kid,
            publisher_private_key_hex=self.publisher.private_key_hex,
            broker_id="ibkr_flex",
            blinded_account_tag="57" * 32,
            account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
            provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
            environment_tier=EnvironmentTier.LIVE_PRODUCTION,
            claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
            source_body_sha256="79" * 32,
            period_start_utc="2025-01-02T00:00:00Z",
            period_end_utc="2025-06-30T00:00:00Z",
            base_currency="USD",
            leaf_payloads=leaves,
            disclose_leaf_names=["core_metrics"],
        )
        self.assertEqual(
            self.client.post("/api/v1/proofs", json={"proof_bundle": redacted_bundle.to_dict()}).status_code,
            201,
        )
        r_red = self.client.get(
            "/api/v1/benchmarks/series",
            params={"symbol": "SPY", "proof_id": "prf-bench-redacted"},
        )
        self.assertEqual(r_red.status_code, 422)
        self.assertEqual(r_red.json()["error"], "indexed_curve_undisclosed")
        self.assertIsNotNone(redacted)


if __name__ == "__main__":
    unittest.main()
