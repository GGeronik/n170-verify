import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  sniffBrokerageStatement,
  SYNTHETIC_DROPZONE_SPECIMENS,
  IBKR_FLEX_60S_CHECKLIST,
} from "../src/lib/statementSniffer.ts";
import {
  getAllConnectorDescriptors,
  getConnectorDescriptor,
  resolveStatusPill,
  validateReadOnlyScopeString,
  validateScopePermissions,
} from "../src/lib/connectorStatus.ts";
import {
  verifyWithPyodideFailsafe,
  isPyodideFailsafeSupported,
} from "../src/lib/pyodideClient.ts";
import { verifyWheelIntegrity } from "../src/lib/pyodideFailsafeWorker.ts";
// @ts-expect-error script is untyped JS module
import { buildPyodideWheel } from "../scripts/build-pyodide-wheel.mjs";
import { verifyProofBundle } from "../src/lib/browserVerify.ts";
import {
  DEMO_REGISTRY_DOCUMENT,
  BUNDLE_COACHING_STUDIO,
} from "../src/lib/demoFixtures.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, "../..");

test("Statement Sniffer auto-detects all 8 brokerage and journal formats with 0 dropdowns", async () => {
  // 1. IBKR complete XML
  const ibkrRes = await sniffBrokerageStatement(SYNTHETIC_DROPZONE_SPECIMENS.ibkr_complete.content);
  assert.equal(ibkrRes.family, "ibkr_flex_xml");
  assert.equal(ibkrRes.paperAccountRejected, false);
  assert.equal(ibkrRes.previewReconciliation, "reconciled_within_tolerance");
  assert.equal(ibkrRes.missingSections.length, 0);

  // 1b. IBKR DU* paper account rejection
  const ibkrPaperRes = await sniffBrokerageStatement(
    `<FlexQueryResponse><FlexStatements><FlexStatement accountId="DU12345" /></FlexStatements></FlexQueryResponse>`
  );
  assert.equal(ibkrPaperRes.family, "ibkr_flex_xml");
  assert.equal(ibkrPaperRes.paperAccountRejected, true);

  // 2. DEGIRO NL / DE / EN
  const degiroRes = await sniffBrokerageStatement(SYNTHETIC_DROPZONE_SPECIMENS.degiro_nl.content);
  assert.equal(degiroRes.family, "degiro_csv");
  assert.equal(degiroRes.detectedLocale, "NL");
  assert.equal(degiroRes.apiCsvFormat, "degiro");

  // 3. MT4/MT5 report
  const mt5Res = await sniffBrokerageStatement(SYNTHETIC_DROPZONE_SPECIMENS.mt5_html.content);
  assert.equal(mt5Res.family, "mt4_mt5_report");
  assert.equal(mt5Res.paperAccountRejected, false);

  // 3b. MT4/MT5 Demo server rejection
  const mt5Demo = await sniffBrokerageStatement("<html>Server: MetaQuotes-Demo trade history</html>");
  assert.equal(mt5Demo.family, "mt4_mt5_report");
  assert.equal(mt5Demo.paperAccountRejected, true);

  // 4. Tradovate Futures
  const tradovateRes = await sniffBrokerageStatement(SYNTHETIC_DROPZONE_SPECIMENS.tradovate_futures.content);
  assert.equal(tradovateRes.family, "tradovate_csv");
  assert.equal(tradovateRes.paperAccountRejected, false);

  // 4b. Tradovate SIM rejection
  const tradovateSim = await sniffBrokerageStatement("symbol,_priceFormat\nESH6,-2,0.25,SIM12345");
  assert.equal(tradovateSim.family, "tradovate_csv");
  assert.equal(tradovateSim.paperAccountRejected, true);

  // 5. TraderSync / TradeZella 1-Click Migration
  const migRes = await sniffBrokerageStatement(SYNTHETIC_DROPZONE_SPECIMENS.tradezella_migration.content);
  assert.equal(migRes.family, "journal_migration_csv");
  assert.equal(migRes.migrationSource, "TradeZella");
  assert.ok(migRes.importedJournalTags.length > 0);
  assert.ok(migRes.importedJournalTags.includes("momentum_breakout"));

  // 6. Signed N170 proof bundle
  const bundleRes = await sniffBrokerageStatement(JSON.stringify(BUNDLE_COACHING_STUDIO));
  assert.equal(bundleRes.family, "n170_proof_bundle");
  assert.equal(bundleRes.missingSections.length, 0);
});

test("Connector Capabilities and Status pills conform to read-only constraints and zero Live pills", () => {
  const descriptors = getAllConnectorDescriptors();
  assert.ok(descriptors.length >= 15, "Descriptors should include all direct, exchange and offline adapters");

  const ibkr = getConnectorDescriptor("ibkr");
  assert.ok(ibkr, "IBKR descriptor must resolve");
  assert.equal(ibkr?.supports_subaccount_enumeration, true);

  const ctrader = getConnectorDescriptor("ctrader");
  assert.ok(ctrader, "cTrader descriptor must resolve");

  // Anti-slop: resolveStatusPill must never return 'Live'
  const pillApproved = resolveStatusPill("approved_live");
  assert.notEqual(pillApproved.label, "Live");
  assert.equal(pillApproved.variant, "emerald");

  const pillUserKey = resolveStatusPill("user_key_self_attested");
  assert.notEqual(pillUserKey.label, "Live");
  assert.equal(pillUserKey.variant, "champagne");

  // Scope validation tests
  const readOnlyScope = validateReadOnlyScopeString("ACCOUNTS read_profile");
  assert.equal(readOnlyScope.allowed, true);
  assert.equal(readOnlyScope.rejectedTokens.length, 0);

  const unsafeScope = validateReadOnlyScopeString("ACCOUNTS TRADING withdraw");
  assert.equal(unsafeScope.allowed, false);
  assert.ok(unsafeScope.rejectedTokens.includes("TRADING"));
  assert.ok(unsafeScope.rejectedTokens.includes("withdraw"));

  const scopePerms = validateScopePermissions("ctrader", ["Scope: ACCOUNTS", "Scope: TRADING"]);
  assert.equal(scopePerms.allowed, false);
  assert.ok(scopePerms.violations.length > 0);
});

test("Pyodide Wheel Builder produces valid wheel with pinned SHA-384 integrity and verification passes", () => {
  const manifest = buildPyodideWheel();
  assert.equal(manifest.wheel_name, "n170_verify-0.3.0-py3-none-any.whl");
  assert.ok(manifest.bytes > 50000, "Wheel should be at least 50KB");
  assert.equal(manifest.sha384.length, 96, "SHA-384 hex must be 96 characters");

  // Verify file on disk
  const wheelPath = path.join(REPO_ROOT, "web/public/pyodide", manifest.wheel_name);
  assert.ok(fs.existsSync(wheelPath), "Wheel must exist on disk");
  const bytes = fs.readFileSync(wheelPath);
  const actualHash = crypto.createHash("sha384").update(bytes).digest("hex");
  assert.equal(actualHash, manifest.sha384);
});

test("Wheel integrity verification checks SHA-384 and rejects tampered bytes", async () => {
  const sampleData = new TextEncoder().encode("print('n170 verify failsafe')");
  const validHash = crypto.createHash("sha384").update(sampleData).digest("hex");

  const validCheck = await verifyWheelIntegrity(sampleData, validHash);
  assert.equal(validCheck.valid, true);

  const tamperedData = new TextEncoder().encode("print('tampered payload')");
  const invalidCheck = await verifyWheelIntegrity(tamperedData, validHash);
  assert.equal(invalidCheck.valid, false);
});

test("Offline Pyodide Failsafe produces valid .verify.json with zero network requests", async () => {
  // Use IBKR complete specimen
  const specimen = SYNTHETIC_DROPZONE_SPECIMENS.ibkr_complete.content;
  const result = await verifyWithPyodideFailsafe({
    broker_id: "ibkr_flex_offline",
    raw_statement: specimen,
  });

  assert.ok(result.proof_bundle, "Failsafe must produce a proof bundle");
  assert.equal(result.isolation_receipt.mode, "pyodide_failsafe");
  assert.equal(result.isolation_receipt.zeroNetworkRequestsVerified, true);
  assert.equal(result.isolation_receipt.sha384IntegrityVerified, true);

  // Verify the bundle using browser WebCrypto verifier
  const verifyResult = await verifyProofBundle(result.proof_bundle, {
    registryDoc: DEMO_REGISTRY_DOCUMENT,
  });
  assert.equal(verifyResult.valid, true, "Issued failsafe bundle must be cryptographically valid");
});

test("Anti-slop compliance: 0 em dashes, 0 statusPill Live, 0 banned copy words", () => {
  const filesToCheck = [
    "web/src/lib/statementSniffer.ts",
    "web/src/lib/connectorStatus.ts",
    "web/src/components/ConnectIsolationReceipt.tsx",
    "web/src/app/connect/page.tsx",
  ];

  const banned = [
    "fund", "hedge fund", "LP", "allocate", "capacity", "bare verified",
    "audited", "trustless", "tamper-proof", "zero-knowledge", "air-gapped",
    "timestamped", "guaranteed", "100% private", "proves skill", "fraud",
    "forensic", "caught", "insider", "D" + "SR", "streak", "connect any broker",
    "works with IBKR", "12 brokers"
  ];

  for (const relPath of filesToCheck) {
    const fullPath = path.join(REPO_ROOT, relPath);
    if (!fs.existsSync(fullPath)) continue;
    const content = fs.readFileSync(fullPath, "utf-8");

    // 1. Zero em dashes
    const dashMatches = content.match(/[—–]/g);
    assert.equal(
      dashMatches,
      null,
      `File ${relPath} contains em dashes: ${dashMatches?.length}`
    );

    // 2. Zero statusPill: "Live"
    const liveMatches = content.match(/statusPill:\s*"Live"/g);
    assert.equal(
      liveMatches,
      null,
      `File ${relPath} contains statusPill: "Live"`
    );

    // 3. Zero banned words in rendered copy
    for (const b of banned) {
      const regex = new RegExp(`\\b${b}\\b`, "i");
      assert.equal(
        regex.test(content),
        false,
        `File ${relPath} contains banned copy word: "${b}"`
      );
    }
  }
});
