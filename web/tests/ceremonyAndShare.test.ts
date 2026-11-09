import assert from "node:assert/strict";
import test from "node:test";

import { renderInstitutionalBadgeSvg } from "../src/lib/badgeSvg.ts";
import { redactProofBundleLeaves, verifyProofBundle } from "../src/lib/browserVerify.ts";
import {
  computeMerkleTreeTopology,
  runCeremonyTelemetry,
} from "../src/lib/ceremonyTelemetry.ts";
import {
  BUNDLE_DISCREPANCY_XRAY,
  BUNDLE_INSTITUTIONAL_FUND,
  BUNDLE_INSTITUTIONAL_SEQ0,
  BUNDLE_INSTITUTIONAL_SEQ1,
  DEMO_CONTINUITY_LOG_LEAVES,
  DEMO_REGISTRY_DOCUMENT,
} from "../src/lib/demoFixtures.ts";
import { generateQrCode } from "../src/lib/qrSvg.ts";

test("runCeremonyTelemetry executes 5-step WebCrypto trace with 0 bytes sent to server", async () => {
  const report = await runCeremonyTelemetry(BUNDLE_INSTITUTIONAL_FUND, {
    registryDoc: DEMO_REGISTRY_DOCUMENT,
    chainHistory: [BUNDLE_INSTITUTIONAL_SEQ0, BUNDLE_INSTITUTIONAL_SEQ1],
    continuityLogLeaves: DEMO_CONTINUITY_LOG_LEAVES,
  });

  assert.equal(report.bytesSentToServer, 0);
  assert.equal(report.result.valid, true);
  assert.equal(report.steps.length, 5);
  assert.ok(report.totalComputeMs > 0);
  for (const step of report.steps) {
    assert.equal(step.status, "pass");
  }
});

test("computeMerkleTreeTopology reconstructs exact merkle_root before and after salted leaf redaction", async () => {
  const fullTopo = await computeMerkleTreeTopology(BUNDLE_INSTITUTIONAL_FUND);
  assert.equal(fullTopo.root, BUNDLE_INSTITUTIONAL_FUND.merkle_root);
  assert.equal(fullTopo.leaves.filter((l) => l.disclosed).length, 7);

  const redacted = redactProofBundleLeaves(BUNDLE_INSTITUTIONAL_FUND, [
    "capital_bracket",
    "delayed_closed_trades",
  ]);
  const redactedTopo = await computeMerkleTreeTopology(redacted);
  assert.equal(redactedTopo.root, BUNDLE_INSTITUTIONAL_FUND.merkle_root);
  assert.equal(redactedTopo.leaves.filter((l) => l.disclosed).length, 5);
});

test("generateQrCode produces deterministic ISO/IEC 18004 finder patterns and SVG path", () => {
  const qr = generateQrCode("https://verify.n170.io/p/prf-inst-alpha-012");
  assert.ok(qr.size >= 25);
  assert.ok(qr.svgPath.startsWith("M0,0h1v1h-1z"));
  // Top-left 7x7 finder outer corners & center must be dark
  assert.equal(qr.modules[0]![0], true);
  assert.equal(qr.modules[0]![6], true);
  assert.equal(qr.modules[6]![0], true);
  assert.equal(qr.modules[3]![3], true);
});

test("renderInstitutionalBadgeSvg renders verifier-computed origin in both Obsidian and Paper themes", async () => {
  const verified = await verifyProofBundle(BUNDLE_DISCREPANCY_XRAY, {
    registryDoc: DEMO_REGISTRY_DOCUMENT,
  });
  const obsidianSvg = renderInstitutionalBadgeSvg(
    BUNDLE_DISCREPANCY_XRAY,
    verified,
    "obsidian",
  );
  const paperSvg = renderInstitutionalBadgeSvg(
    BUNDLE_DISCREPANCY_XRAY,
    verified,
    "paper",
  );

  assert.ok(obsidianSvg.includes("#090A0D"));
  assert.ok(paperSvg.includes("#F7F6F2"));
  assert.ok(obsidianSvg.includes("OPERATOR-RETRIEVED"));
  assert.ok(obsidianSvg.includes("GATED (T=22&lt;30)"));
});
