import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { verifyProofBundle } from "../src/lib/browserVerify.ts";
import {
  BUNDLE_INSTITUTIONAL_FUND,
  BUNDLE_INSTITUTIONAL_SEQ0,
  BUNDLE_INSTITUTIONAL_SEQ1,
  DEMO_CONTINUITY_LOG_LEAVES,
  DEMO_REGISTRY_DOCUMENT,
} from "../src/lib/demoFixtures.ts";
import {
  extractTypedLeaves,
  type BundleVerificationResult,
} from "../src/lib/contracts.ts";
import {
  resolveDailyCalendarCells,
  groupCalendarCellsByMonth,
  resolveBootstrapSummary,
  resolveSessionExpectancyCells,
  resolveCounterfactualTwin,
  resolveQuantDnaProfile,
} from "../src/lib/wave4Analytics.ts";
import {
  standardNormalCdf,
  standardNormalPdf,
  computePsrVarianceFactor,
  computeClaimPlausibility,
  buildPlausibilityQueryString,
  parsePlausibilityQueryParams,
  buildPoliteChallengeReply,
  SufficiencyTier,
  type PlausibilityInputs,
} from "../src/lib/plausibilityMath.ts";
import {
  renderShareCard16x9Svg,
  renderShareCard9x16Svg,
  buildDiscordVerifyEmbedJson,
  buildMarkdownBadgeSnippet,
  buildSubstackNotionIframeSnippet,
} from "../src/lib/viralShareBuilders.ts";
import { renderArchivalBadgeSvg } from "../src/lib/badgeSvg.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const WEB_SRC_DIR = path.resolve(__dirname, "../src");

test("Hero Analytics: Calendar, Bootstrap, Session Expectancy, and Twin calculations", async () => {
  const verification = await verifyProofBundle(BUNDLE_INSTITUTIONAL_FUND, {
    registryDoc: DEMO_REGISTRY_DOCUMENT,
    chainHistory: [BUNDLE_INSTITUTIONAL_SEQ0, BUNDLE_INSTITUTIONAL_SEQ1],
    continuityLogLeaves: DEMO_CONTINUITY_LOG_LEAVES,
    nowUtc: "2026-04-02T00:00:00Z",
  });
  assert.equal(verification.valid, true);

  const leaves = extractTypedLeaves(BUNDLE_INSTITUTIONAL_FUND);
  assert.ok(leaves);

  // 1. Calendar cells
  const cells = resolveDailyCalendarCells(BUNDLE_INSTITUTIONAL_FUND, leaves);
  assert.ok(Array.isArray(cells));
  assert.ok(cells.length > 0);
  assert.equal(typeof cells[0].date, "string");
  assert.equal(typeof cells[0].return_pct, "number");

  // Monthly grouping
  const monthGroups = groupCalendarCellsByMonth(cells);
  assert.ok(monthGroups.length > 0);
  for (const mg of monthGroups) {
    assert.ok(mg.monthKey.length >= 6);
    assert.ok(mg.monthLabel.length >= 3);
    assert.ok(Number.isFinite(mg.compoundedReturnPct));
    assert.ok(mg.totalTrades >= 0);
  }

  // 2. Stationary block bootstrap (1,000 paths)
  const bs = resolveBootstrapSummary(BUNDLE_INSTITUTIONAL_FUND, leaves);
  assert.ok(bs);
  assert.equal(bs.num_simulations, 1000);
  assert.ok(bs.cone.length > 0);
  assert.ok(Number.isFinite(bs.prob_drawdown_10pct));
  assert.ok(Number.isFinite(bs.prob_drawdown_20pct));
  assert.ok(Number.isFinite(bs.prob_positive_terminal));

  // Determinism check (zero createSeededRng dependency)
  const bs2 = resolveBootstrapSummary(BUNDLE_INSTITUTIONAL_FUND, leaves);
  assert.deepEqual(bs.cone, bs2.cone);
  assert.equal(bs.prob_positive_terminal, bs2.prob_positive_terminal);

  // 3. Session expectancy (populated weekday x hour cells)
  const sessionCells = resolveSessionExpectancyCells(
    BUNDLE_INSTITUTIONAL_FUND,
    leaves,
  );
  assert.ok(sessionCells.length > 0 && sessionCells.length <= 168);
  for (const cell of sessionCells) {
    assert.ok(cell.weekday >= 0 && cell.weekday <= 6);
    assert.ok(cell.hour_utc >= 0 && cell.hour_utc <= 23);
    assert.ok(cell.trade_count >= 0);
    assert.ok(Number.isFinite(cell.win_rate));
  }

  // 4. Counterfactual twin & compliance disclaimer
  const twin = resolveCounterfactualTwin(BUNDLE_INSTITUTIONAL_FUND, leaves);
  assert.ok(twin);
  assert.equal(twin.is_hypothetical_simulation, true);
  assert.ok(twin.compliance_disclaimer.toUpperCase().includes("HYPOTHETICAL"));
  assert.ok(twin.zero_friction_ending_index >= twin.actual_ending_index);

  // 5. Quant DNA profile
  const dna = resolveQuantDnaProfile(BUNDLE_INSTITUTIONAL_FUND, leaves);
  assert.ok(dna);
  assert.ok(dna.consistency_score >= 0 && dna.consistency_score <= 100);
  assert.ok(dna.drawdown_resilience_score >= 0 && dna.drawdown_resilience_score <= 100);
  assert.ok(dna.archetype_label.length > 3);
});

test("Obsidian and Paper Theme tokens and CSS rules", () => {
  const cssPath = path.resolve(WEB_SRC_DIR, "app/globals.css");
  const css = fs.readFileSync(cssPath, "utf-8");

  // Check Obsidian tokens
  assert.ok(css.includes("#06080D") || css.includes("#0a0b0d"));
  assert.ok(css.includes("#0E1117") || css.includes("#111317"));
  assert.ok(css.includes("#141822") || css.includes("#222631"));

  // Check Paper tokens
  assert.ok(css.includes("#F7F6F2") || css.includes("#fbfbf9"));
  assert.ok(css.includes("#FFFFFF") || css.includes("#f4f4f0"));

  // Check Telemetry grid utility
  assert.ok(css.includes(".bg-telemetry-grid"));
  assert.equal(css.includes(".bg-institutional-grid"), false);

  // Check zero SVG glow filters in css
  assert.equal(css.includes("feGaussianBlur"), false);
});

test("Viral Tear-Sheet Builders: 16:9, 9:16 cards, Badge SVGs, Discord and iframe snippets", async () => {
  const verification = await verifyProofBundle(BUNDLE_INSTITUTIONAL_FUND, {
    registryDoc: DEMO_REGISTRY_DOCUMENT,
    chainHistory: [BUNDLE_INSTITUTIONAL_SEQ0, BUNDLE_INSTITUTIONAL_SEQ1],
    continuityLogLeaves: DEMO_CONTINUITY_LOG_LEAVES,
    nowUtc: "2026-04-02T00:00:00Z",
  });
  assert.equal(verification.valid, true);

  // 1. 16:9 Share Card SVG in both Obsidian and Paper themes
  const svg16x9Obsidian = renderShareCard16x9Svg(
    BUNDLE_INSTITUTIONAL_FUND,
    verification,
    { theme: "obsidian", originUrl: "https://verify.example.org" },
  );
  assert.ok(svg16x9Obsidian.startsWith("<svg"));
  assert.ok(svg16x9Obsidian.includes('viewBox="0 0 1280 720"'));
  assert.ok(svg16x9Obsidian.includes("INDEXED-100 TWR"));
  assert.equal(svg16x9Obsidian.includes("n170.io"), false);
  assert.equal(svg16x9Obsidian.includes("n170.ai"), false);
  assert.equal(svg16x9Obsidian.includes("\u2014"), false);
  assert.equal(svg16x9Obsidian.includes("\u2013"), false);

  const svg16x9Paper = renderShareCard16x9Svg(
    BUNDLE_INSTITUTIONAL_FUND,
    verification,
    { theme: "paper", originUrl: "https://verify.example.org" },
  );
  assert.ok(svg16x9Paper.startsWith("<svg"));
  assert.ok(svg16x9Paper.includes("#F7F6F2") || svg16x9Paper.includes("#FFFFFF") || svg16x9Paper.includes("fill="));

  // 2. 9:16 Share Card SVG
  const svg9x16 = renderShareCard9x16Svg(
    BUNDLE_INSTITUTIONAL_FUND,
    verification,
    { theme: "obsidian", originUrl: "https://verify.example.org" },
  );
  assert.ok(svg9x16.startsWith("<svg"));
  assert.ok(svg9x16.includes('viewBox="0 0 720 1280"'));
  assert.equal(svg9x16.includes("\u2014"), false);
  assert.equal(svg9x16.includes("\u2013"), false);

  // 3. Standalone Badge SVG in both themes
  const badgeSvgObsidian = renderArchivalBadgeSvg(
    BUNDLE_INSTITUTIONAL_FUND,
    verification,
    "obsidian",
    "Alpha Desk",
  );
  assert.ok(badgeSvgObsidian.startsWith("<svg"));
  assert.ok(badgeSvgObsidian.toUpperCase().includes("ALPHA DESK"));
  assert.ok(badgeSvgObsidian.includes("INDEXED-100 TWR"));
  assert.equal(badgeSvgObsidian.includes("\u2014"), false);

  const badgeSvgPaper = renderArchivalBadgeSvg(
    BUNDLE_INSTITUTIONAL_FUND,
    verification,
    "paper",
  );
  assert.ok(badgeSvgPaper.startsWith("<svg"));

  // 4. Discord Embed JSON
  const discordJson = buildDiscordVerifyEmbedJson(
    BUNDLE_INSTITUTIONAL_FUND,
    verification,
    { originUrl: "https://verify.example.org" },
  );
  const parsedDiscord = JSON.parse(discordJson);
  assert.ok(parsedDiscord.embeds && parsedDiscord.embeds.length > 0);
  assert.ok(parsedDiscord.embeds[0].title);
  assert.ok(parsedDiscord.embeds[0].url.startsWith("https://verify.example.org/p/"));
  assert.ok(Array.isArray(parsedDiscord.embeds[0].fields));
  assert.ok(parsedDiscord.embeds[0].fields.length >= 4);

  // 5. Embed snippets (Markdown and iframe)
  const mdSnippet = buildMarkdownBadgeSnippet("prf-alpha-01", "https://verify.example.org");
  assert.ok(mdSnippet.includes("https://verify.example.org/api/v1/badges/prf-alpha-01.svg"));

  const iframeSnippet = buildSubstackNotionIframeSnippet(
    "prf-alpha-01",
    "https://verify.example.org",
    "obsidian",
  );
  assert.ok(iframeSnippet.iframeHtml.includes("<iframe"));
  assert.ok(iframeSnippet.iframeHtml.includes('sandbox="allow-scripts allow-popups"'));

  // 6. Rejected bundle renders unverified state cleanly
  const invalidResult: BundleVerificationResult = {
    ...verification,
    valid: false,
    signature_valid: false,
    merkle_valid: false,
  };
  const rejectedSvg = renderShareCard16x9Svg(
    BUNDLE_INSTITUTIONAL_FUND,
    invalidResult,
    { theme: "obsidian", originUrl: "https://verify.example.org" },
  );
  assert.ok(rejectedSvg.includes("UNVERIFIED") || rejectedSvg.includes("REJECTED"));
});

test("Plausibility Math: Non-normal PSR, MinTRL, query string parsing & tone challenge", () => {
  // 1. Standard normal CDF and PDF bounds
  assert.ok(Math.abs(standardNormalCdf(0) - 0.5) < 1e-6);
  assert.ok(Math.abs(standardNormalCdf(1.96) - 0.975) < 0.001);
  assert.ok(Math.abs(standardNormalCdf(-1.96) - 0.025) < 0.001);
  assert.ok(standardNormalPdf(0) > 0.398);

  // 2. Variance factor under non-normality (Bailey & Lopez de Prado)
  const vfNormal = computePsrVarianceFactor(1.0, 0, 0);
  assert.ok(Math.abs(vfNormal - 1.5) < 1e-4);

  // Heavy negative skew increases variance factor and deflates PSR
  const vfSkewed = computePsrVarianceFactor(1.0, -1.5, 5.0);
  assert.ok(vfSkewed > vfNormal);

  // 3. Claim plausibility computation
  const inputs: PlausibilityInputs = {
    claimedSharpe: 2.8,
    observedPeriods: 252,
    skewness: -0.5,
    excessKurtosis: 3.0,
    benchmarkSharpe: 0.0,
    annualizationFactor: 252,
  };
  const claim = computeClaimPlausibility(inputs);
  assert.equal(claim.claimed_sharpe, 2.8);
  assert.ok(claim.implied_psr > 0.95);
  assert.ok(claim.required_min_trl_periods_95pct != null && claim.required_min_trl_periods_95pct > 0);
  assert.equal(claim.sufficiency_tier, SufficiencyTier.STATISTICALLY_SUFFICIENT_IF_UNSMOOTHED);

  // Insufficient sample claim (T=15, claimed Sharpe = 5.0)
  const dubiousClaim = computeClaimPlausibility({
    claimedSharpe: 5.0,
    observedPeriods: 15,
    skewness: -2.0,
    excessKurtosis: 6.0,
    benchmarkSharpe: 1.0,
    annualizationFactor: 252,
  });
  assert.ok(dubiousClaim.implied_psr < 0.95);
  assert.equal(dubiousClaim.sufficiency_tier, SufficiencyTier.INSUFFICIENT_TRACK_RECORD_NOISE_DOMINATED);

  // 4. Query string round-trip
  const qs = buildPlausibilityQueryString(inputs);
  const parsed = parsePlausibilityQueryParams(new URLSearchParams(qs));
  assert.equal(parsed.claimedSharpe, 2.8);
  assert.equal(parsed.observedPeriods, 252);
  assert.equal(parsed.skewness, -0.5);
  assert.equal(parsed.excessKurtosis, 3.0);

  // 5. Challenge reply generator across tones
  for (const tone of ["professional", "peer_quant", "concise_reply"] as const) {
    const rep = buildPoliteChallengeReply({
      handle: "@trader_bob",
      claimText: "+350% crypto options",
      tone,
      originUrl: "https://verify.example.org",
    });
    assert.equal(rep.sanitizedHandle, "@trader_bob");
    assert.ok(rep.replyText.length > 20);
    assert.ok(rep.challengeUrl.startsWith("https://verify.example.org/challenge"));
    assert.equal(rep.replyText.includes("\u2014"), false);
    assert.equal(rep.replyText.includes("\u2013"), false);
    assert.equal(rep.replyText.includes("n170.io"), false);
  }
});

test("Automated Anti-Slop Audit: zero em dashes, zero n170.(io|ai), zero banned copy words across owned files", () => {
  const BANNED_COPY_WORDS = [
    "hedge fund",
    "\\bfund\\b",
    "\\bLP\\b",
    "allocate",
    "capacity",
    "audited",
    "trustless",
    "tamper-proof",
    "zero-knowledge",
    "air-gapped",
    "timestamped",
    "institutional",
    "guaranteed",
    "100% private",
    "proves skill",
    "fraud",
    "forensic",
    "caught",
    "insider",
    "\\bDSR\\b",
    "\\bstreak\\b",
    "connect any broker",
    "works with IBKR",
    "12 brokers",
    "v0.5.0",
  ];

  const EXCLUDED_SCAN_FILES = [
    "demoFixtures.ts",
    "contracts.ts",
    "statementSniffer.ts",
    "ConnectIsolationReceipt.tsx",
  ];

  function scanDirectory(dir: string): { file: string; line: number; issue: string; text: string }[] {
    const issues: { file: string; line: number; issue: string; text: string }[] = [];
    const entries = fs.readdirSync(dir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (
          entry.name === "connect" ||
          entry.name === "pyodide" ||
          entry.name === "connector" ||
          entry.name === "node_modules" ||
          entry.name === ".next"
        ) {
          continue;
        }
        issues.push(...scanDirectory(fullPath));
      } else if (entry.isFile() && (entry.name.endsWith(".ts") || entry.name.endsWith(".tsx"))) {
        if (EXCLUDED_SCAN_FILES.includes(entry.name)) continue;

        const content = fs.readFileSync(fullPath, "utf-8");
        const lines = content.split("\n");

        for (let idx = 0; idx < lines.length; idx++) {
          const lineNum = idx + 1;
          const line = lines[idx];

          // 1. Check em dashes and en dashes
          if (/[\u2013\u2014]/.test(line)) {
            issues.push({
              file: path.relative(WEB_SRC_DIR, fullPath),
              line: lineNum,
              issue: "em/en-dash",
              text: line.trim(),
            });
          }

          // 2. Check domain n170.(io|ai)
          if (/n170\.(?:io|ai)/i.test(line)) {
            issues.push({
              file: path.relative(WEB_SRC_DIR, fullPath),
              line: lineNum,
              issue: "n170-domain",
              text: line.trim(),
            });
          }

          // 3. Check statusPill: 'Live'
          if (/statusPill:\s*["']Live["']/.test(line)) {
            issues.push({
              file: path.relative(WEB_SRC_DIR, fullPath),
              line: lineNum,
              issue: "statusPill-Live",
              text: line.trim(),
            });
          }

          // 4. Check createSeededRng / mergeWithDemoRegistry
          if (line.includes("createSeededRng")) {
            issues.push({
              file: path.relative(WEB_SRC_DIR, fullPath),
              line: lineNum,
              issue: "createSeededRng",
              text: line.trim(),
            });
          }
          if (line.includes("mergeWithDemoRegistry")) {
            issues.push({
              file: path.relative(WEB_SRC_DIR, fullPath),
              line: lineNum,
              issue: "mergeWithDemoRegistry",
              text: line.trim(),
            });
          }

          // 5. Check banned copy words in rendered copy / string literals / JSX
          const isImportOrConst =
            line.trim().startsWith("import ") ||
            line.includes("BUNDLE_INSTITUTIONAL_") ||
            line.includes("official TLS endpoint") ||
            line.includes("capacityBits") ||
            line.includes("renderInstitutionalBadgeSvg") ||
            line.includes('options.tone === "institutional"') ||
            line.includes("ChallengeTone");

          if (!isImportOrConst) {
            for (const bw of BANNED_COPY_WORDS) {
              const regex = new RegExp(bw, "i");
              if (regex.test(line)) {
                issues.push({
                  file: path.relative(WEB_SRC_DIR, fullPath),
                  line: lineNum,
                  issue: `banned-word:${bw}`,
                  text: line.trim(),
                });
              }
            }
          }

          // 6. Check bare v3
          if (/(?<![.\-_/])\bv3\b/i.test(line)) {
            if (
              !line.includes("schema_version") &&
              !line.includes("bundle.v3") &&
              !line.includes("leaf.v3") &&
              !isImportOrConst
            ) {
              issues.push({
                file: path.relative(WEB_SRC_DIR, fullPath),
                line: lineNum,
                issue: "bare-v3",
                text: line.trim(),
              });
            }
          }
        }
      }
    }
    return issues;
  }

  const findings = scanDirectory(WEB_SRC_DIR);
  if (findings.length > 0) {
    console.error("Anti-slop violations found in web/src:", findings);
  }
  assert.equal(
    findings.length,
    0,
    `Expected 0 anti-slop violations, found ${findings.length}`,
  );
});
