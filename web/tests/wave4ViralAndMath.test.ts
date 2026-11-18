import assert from "node:assert/strict";
import test from "node:test";

import { verifyProofBundle } from "../src/lib/browserVerify.ts";
import {
  extractTypedLeaves,
  OriginAssurance,
  ReconciliationStatus,
} from "../src/lib/contracts.ts";
import {
  BUNDLE_COACHING_STUDIO_FULL,
  BUNDLE_DISCREPANCY_XRAY,
  BUNDLE_INSTITUTIONAL_FUND,
  BUNDLE_INSTITUTIONAL_SEQ0,
  BUNDLE_INSTITUTIONAL_SEQ1,
  DEMO_CONTINUITY_LOG_LEAVES,
  DEMO_REGISTRY_DOCUMENT,
  findShowcaseProfile,
} from "../src/lib/demoFixtures.ts";
import {
  ASSET_TAIL_PRESETS,
  SufficiencyTier,
  Z_ALPHA_95,
  buildPlausibilityQueryString,
  buildPoliteChallengeReply,
  computeClaimPlausibility,
  computePsrVarianceFactor,
  parsePlausibilityQueryParams,
  sanitizeHandleInput,
  sanitizePlainInput,
} from "../src/lib/plausibilityMath.ts";
import {
  IBKR_FLEX_60S_CHECKLIST,
  SYNTHETIC_DROPZONE_SPECIMENS,
  sniffBrokerageStatement,
} from "../src/lib/statementSniffer.ts";
import {
  buildDiscordVerifyEmbedPayload,
  buildMarkdownBadgeSnippet,
  buildSubstackNotionIframeSnippet,
  extractVerifiedCardSummary,
  renderShareCard16x9Svg,
  renderShareCard9x16Svg,
  sanitizeOriginUrl,
} from "../src/lib/viralShareBuilders.ts";
import {
  groupCalendarCellsByMonth,
  resolveBootstrapSummary,
  resolveCounterfactualTwin,
  resolveDailyCalendarCells,
  resolveQuantDnaProfile,
  resolveSessionExpectancyCells,
} from "../src/lib/wave4Analytics.ts";

test("computeClaimPlausibility matches Bailey & Lopez de Prado (2012) non-normal PSR and MinTRL", () => {
  // Gaussian case (skew=0, excess_kurtosis=0, T=504 days = 2 years): V = 1 + 0.5 * sr_hat^2
  const gaussian = computeClaimPlausibility({
    claimedSharpe: 2.0,
    observedPeriods: 504,
    skewness: 0.0,
    excessKurtosis: 0.0,
    benchmarkSharpe: 0.5,
    annualizationFactor: 252,
  });

  const srPeriod = 2.0 / Math.sqrt(252);
  const benchPeriod = 0.5 / Math.sqrt(252);
  const expectedV = 1.0 + 0.5 * srPeriod * srPeriod;
  assert.ok(
    Math.abs(computePsrVarianceFactor(srPeriod, 0.0, 0.0) - expectedV) < 1e-12,
  );
  const expectedMinTrl =
    1.0 + expectedV * (Z_ALPHA_95 / (srPeriod - benchPeriod)) ** 2;
  assert.ok(gaussian.required_min_trl_periods_95pct !== null);
  assert.ok(
    Math.abs(gaussian.required_min_trl_periods_95pct! - expectedMinTrl) < 0.02,
  );
  assert.ok(gaussian.implied_psr > 0.98);
  assert.equal(
    gaussian.sufficiency_tier,
    SufficiencyTier.STATISTICALLY_SUFFICIENT_IF_UNSMOOTHED,
  );

  // Short-Vol / Options preset (skew -1.5, excess kurtosis 6.0) inflates MinTRL vs Gaussian
  const shortVolPreset = ASSET_TAIL_PRESETS.find(
    (p) => p.id === "short_vol_options",
  );
  assert.ok(shortVolPreset);
  const shortVol = computeClaimPlausibility({
    claimedSharpe: 2.0,
    observedPeriods: 28,
    skewness: shortVolPreset.skewness,
    excessKurtosis: shortVolPreset.excessKurtosis,
    benchmarkSharpe: 0.5,
    annualizationFactor: 252,
  });
  assert.ok(
    shortVol.required_min_trl_periods_95pct! >
      gaussian.required_min_trl_periods_95pct!,
  );
  assert.equal(
    shortVol.sufficiency_tier,
    SufficiencyTier.INSUFFICIENT_TRACK_RECORD_NOISE_DOMINATED,
  );
  // Zero single-account multiple-testing Sharpe deflation or defamatory phrasing
  assert.equal(shortVol.plain_english_summary.includes("D" + "SR"), false);
  assert.equal(
    /fraud|scam|fake/i.test(shortVol.plain_english_summary),
    false,
  );
});

test("plausibility query string round-trips cleanly and clamps out-of-range parameters", () => {
  const qs = buildPlausibilityQueryString({
    claimedSharpe: 3.45,
    observedPeriods: 64,
    skewness: -1.5,
    excessKurtosis: 6.0,
    benchmarkSharpe: 0.5,
    annualizationFactor: 252,
  });
  const parsed = parsePlausibilityQueryParams(new URLSearchParams(qs));
  assert.equal(parsed.claimedSharpe, 3.45);
  assert.equal(parsed.observedPeriods, 64);
  assert.equal(parsed.skewness, -1.5);
  assert.equal(parsed.excessKurtosis, 6.0);
  assert.equal(parsed.benchmarkSharpe, 0.5);
  assert.equal(parsed.annualizationFactor, 252);
});

test("16:9 & 9:16 QR share cards and Discord /verify embed strictly bind to WebCrypto verification", async () => {
  // Specimen 03 claims independently_witnessed_tls, but WebCrypto verifier downgrades to operator_retrieved!
  const downgradedVer = await verifyProofBundle(BUNDLE_DISCREPANCY_XRAY, {
    registryDoc: DEMO_REGISTRY_DOCUMENT,
  });
  assert.equal(downgradedVer.valid, true);
  assert.equal(downgradedVer.effective_origin_assurance, "operator_retrieved");

  const card169 = renderShareCard16x9Svg(BUNDLE_DISCREPANCY_XRAY, downgradedVer, {
    title: 'Event Swing <script>alert("xss")</script>',
    handle: "@xray_audit",
    originUrl: "https://verify.example.org",
  });
  assert.ok(card169.includes('width="1280" height="720"'));
  assert.ok(card169.includes("Operator-Retrieved (Downgraded)"));
  assert.equal(card169.includes("Witnessed TLS (k≥2)"), false);
  assert.equal(card169.includes("<script>"), false);
  assert.ok(card169.includes("M0,0h1v1h-1z")); // Embedded ISO QR finder module

  const card916 = renderShareCard9x16Svg(BUNDLE_INSTITUTIONAL_FUND, await verifyProofBundle(BUNDLE_INSTITUTIONAL_FUND, {
    registryDoc: DEMO_REGISTRY_DOCUMENT,
    chainHistory: [BUNDLE_INSTITUTIONAL_SEQ0, BUNDLE_INSTITUTIONAL_SEQ1],
    continuityLogLeaves: DEMO_CONTINUITY_LOG_LEAVES,
  }), {
    theme: "paper",
    handle: "@meridian",
  });
  assert.ok(card916.includes('width="720" height="1280"'));
  assert.ok(card916.includes("#F7F6F2"));

  // Pending / null verification NEVER echoes unverified bundle claims
  const unverifiedSummary = extractVerifiedCardSummary(
    BUNDLE_DISCREPANCY_XRAY,
    null,
  );
  assert.equal(unverifiedSummary.valid, false);
  assert.equal(unverifiedSummary.twrLabel, "VERIFYING…");
  assert.equal(unverifiedSummary.chips[0].value, "Pending WebCrypto");

  // Discord /verify embed JSON
  const discordPayload = buildDiscordVerifyEmbedPayload(
    BUNDLE_DISCREPANCY_XRAY,
    downgradedVer,
    { handle: "@xray" },
  );
  assert.equal(discordPayload.embeds.length, 1);
  assert.equal(discordPayload.embeds[0].color, 0xf59e0b); // Ochre downgrade color
  assert.equal(discordPayload.embeds[0].fields.length, 7);
});

test("XSS sanitizers strip HTML tags, quotes, control chars, and javascript: URIs across Challenge & Embeds", () => {
  assert.equal(
    sanitizePlainInput('<img src=x onerror="alert(1)">Sharpe 4.2 javascript:evil()', 80),
    "Sharpe 4.2 evil()",
  );
  assert.equal(
    sanitizePlainInput('on"error="alert(1) oonload=evil2() javajavascript:script:evil() <scr<script>ipt>x', 80),
    "alert(1) evil2() evil() x",
  );
  assert.equal(sanitizeHandleInput("  <svg>@quant_trader!</svg> "), "@quant_trader");
  assert.equal(sanitizeOriginUrl("javascript:alert(1)"), "https://verify.example.org");
  assert.equal(
    sanitizeOriginUrl("https://verify.example.org/subpath/ignored"),
    "https://verify.example.org",
  );

  const challenge = buildPoliteChallengeReply({
    handle: '<script>bad</script>alpha_desk',
    claimText: '"+210% YTD" <iframe src="evil">',
    tone: "concise_reply",
    originUrl: "https://verify.example.org",
  });
  assert.equal(challenge.sanitizedHandle, "@badalpha_desk");
  assert.equal(challenge.replyText.includes("<"), false);
  assert.ok(challenge.replyText.includes("kept private"));

  const { iframeHtml } = buildSubstackNotionIframeSnippet(
    'prf-inst-alpha-012"><script>alert(1)</script>',
    "https://verify.example.org",
    "obsidian",
  );
  assert.equal(iframeHtml.includes("<script>"), false);
  assert.ok(iframeHtml.includes("/embed/prf-inst-alpha-012scriptalert1script"));

  const md = buildMarkdownBadgeSnippet("prf-inst-alpha-012", "https://verify.example.org");
  assert.ok(md.startsWith("[![N170 Verified Performance"));
});

test("sniffBrokerageStatement auto-detects IBKR 9-section XML, DEGIRO EN/NL/DE, Robinhood, Schwab, MT4/MT5, Tradovate, and TraderSync/TradeZella Migration", async () => {
  assert.equal(IBKR_FLEX_60S_CHECKLIST.length, 9);

  // 1. IBKR Complete 9-section XML
  const ibkr = await sniffBrokerageStatement(
    SYNTHETIC_DROPZONE_SPECIMENS.ibkr_complete.content,
  );
  assert.equal(ibkr.family, "ibkr_flex_xml");
  assert.equal(ibkr.sectionsFound.length, 9);
  assert.equal(ibkr.missingSections.length, 0);
  assert.equal(ibkr.paperAccountRejected, false);
  assert.equal(
    ibkr.previewReconciliation,
    ReconciliationStatus.RECONCILED_WITHIN_TOLERANCE,
  );

  // 1b. IBKR DU* paper account rejected
  const ibkrPaper = await sniffBrokerageStatement(
    '<FlexQueryResponse><FlexStatement accountId="DU1234567"><Trades /></FlexStatement></FlexQueryResponse>',
  );
  assert.equal(ibkrPaper.family, "ibkr_flex_xml");
  assert.equal(ibkrPaper.paperAccountRejected, true);

  // 2. DEGIRO NL, DE, and EN
  const degiroNl = await sniffBrokerageStatement(
    SYNTHETIC_DROPZONE_SPECIMENS.degiro_nl.content,
  );
  assert.equal(degiroNl.family, "degiro_csv");
  assert.equal(degiroNl.detectedLocale, "NL");

  const degiroDe = await sniffBrokerageStatement(
    "Datum,Uhrzeit,Valutadatum,Produkt,ISIN,Beschreibung,FX,Änderung,,Saldo,,Order-ID\n02-02-2026,09:15,02-02-2026,SAP SE,DE0007164600,Kauf 10,,EUR,-1800.00,EUR,8200.00,111",
  );
  assert.equal(degiroDe.family, "degiro_csv");
  assert.equal(degiroDe.detectedLocale, "DE");

  const degiroEn = await sniffBrokerageStatement(
    "Date,Time,Value date,Product,ISIN,Description,FX,Change,,Balance,,Order Id\n02-02-2026,09:15,02-02-2026,ASML,NL0010273215,Buy 2,,EUR,-1360.00,EUR,5000.00,abc",
  );
  assert.equal(degiroEn.family, "degiro_csv");
  assert.equal(degiroEn.detectedLocale, "EN");

  // 3. Robinhood & Schwab
  const rh = await sniffBrokerageStatement(
    "Activity Date,Process Date,Settle Date,Instrument,Description,Trans Code,Quantity,Price,Amount\n02/10/2026,02/10/2026,02/11/2026,AAPL,Apple,Buy,10,$220.00,($2200.00)",
  );
  assert.equal(rh.family, "robinhood_csv");

  const schwab = await sniffBrokerageStatement(
    '"Date","Action","Symbol","Description","Quantity","Price","Fees & Comm","Amount"\n"02/10/2026","Buy","MSFT","MICROSOFT","5","$410.00","$0.65","-$2050.65"',
  );
  assert.equal(schwab.family, "schwab_csv");

  // 4. MT4/MT5 HTML & Demo server rejection
  const mt5 = await sniffBrokerageStatement(
    SYNTHETIC_DROPZONE_SPECIMENS.mt5_html.content,
  );
  assert.equal(mt5.family, "mt4_mt5_report");
  assert.equal(mt5.paperAccountRejected, false);

  const mtDemo = await sniffBrokerageStatement(
    "<html><title>MetaTrader 5</title><body>Server: MetaQuotes-Demo <table><tr><td>Closed Transactions</td><td>Ticket</td></tr></table></body></html>",
  );
  assert.equal(mtDemo.family, "mt4_mt5_report");
  assert.equal(mtDemo.paperAccountRejected, true);

  // 5. Tradovate Futures CSV
  const tradovate = await sniffBrokerageStatement(
    SYNTHETIC_DROPZONE_SPECIMENS.tradovate_futures.content,
  );
  assert.equal(tradovate.family, "tradovate_csv");
  assert.equal(tradovate.paperAccountRejected, false);

  // 6. 1-Click Leave TraderSync / TradeZella Migration
  const migration = await sniffBrokerageStatement(
    SYNTHETIC_DROPZONE_SPECIMENS.tradezella_migration.content,
  );
  assert.equal(migration.family, "journal_migration_csv");
  assert.equal(migration.previewOrigin, OriginAssurance.SELF_REPORTED);
  assert.equal(
    migration.previewReconciliation,
    ReconciliationStatus.INSUFFICIENT_SECTIONS,
  );
  assert.ok(migration.importedJournalTags.includes("momentum_breakout"));
  assert.ok(migration.importedJournalTags.includes("orb_5m"));
});

test("Wave-4 tear-sheet analytics preserve privacy, monotonicity, compliance disclaimers, and /vs demo aliases", () => {
  assert.equal(
    findShowcaseProfile("demo-tls-alpha")?.proofId,
    "prf-inst-alpha-012",
  );
  assert.equal(
    findShowcaseProfile("demo-ibkr-flex")?.proofId,
    "prf-xray-residual-004",
  );

  const leaves = extractTypedLeaves(BUNDLE_COACHING_STUDIO_FULL);
  const dailyCells = resolveDailyCalendarCells(
    BUNDLE_COACHING_STUDIO_FULL,
    leaves,
  );
  assert.ok(dailyCells.length >= 10);
  for (const c of dailyCells) {
    assert.deepEqual(Object.keys(c).sort(), ["date", "return_pct", "trade_count"]);
  }

  const months = groupCalendarCellsByMonth(dailyCells);
  assert.ok(months.length >= 1);

  const bootstrap = resolveBootstrapSummary(
    BUNDLE_COACHING_STUDIO_FULL,
    leaves,
    dailyCells,
  );
  assert.equal(bootstrap.num_simulations, 1000);
  assert.ok(bootstrap.cone.length >= 10);
  for (const pt of bootstrap.cone) {
    assert.ok(pt.p05 <= pt.p25 && pt.p25 <= pt.p50 && pt.p50 <= pt.p75 && pt.p75 <= pt.p95);
  }

  const sessionCells = resolveSessionExpectancyCells(
    BUNDLE_COACHING_STUDIO_FULL,
    leaves,
  );
  assert.ok(sessionCells.length >= 20);

  const twin = resolveCounterfactualTwin(BUNDLE_COACHING_STUDIO_FULL, leaves);
  assert.ok(twin);
  assert.equal(twin.is_hypothetical_simulation, true);
  assert.ok(twin.compliance_disclaimer.toUpperCase().includes("HYPOTHETICAL"));
  assert.ok(twin.zero_friction_ending_index >= twin.actual_ending_index);

  const dna = resolveQuantDnaProfile(BUNDLE_COACHING_STUDIO_FULL, leaves);
  assert.ok(dna);
  assert.ok(dna.archetype_label.length > 5);
  assert.ok(dna.consistency_score >= 8 && dna.consistency_score <= 99);
});
