/**
 * N170 Verify v3 — Universal Zero-Dropdown Brokerage & Journal Statement Sniffer.
 *
 * Auto-detects file signatures in browser / Node WebCrypto memory across:
 * - IBKR Activity Flex XML v3 (9-section completeness & DU* paper-account guard)
 * - DEGIRO Account Statement CSV (EN / NL / DE localized headers)
 * - Robinhood Activity CSV
 * - Charles Schwab Transactions CSV
 * - MetaTrader 4 / MetaTrader 5 (MT4/MT5) HTML & CSV Reports (+ Demo server guard)
 * - Tradovate Futures Performance / Fills CSV
 * - 1-Click Leave TraderSync / TradeZella Migration CSV (preserves coaching tags
 *   with transparent `self_reported` + `insufficient_sections` badge preview)
 * - Signed N170 `.verify.json` Proof Bundles
 */

import { sha256Hex } from "./browserVerify.ts";
import {
  AccountScope,
  OriginAssurance,
  ReconciliationStatus,
} from "./contracts.ts";
import { sanitizePlainInput } from "./plausibilityMath.ts";

export type DetectedFormatFamily =
  | "ibkr_flex_xml"
  | "degiro_csv"
  | "robinhood_csv"
  | "schwab_csv"
  | "mt4_mt5_report"
  | "tradovate_csv"
  | "journal_migration_csv"
  | "n170_proof_bundle"
  | "generic_csv";

export interface IbkrChecklistSectionSpec {
  id: string;
  xmlTag: string;
  stepTime: string;
  requiredForReconciled: boolean;
  purpose: string;
}

export const IBKR_FLEX_60S_CHECKLIST: readonly IbkrChecklistSectionSpec[] = [
  {
    id: "EquitySummaryInBase",
    xmlTag: "EquitySummaryInBase",
    stepTime: "05s",
    requiredForReconciled: true,
    purpose: "Daily closing total equity in base currency for flow-adjusted TWR indexing.",
  },
  {
    id: "PriorPeriodPositions",
    xmlTag: "PriorPeriodPositions",
    stepTime: "12s",
    requiredForReconciled: true,
    purpose: "Anchors opening mark-to-market holdings so pre-existing positions reconcile.",
  },
  {
    id: "OpenPositions",
    xmlTag: "OpenPositions",
    stepTime: "18s",
    requiredForReconciled: true,
    purpose: "Verifies ending period mark-to-market inventory without leaking live holdings publicly.",
  },
  {
    id: "Trades",
    xmlTag: "Trades",
    stepTime: "24s",
    requiredForReconciled: true,
    purpose: "Execution fills, timestamps, commissions, and asset classes for 2-stage EODHD bounds.",
  },
  {
    id: "CashTransactions",
    xmlTag: "CashTransactions",
    stepTime: "30s",
    requiredForReconciled: true,
    purpose: "Dividends, withholding taxes, margin interest, and external cash deposits/withdrawals.",
  },
  {
    id: "Transfers",
    xmlTag: "Transfers",
    stepTime: "38s",
    requiredForReconciled: true,
    purpose: "Separates ACATS, FOP, and internal sub-account transfers from trading return.",
  },
  {
    id: "CorporateActions",
    xmlTag: "CorporateActions",
    stepTime: "45s",
    requiredForReconciled: true,
    purpose: "Accounts for stock splits, mergers, and spin-offs without false NAV jump residuals.",
  },
  {
    id: "OptionEAE",
    xmlTag: "OptionEAE",
    stepTime: "52s",
    requiredForReconciled: true,
    purpose: "Reconciles option exercises, assignments, and expirations across clearing boundaries.",
  },
  {
    id: "ConversionRates",
    xmlTag: "ConversionRates",
    stepTime: "60s",
    requiredForReconciled: false,
    purpose: "Multi-currency FX translation rates for non-base execution & borrow drag attribution.",
  },
] as const;

export interface SniffedStatementResult {
  family: DetectedFormatFamily;
  formatLabel: string;
  detectedLocale?: "EN" | "NL" | "DE";
  migrationSource?: "TraderSync" | "TradeZella";
  apiBrokerId: string;
  apiCsvFormat?: "degiro" | "robinhood" | "schwab";
  sha256Hex: string;
  byteLength: number;
  sectionsFound: string[];
  missingSections: string[];
  importedJournalTags: string[];
  paperAccountRejected: boolean;
  previewOrigin: OriginAssurance;
  previewScope: AccountScope;
  previewReconciliation: ReconciliationStatus;
  transparencyNotice: string;
}

async function sha256Utf8Hex(text: string): Promise<{ hex: string; byteLength: number }> {
  const bytes = new TextEncoder().encode(text);
  return { hex: await sha256Hex(bytes), byteLength: bytes.byteLength };
}

function splitCsvLine(line: string): string[] {
  const cells: string[] = [];
  let cur = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i]!;
    if (ch === '"') {
      inQuotes = !inQuotes;
    } else if ((ch === "," || ch === ";") && !inQuotes) {
      cells.push(cur.trim());
      cur = "";
    } else {
      cur += ch;
    }
  }
  cells.push(cur.trim());
  return cells.map((c) => c.replace(/^"+|"+$/g, "").trim());
}

function extractJournalTagsFromCsv(lines: string[], headerCells: string[]): string[] {
  const tagColIndices: number[] = [];
  for (let idx = 0; idx < headerCells.length; idx++) {
    const col = headerCells[idx] ?? "";
    const lc = col.toLowerCase();
    if (
      lc.includes("setup") ||
      lc.includes("mistake") ||
      lc.includes("playbook") ||
      lc.includes("tag")
    ) {
      tagColIndices.push(idx);
    }
  }
  if (tagColIndices.length === 0) return [];

  const collected = new Set<string>();
  for (const row of lines.slice(1, 40)) {
    if (!row.trim()) continue;
    const cols = splitCsvLine(row);
    for (const colIdx of tagColIndices) {
      const rawCell = cols[colIdx] ?? "";
      for (const token of rawCell.split(/[|;/,]+/)) {
        const clean = sanitizePlainInput(token, 36)
          .toLowerCase()
          .replace(/[^a-z0-9_\- ]/g, "")
          .trim()
          .replace(/\s+/g, "_");
        if (clean.length >= 2 && clean !== "none" && clean !== "na") {
          collected.add(clean);
        }
        if (collected.size >= 12) break;
      }
    }
    if (collected.size >= 12) break;
  }
  return Array.from(collected);
}

/**
 * Auto-detects brokerage XML/CSV/HTML exports and SaaS journal migrations with zero dropdowns.
 */
export async function sniffBrokerageStatement(
  rawText: string,
  fileName?: string,
): Promise<SniffedStatementResult> {
  const { hex: sha256Hex, byteLength } = await sha256Utf8Hex(rawText);
  const trimmed = rawText.trim();
  const head = trimmed.slice(0, 4096);
  const headLower = head.toLowerCase();
  const lines = trimmed.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const firstLine = lines[0] ?? "";
  const secondLine = lines[1] ?? "";
  const headerCells = splitCsvLine(firstLine);

  // 1. Signed N170 .verify.json Proof Bundle
  if (
    trimmed.startsWith("{") &&
    trimmed.includes('"proof_id"') &&
    trimmed.includes('"merkle_root"') &&
    trimmed.includes('"signature_hex"')
  ) {
    return {
      family: "n170_proof_bundle",
      formatLabel: "Signed N170 .verify.json Proof Bundle",
      apiBrokerId: "n170_bundle",
      sha256Hex,
      byteLength,
      sectionsFound: ["merkle_root", "disclosed_leaves", "signature_hex"],
      missingSections: [],
      importedJournalTags: [],
      paperAccountRejected: false,
      previewOrigin: OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
      previewScope: AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
      previewReconciliation: ReconciliationStatus.RECONCILED_WITHIN_TOLERANCE,
      transparencyNotice:
        "Cryptographically signed N170 bundle detected — ready for instant client-side WebCrypto verification.",
    };
  }

  // 2. IBKR Activity Flex XML v3
  if (trimmed.includes("<FlexQueryResponse") || trimmed.includes("<FlexStatement")) {
    const found: string[] = [];
    const missing: string[] = [];
    for (const spec of IBKR_FLEX_60S_CHECKLIST) {
      if (trimmed.includes(`<${spec.xmlTag}`)) {
        found.push(spec.xmlTag);
      } else if (spec.requiredForReconciled) {
        missing.push(spec.xmlTag);
      }
    }
    const paperAccountRejected =
      /accountId\s*=\s*["']DU[0-9A-Za-z]+["']/i.test(trimmed) ||
      /accountType\s*=\s*["']Paper["']/i.test(trimmed);
    const recon =
      missing.length === 0
        ? ReconciliationStatus.RECONCILED_WITHIN_TOLERANCE
        : ReconciliationStatus.INSUFFICIENT_SECTIONS;

    return {
      family: "ibkr_flex_xml",
      formatLabel: "IBKR Activity Flex XML v3",
      apiBrokerId: "ibkr_flex_offline",
      sha256Hex,
      byteLength,
      sectionsFound: found,
      missingSections: missing,
      importedJournalTags: [],
      paperAccountRejected,
      previewOrigin: OriginAssurance.SELF_REPORTED,
      previewScope: AccountScope.UNKNOWN_OFFLINE_SCOPE,
      previewReconciliation: recon,
      transparencyNotice: paperAccountRejected
        ? "DU* IBKR paper-trading account prefix detected — live production gate blocks issuance."
        : missing.length === 0
          ? "All 8 mandatory non-cash & equity Flex sections present. Offline XML upload is labeled SELF_REPORTED (use 6h Flex Token or Local Gateway CLI for Witnessed TLS)."
          : `Missing ${missing.length} Flex section(s) (${missing.join(", ")}) — reconciliation will transparently report INSUFFICIENT_SECTIONS.`,
    };
  }

  // 3. TraderSync / TradeZella 1-Click Journal Migration CSV
  const isTraderSync =
    headLower.includes("tradersync") ||
    (firstLine.includes("Symb") &&
      firstLine.includes("Open Date") &&
      firstLine.includes("Close Date")) ||
    (headLower.includes("open date") &&
      headLower.includes("setups") &&
      headLower.includes("mistakes") &&
      headLower.includes("net return"));
  const isTradeZella =
    headLower.includes("tradezella") ||
    headLower.includes("zella scale") ||
    (headLower.includes("playbook") &&
      headLower.includes("mistakes") &&
      (headLower.includes("entry price") || headLower.includes("r-multiple")));

  if (
    isTraderSync ||
    isTradeZella ||
    (fileName && /tradersync|tradezella/i.test(fileName))
  ) {
    const migrationSource: "TraderSync" | "TradeZella" = isTradeZella
      ? "TradeZella"
      : "TraderSync";
    const importedTags = extractJournalTagsFromCsv(lines, headerCells);
    return {
      family: "journal_migration_csv",
      formatLabel: `${migrationSource} Coaching Journal Migration CSV`,
      migrationSource,
      apiBrokerId: "schwab_csv",
      apiCsvFormat: "schwab",
      sha256Hex,
      byteLength,
      sectionsFound: [
        `${migrationSource} Closed Trades`,
        importedTags.length > 0
          ? `${importedTags.length} Coaching Tags Preserved`
          : "Setup/Mistake Columns Mapped",
      ],
      missingSections: [
        "CustodyCashLedger",
        "PriorPeriodPositions",
        "Transfers",
        "CorporateActions",
      ],
      importedJournalTags: importedTags,
      paperAccountRejected: false,
      previewOrigin: OriginAssurance.SELF_REPORTED,
      previewScope: AccountScope.UNKNOWN_OFFLINE_SCOPE,
      previewReconciliation: ReconciliationStatus.INSUFFICIENT_SECTIONS,
      transparencyNotice: `1-Click Leave ${migrationSource} Migration: preserves your setup & mistake coaching tags inside the open-source Coaching Studio while transparently badging provenance as SELF_REPORTED + INSUFFICIENT_SECTIONS until paired with a brokerage custody statement.`,
    };
  }

  // 4. MetaTrader 4 / MetaTrader 5 (MT4/MT5) HTML or CSV Statement
  const isMtHtml =
    (headLower.includes("<html") || headLower.includes("<!doctype html") || headLower.includes("<table")) &&
    (headLower.includes("metatrader 4") ||
      headLower.includes("metatrader 5") ||
      (headLower.includes("closed transactions") && headLower.includes("ticket")) ||
      (headLower.includes("trade history report") && headLower.includes("positions")));
  const isMtCsv =
    (firstLine.includes("Position") &&
      firstLine.includes("Symbol") &&
      firstLine.includes("Volume") &&
      firstLine.includes("S / L") &&
      firstLine.includes("T / P")) ||
    (firstLine.includes("Ticket") &&
      firstLine.includes("Open Time") &&
      firstLine.includes("Close Time") &&
      firstLine.includes("Swap") &&
      firstLine.includes("Profit"));

  if (isMtHtml || isMtCsv) {
    const paperAccountRejected =
      /metaquotes-demo|demo\s*account|server:\s*[^\n<]*demo/i.test(head);
    return {
      family: "mt4_mt5_report",
      formatLabel: isMtHtml
        ? "MT4 / MT5 Account History HTML Report"
        : "MT4 / MT5 Trade History CSV",
      apiBrokerId: "schwab_csv",
      apiCsvFormat: "schwab",
      sha256Hex,
      byteLength,
      sectionsFound: [
        isMtHtml ? "HTML Statement Table" : "MT4/MT5 Execution Rows",
        "Swap & Commission Columns",
      ],
      missingSections: ["CorporateActions", "SubAccountEnumeration"],
      importedJournalTags: [],
      paperAccountRejected,
      previewOrigin: OriginAssurance.SELF_REPORTED,
      previewScope: AccountScope.UNKNOWN_OFFLINE_SCOPE,
      previewReconciliation: ReconciliationStatus.INSUFFICIENT_SECTIONS,
      transparencyNotice: paperAccountRejected
        ? "MT4/MT5 Demo server signature detected — live production gate blocks demo statements."
        : "MT4/MT5 offline statement detected — unlocks friction waterfall (swap + commission bps) and behavioural coaching under honest SELF_REPORTED provenance.",
    };
  }

  // 5. Tradovate Futures CSV
  if (
    (firstLine.includes("_priceFormat") && firstLine.includes("buyFillId") && firstLine.includes("sellFillId")) ||
    (firstLine.includes("B/S") && firstLine.includes("Contract") && firstLine.includes("FillTime")) ||
    headLower.includes("tradovate")
  ) {
    const paperAccountRejected = /\b(?:DEMO|SIM)[0-9]{3,}\b/.test(head);
    return {
      family: "tradovate_csv",
      formatLabel: "Tradovate Futures Performance / Fills CSV",
      apiBrokerId: "schwab_csv",
      apiCsvFormat: "schwab",
      sha256Hex,
      byteLength,
      sectionsFound: ["Futures Round-Trip Fills", "Tick Size & Contract Metadata"],
      missingSections: ["CashWireLedger", "PriorPeriodPositions"],
      importedJournalTags: [],
      paperAccountRejected,
      previewOrigin: OriginAssurance.SELF_REPORTED,
      previewScope: AccountScope.UNKNOWN_OFFLINE_SCOPE,
      previewReconciliation: ReconciliationStatus.INSUFFICIENT_SECTIONS,
      transparencyNotice: paperAccountRejected
        ? "Tradovate SIM/DEMO account identifier detected — live production gate blocks simulated fills."
        : "Tradovate futures export detected — computes session expectancy matrix, Odean hold symmetry, and fee drag under SELF_REPORTED provenance.",
    };
  }

  // 6. DEGIRO Account Statement CSV (EN / NL / DE)
  const isDegiroNl =
    firstLine.includes("Datum,Tijd") ||
    (firstLine.includes("Datum") && firstLine.includes("Valutadatum") && firstLine.includes("Mutatie"));
  const isDegiroDe =
    firstLine.includes("Datum,Uhrzeit") ||
    (firstLine.includes("Datum") && firstLine.includes("Valutadatum") && firstLine.includes("Produkt"));
  const isDegiroEn =
    (firstLine.includes("Date,Time,Value date,Product,ISIN") ||
      (firstLine.includes("Date") && firstLine.includes("ISIN") && firstLine.includes("Order Id"))) ||
    headLower.includes("degiro");

  if (isDegiroNl || isDegiroDe || isDegiroEn) {
    const locale: "NL" | "DE" | "EN" = isDegiroNl
      ? "NL"
      : isDegiroDe
        ? "DE"
        : "EN";
    return {
      family: "degiro_csv",
      formatLabel: `DEGIRO Account Statement CSV (${locale})`,
      detectedLocale: locale,
      apiBrokerId: "degiro_csv",
      apiCsvFormat: "degiro",
      sha256Hex,
      byteLength,
      sectionsFound: [`DEGIRO ${locale} Localized Header`, "ISIN & FX Mutation Rows"],
      missingSections: ["PriorPeriodPositions"],
      importedJournalTags: [],
      paperAccountRejected: false,
      previewOrigin: OriginAssurance.SELF_REPORTED,
      previewScope: AccountScope.UNKNOWN_OFFLINE_SCOPE,
      previewReconciliation: ReconciliationStatus.INSUFFICIENT_SECTIONS,
      transparencyNotice: `Auto-detected DEGIRO (${locale}) localized statement without password/MFA scraping. Labeled SELF_REPORTED.`,
    };
  }

  // 7. Robinhood Activity CSV
  if (
    firstLine.includes("Activity Date,Process Date,Settle Date") ||
    (firstLine.includes("Activity Date") && firstLine.includes("Trans Code"))
  ) {
    return {
      family: "robinhood_csv",
      formatLabel: "Robinhood Account Activity CSV",
      apiBrokerId: "robinhood_csv",
      apiCsvFormat: "robinhood",
      sha256Hex,
      byteLength,
      sectionsFound: ["Robinhood Activity Ledger", "Settle Date & Trans Code"],
      missingSections: ["PriorPeriodPositions"],
      importedJournalTags: [],
      paperAccountRejected: false,
      previewOrigin: OriginAssurance.SELF_REPORTED,
      previewScope: AccountScope.UNKNOWN_OFFLINE_SCOPE,
      previewReconciliation: ReconciliationStatus.INSUFFICIENT_SECTIONS,
      transparencyNotice:
        "Auto-detected Robinhood Activity CSV export — full flow-adjusted TWR & coaching under honest SELF_REPORTED provenance.",
    };
  }

  // 8. Charles Schwab Transactions CSV
  if (
    firstLine.toLowerCase().includes("transactions  for account") ||
    firstLine.toLowerCase().includes("transactions for account") ||
    (firstLine.includes("Action") &&
      firstLine.includes("Fees & Comm") &&
      firstLine.includes("Amount")) ||
    (secondLine.includes("Action") && secondLine.includes("Fees & Comm"))
  ) {
    return {
      family: "schwab_csv",
      formatLabel: "Charles Schwab Transactions CSV",
      apiBrokerId: "schwab_csv",
      apiCsvFormat: "schwab",
      sha256Hex,
      byteLength,
      sectionsFound: ["Schwab Cash & Trade Ledger", "Fees & Comm Column"],
      missingSections: ["PriorPeriodPositions"],
      importedJournalTags: [],
      paperAccountRejected: false,
      previewOrigin: OriginAssurance.SELF_REPORTED,
      previewScope: AccountScope.UNKNOWN_OFFLINE_SCOPE,
      previewReconciliation: ReconciliationStatus.INSUFFICIENT_SECTIONS,
      transparencyNotice:
        "Auto-detected Charles Schwab CSV export — labeled SELF_REPORTED until Schwab OAuth live API is linked.",
    };
  }

  return {
    family: "generic_csv",
    formatLabel: "Generic Brokerage Transaction CSV",
    apiBrokerId: "schwab_csv",
    apiCsvFormat: "schwab",
    sha256Hex,
    byteLength,
    sectionsFound: ["Tabular Delimited Statement"],
    missingSections: ["PriorPeriodPositions", "Transfers"],
    importedJournalTags: [],
    paperAccountRejected: false,
    previewOrigin: OriginAssurance.SELF_REPORTED,
    previewScope: AccountScope.UNKNOWN_OFFLINE_SCOPE,
    previewReconciliation: ReconciliationStatus.INSUFFICIENT_SECTIONS,
    transparencyNotice:
      "Generic tabular statement detected — offline exports are strictly labeled SELF_REPORTED.",
  };
}

export const SYNTHETIC_DROPZONE_SPECIMENS: Record<
  | "ibkr_complete"
  | "degiro_nl"
  | "mt5_html"
  | "tradovate_futures"
  | "tradezella_migration",
  { label: string; badge: string; content: string }
> = {
  ibkr_complete: {
    label: "IBKR Flex XML (All 9 Sections)",
    badge: "XML v3",
    content: [
      `<?xml version="1.0" encoding="UTF-8"?>`,
      `<${"FlexQueryResponse"} queryName="N170_ReadOnly_Audit_v3" type="AF">`,
      `  <FlexStatements count="1">`,
      `    <${"FlexStatement"} accountId="U9048120" fromDate="2026-01-01" toDate="2026-03-31" period="LastQuarter">`,
      `      <AccountInformation accountId="U9048120" currency="USD" accountType="Institutional" />`,
      `      <EquitySummaryInBase count="63" />`,
      `      <PriorPeriodPositions count="4" />`,
      `      <OpenPositions count="3" />`,
      `      <Trades count="48" />`,
      `      <CashTransactions count="12" />`,
      `      <Transfers count="1" />`,
      `      <CorporateActions count="0" />`,
      `      <OptionEAE count="6" />`,
      `      <ConversionRates count="63" />`,
      `    </${"FlexStatement"}>`,
      `  </FlexStatements>`,
      `</${"FlexQueryResponse"}>`,
    ].join("\n"),
  },
  degiro_nl: {
    label: "DEGIRO Statement (NL/DE/EN)",
    badge: "DEGIRO",
    content: [
      "Datum,Tijd,Valutadatum,Product,ISIN,Beschrijving,FX,Mutatie,,Saldo,,Order Id",
      "02-02-2026,09:15,02-02-2026,ASML HOLDING,NL0010273215,Koop 5 @ 680.40 EUR,,EUR,-3402.00,EUR,16598.00,fd81a200-1122",
      "18-02-2026,15:40,18-02-2026,ASML HOLDING,NL0010273215,Verkoop 5 @ 712.80 EUR,,EUR,3564.00,EUR,20162.00,ab92c110-3344",
    ].join("\n"),
  },
  mt5_html: {
    label: "MT4 / MT5 Report",
    badge: "MT5 HTML",
    content: [
      "<!DOCTYPE html><html><head><title>MetaTrader 5 Trade History Report</title></head>",
      "<body><table><tr><th colspan='8'>Closed Transactions:</th></tr>",
      "<tr><td>Ticket</td><td>Open Time</td><td>Type</td><td>Volume</td><td>Symbol</td><td>Close Time</td><td>Swap</td><td>Profit</td></tr>",
      "<tr><td>8841201</td><td>2026.02.10 08:30:00</td><td>buy</td><td>1.00</td><td>EURUSD</td><td>2026.02.10 14:15:00</td><td>-1.20</td><td>+245.00</td></tr>",
      "</table></body></html>",
    ].join("\n"),
  },
  tradovate_futures: {
    label: "Tradovate Futures CSV",
    badge: "FUTURES",
    content: [
      "symbol,_priceFormat,_tickSize,buyFillId,sellFillId,qty,buyPrice,sellPrice,pnl,boughtTimestamp,soldTimestamp",
      "ESH6,-2,0.25,190012,190045,2,5812.25,5824.75,$1250.00,02/11/2026 09:34:12,02/11/2026 10:18:44",
      "NQH6,-2,0.25,190088,190112,1,20410.50,20468.00,$1150.00,02/12/2026 14:05:09,02/12/2026 15:22:31",
    ].join("\n"),
  },
  tradezella_migration: {
    label: "1-Click Leave TraderSync / TradeZella",
    badge: "MIGRATION",
    content: [
      "Open Date,Close Date,Symbol,Side,Entry Price,Exit Price,Playbook,Setups,Mistakes,Custom Tags",
      "2026-02-03,2026-02-03,NVDA,LONG,128.40,134.90,Momentum_Breakout,ORB_5m;Post_Earnings_Drift,None,a_plus_execution|catalyst_aligned",
      "2026-02-06,2026-02-06,TSLA,SHORT,362.10,354.20,Mean_Reversion,VWAP_Fade,Early_Exit_Trim,ny_open_alpha",
      "2026-02-11,2026-02-11,META,LONG,694.00,708.50,Catalyst_Swing,Gap_And_Go,None,institutional_flow",
    ].join("\n"),
  },
};
