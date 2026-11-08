"use client";

import {
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Clock,
  FileCode2,
  Lock,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Upload,
  XCircle,
} from "lucide-react";
import Link from "next/link";
import { type DragEvent, useState } from "react";
import { TearSheetView } from "@/components/TearSheetView.tsx";
import {
  fetchActiveRegistryDocument,
  getConfiguredApiBaseUrl,
  submitOneShotVerification,
  type ApiOneShotVerifyResponse,
} from "@/lib/apiClient.ts";
import {
  ACCOUNT_SCOPE_META,
  AccountScope,
  CHAIN_CONTINUITY_META,
  ChainContinuityMode,
  ORIGIN_ASSURANCE_META,
  OriginAssurance,
  ProviderApprovalState,
  RECONCILIATION_STATUS_META,
  type CanonicalLeafName,
  type PublisherKeyRegistryDocument,
  type RetentionMode,
} from "@/lib/contracts.ts";
import { DEMO_REGISTRY_DOCUMENT } from "@/lib/demoFixtures.ts";
import {
  IBKR_FLEX_60S_CHECKLIST,
  SYNTHETIC_DROPZONE_SPECIMENS,
  sniffBrokerageStatement,
  type SniffedStatementResult,
} from "@/lib/statementSniffer.ts";

type BrokerKey =
  | "ibkr"
  | "ctrader"
  | "alpaca"
  | "tradier"
  | "schwab"
  | "trading212"
  | "crypto_cex"
  | "offline_csv";

type IbkrTrack = "oauth" | "local_cli" | "flex_wizard" | "offline_xml";

interface BrokerCatalogItem {
  id: BrokerKey;
  name: string;
  category: string;
  statusPill:
    | "Live"
    | "Live • Scope: ACCOUNTS"
    | "Pending Provider Approval"
    | "Air-Gapped Export";
  statusVariant: "emerald" | "ochre" | "champagne" | "neutral";
  approvalState: ProviderApprovalState;
  defaultOrigin: OriginAssurance;
  accountScope: AccountScope;
  securityNote: string;
  scopeNote: string;
}

const BROKERS: BrokerCatalogItem[] = [
  {
    id: "ibkr",
    name: "Interactive Brokers",
    category: "Prime & Multi-Asset Custody",
    statusPill: "Live",
    statusVariant: "emerald",
    approvalState: ProviderApprovalState.APPROVED_LIVE,
    defaultOrigin: OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
    accountScope: AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    securityNote:
      "Day-1 read-only verification via 60s Flex v3 IP-locked token (6h expiry) or Local Gateway CLI; Third-Party OAuth slot tracked transparently.",
    scopeNote:
      "Enumerates U/F live sub-accounts and structurally rejects DU* paper accounts.",
  },
  {
    id: "ctrader",
    name: "cTrader Open API (OAuth 2.0)",
    category: "Spot FX, Metals & Multi-Broker CFDs",
    statusPill: "Live • Scope: ACCOUNTS",
    statusVariant: "emerald",
    approvalState: ProviderApprovalState.APPROVED_LIVE,
    defaultOrigin: OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
    accountScope: AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    securityNote:
      "Read-only OAuth 2.0 strictly requests Scope: ACCOUNTS (rejects Scope: TRADING). Hard-blocks isLive=false demo cTID accounts.",
    scopeNote:
      "Enumerates all live cTID trading accounts linked to the user token via k>=2 disjoint witnesses.",
  },
  {
    id: "alpaca",
    name: "Alpaca Markets",
    category: "US Equities & Options",
    statusPill: "Live",
    statusVariant: "emerald",
    approvalState: ProviderApprovalState.APPROVED_LIVE,
    defaultOrigin: OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
    accountScope: AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    securityNote:
      "Hard-blocks paper-api.alpaca.markets and PA* paper prefixes at both TLS SNI and statement parser layers.",
    scopeNote: "Witnessed via k>=2 org/ASN-disjoint TLSNotary nodes.",
  },
  {
    id: "tradier",
    name: "Tradier Brokerage",
    category: "US Equities & Options",
    statusPill: "Live",
    statusVariant: "emerald",
    approvalState: ProviderApprovalState.APPROVED_LIVE,
    defaultOrigin: OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
    accountScope: AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    securityNote:
      "Enforces api.tradier.com live production SNI (sandbox.tradier.com rejected) with read-only history scopes.",
    scopeNote: "Enumerates all linked live margin and cash sub-accounts.",
  },
  {
    id: "crypto_cex",
    name: "Binance / Coinbase / Kraken",
    category: "Digital Asset Exchanges",
    statusPill: "Live",
    statusVariant: "champagne",
    approvalState: ProviderApprovalState.USER_KEY_SELF_ATTESTED,
    defaultOrigin: OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
    accountScope: AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    securityNote:
      "Mandatory pre-fetch cryptographic key scope check: aborts immediately if spot/margin trading or withdrawal bits are enabled.",
    scopeNote: "Enumerates master + sub-account UIDs where read-only API permits.",
  },
  {
    id: "schwab",
    name: "Charles Schwab",
    category: "US Multi-Asset",
    statusPill: "Pending Provider Approval",
    statusVariant: "ochre",
    approvalState: ProviderApprovalState.PENDING_PROVIDER_APPROVAL,
    defaultOrigin: OriginAssurance.OPERATOR_RETRIEVED,
    accountScope: AccountScope.ALL_ENUMERATED_SUBACCOUNTS,
    securityNote:
      "Commercial vendor OAuth onboarding in review; personal developer app CLI & CSV verification available today.",
    scopeNote: "Uses /trader/v1/accounts/accountNumbers sub-account enumeration.",
  },
  {
    id: "trading212",
    name: "Trading 212",
    category: "UK / EU Equities & ISA",
    statusPill: "Live",
    statusVariant: "champagne",
    approvalState: ProviderApprovalState.USER_KEY_SELF_ATTESTED,
    defaultOrigin: OriginAssurance.INDEPENDENTLY_WITNESSED_TLS,
    accountScope: AccountScope.SINGLE_ACCOUNT_SURVIVORSHIP_UNVERIFIED,
    securityNote:
      "Blocks demo.trading212.com; verifies read-only metadata, order history, and dividend endpoints.",
    scopeNote:
      "Compartment-scoped keys are labeled single_account_survivorship_unverified unless all compartments are linked.",
  },
  {
    id: "offline_csv",
    name: "DEGIRO / Robinhood / MT4-5 / Tradovate / Journal CSV",
    category: "Zero-Dropdown Universal Statement Export",
    statusPill: "Air-Gapped Export",
    statusVariant: "neutral",
    approvalState: ProviderApprovalState.OFFLINE_EXPORT_ONLY,
    defaultOrigin: OriginAssurance.SELF_REPORTED,
    accountScope: AccountScope.UNKNOWN_OFFLINE_SCOPE,
    securityNote:
      "Unofficial password/MFA scrapers are prohibited. Statement exports & TraderSync/TradeZella migrations receive full coaching under honest SELF_REPORTED badges.",
    scopeNote: "Zero overclaiming of cryptographic origin on offline exports.",
  },
];

export default function ConnectWizardPage() {
  const [selectedBroker, setSelectedBroker] = useState<BrokerKey>("ibkr");
  const [ibkrTrack, setIbkrTrack] = useState<IbkrTrack>("flex_wizard");
  const [ibkrOauthLivePreview, setIbkrOauthLivePreview] = useState(false);
  const [simulateUnsafeWriteKey, setSimulateUnsafeWriteKey] = useState(false);
  const [checklistOpen, setChecklistOpen] = useState(true);

  const [flexChecks, setFlexChecks] = useState<Record<string, boolean>>(() => {
    const init: Record<string, boolean> = {};
    for (const s of IBKR_FLEX_60S_CHECKLIST) {
      init[s.xmlTag] = true;
    }
    return init;
  });

  const [retentionMode, setRetentionMode] = useState<RetentionMode>(
    "no_persistent_storage",
  );
  const [discloseBracket, setDiscloseBracket] = useState(true);
  const [discloseAlpha, setDiscloseAlpha] = useState(true);
  const [discloseDelayedTrades, setDiscloseDelayedTrades] = useState(false);
  const [enrollProspectiveChain, setEnrollProspectiveChain] = useState(true);

  const [rawStatementInput, setRawStatementInput] = useState("");
  const [sniffedMeta, setSniffedMeta] = useState<SniffedStatementResult | null>(
    null,
  );
  const [isDraggingStatement, setIsDraggingStatement] = useState(false);
  const [publishProof, setPublishProof] = useState(false);
  const [optInLeaderboard, setOptInLeaderboard] = useState(false);
  const [submittingVerify, setSubmittingVerify] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [verifyResult, setVerifyResult] =
    useState<ApiOneShotVerifyResponse | null>(null);
  const [liveRegistryDoc, setLiveRegistryDoc] =
    useState<PublisherKeyRegistryDocument>(DEMO_REGISTRY_DOCUMENT);

  const configuredApiUrl = getConfiguredApiBaseUrl();

  const applyStatementContent = async (text: string, fileName?: string) => {
    setRawStatementInput(text);
    if (!text.trim()) {
      setSniffedMeta(null);
      return;
    }
    const meta = await sniffBrokerageStatement(text, fileName);
    setSniffedMeta(meta);
    if (meta.family === "ibkr_flex_xml") {
      setSelectedBroker("ibkr");
      setIbkrTrack("offline_xml");
    } else if (meta.family !== "n170_proof_bundle") {
      setSelectedBroker("offline_csv");
    }
  };

  const handleStatementDrop = async (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDraggingStatement(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      await applyStatementContent(await file.text(), file.name);
    }
  };

  const buildDisclosedLeafNames = (): CanonicalLeafName[] => {
    const base: CanonicalLeafName[] = [
      "core_metrics",
      "indexed_curve",
      "reconciliation",
      "coaching_and_context",
    ];
    if (discloseBracket) base.push("capital_bracket");
    if (discloseAlpha) base.push("benchmark_alpha");
    if (discloseDelayedTrades) base.push("delayed_closed_trades");
    return base;
  };

  const handleLiveStatementVerify = async () => {
    if (!rawStatementInput.trim()) {
      setVerifyError(
        "Drop or paste a brokerage statement (XML / CSV / HTML) or specimen first.",
      );
      return;
    }
    setSubmittingVerify(true);
    setVerifyError(null);
    try {
      const meta =
        sniffedMeta ?? (await sniffBrokerageStatement(rawStatementInput));
      const [apiResp, regInfo] = await Promise.all([
        submitOneShotVerification({
          broker_id: meta.apiBrokerId,
          raw_statement: rawStatementInput,
          csv_format: meta.apiCsvFormat,
          disclose_leaf_names: buildDisclosedLeafNames(),
          publish_proof: publishProof,
          opt_in_leaderboard: publishProof && optInLeaderboard,
        }),
        fetchActiveRegistryDocument(),
      ]);
      setLiveRegistryDoc(regInfo.registryDoc);
      setVerifyResult(apiResp);
    } catch (err) {
      setVerifyResult(null);
      setVerifyError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmittingVerify(false);
    }
  };

  const broker = BROKERS.find((b) => b.id === selectedBroker) ?? BROKERS[0]!;
  const allRequiredFlexChecked = IBKR_FLEX_60S_CHECKLIST.filter(
    (s) => s.requiredForReconciled,
  ).every((s) => Boolean(flexChecks[s.xmlTag]));

  let previewOrigin: OriginAssurance = sniffedMeta
    ? sniffedMeta.previewOrigin
    : broker.defaultOrigin;
  let previewScope: AccountScope = sniffedMeta
    ? sniffedMeta.previewScope
    : broker.accountScope;
  if (!sniffedMeta && selectedBroker === "ibkr" && ibkrTrack === "offline_xml") {
    previewOrigin = OriginAssurance.SELF_REPORTED;
    previewScope = AccountScope.UNKNOWN_OFFLINE_SCOPE;
  }

  const previewContinuity: ChainContinuityMode = enrollProspectiveChain
    ? ChainContinuityMode.PROSPECTIVE_CONTINUOUS
    : ChainContinuityMode.UNENROLLED_SINGLE_SNAPSHOT;

  const disclosedOptionalCount =
    Number(discloseBracket) + Number(discloseAlpha) + Number(discloseDelayedTrades);

  return (
    <div className="bg-institutional-grid">
      <div className="mx-auto max-w-7xl space-y-8 px-4 py-10 sm:px-6 lg:px-8">
        {/* Masthead */}
        <div className="flex flex-col justify-between gap-4 border-b border-hairline pb-6 lg:flex-row lg:items-end">
          <div className="max-w-3xl space-y-2">
            <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
              <span className="badge-emerald rounded px-2 py-0.5 font-semibold uppercase tracking-wider">
                Strictly Read-Only • Zero Order / Withdrawal Scope
              </span>
              <span className="text-ink-muted">•</span>
              <span className="text-signal-champagne">
                Zero-Dropdown Universal Auto-Detect + RLIMIT_CORE=0 Isolation
              </span>
            </div>
            <h1 className="editorial-serif text-3xl text-ink sm:text-4xl">
              Universal Auto-Detect Dropzone &amp; Read-Only Connect Studio
            </h1>
            <p className="text-sm text-ink-secondary">
              Drop any brokerage export or SaaS journal CSV for zero-dropdown format
              detection in browser memory, or connect a live read-only OAuth / MPC-TLS
              witness channel.
            </p>
          </div>

          <div className="flex items-center gap-2 font-mono text-xs">
            <span className="rounded border border-hairline-strong bg-panel px-3 py-1.5 text-ink-secondary">
              Zero Dropdowns • 8 Signatures Auto-Sniffed
            </span>
          </div>
        </div>

        {/* ====================================================================
            HERO: UNIVERSAL ZERO-DROPDOWN AUTO-DETECT DROPZONE + 1-CLICK MIGRATION
            ==================================================================== */}
        <section className="inst-panel rounded-md p-5 sm:p-6">
          <div className="flex flex-col justify-between gap-3 border-b border-hairline pb-4 lg:flex-row lg:items-center">
            <div>
              <span className="font-mono text-[10.5px] font-semibold uppercase tracking-widest text-signal-emerald">
                Zero-Dropdown Browser Signature Sniffer
              </span>
              <h2 className="editorial-serif mt-0.5 text-2xl text-ink">
                Drop IBKR Flex XML, DEGIRO (EN/NL/DE), Robinhood, Schwab, MT4/MT5,
                Tradovate, or TraderSync / TradeZella
              </h2>
            </div>

            <span className="rounded border border-hairline-strong bg-elevated px-3 py-1.5 font-mono text-[11px] text-ink-secondary">
              {configuredApiUrl
                ? `Isolated Worker: ${configuredApiUrl}`
                : "100% Local WebCrypto SHA-256 Inspection"}
            </span>
          </div>

          {/* 1-Click Specimen Pills (Including 1-Click Leave TraderSync / TradeZella Migration) */}
          <div className="mt-4 flex flex-wrap items-center gap-2 font-mono text-[11px]">
            <span className="text-ink-muted">Test Instant Signature Sniffer:</span>
            {(
              Object.entries(SYNTHETIC_DROPZONE_SPECIMENS) as [
                keyof typeof SYNTHETIC_DROPZONE_SPECIMENS,
                (typeof SYNTHETIC_DROPZONE_SPECIMENS)[keyof typeof SYNTHETIC_DROPZONE_SPECIMENS],
              ][]
            ).map(([specKey, spec]) => {
              const isMigration = specKey === "tradezella_migration";
              return (
                <button
                  key={specKey}
                  type="button"
                  onClick={() => void applyStatementContent(spec.content)}
                  className={`inline-flex items-center gap-1.5 rounded border px-2.5 py-1.5 transition ${
                    isMigration
                      ? "border-signal-champagne-border bg-signal-champagne-bg font-semibold text-signal-champagne hover:border-signal-champagne"
                      : "border-hairline-strong bg-elevated text-ink-secondary hover:border-signal-emerald hover:text-ink"
                  }`}
                >
                  {isMigration ? (
                    <Sparkles className="h-3.5 w-3.5" />
                  ) : (
                    <FileCode2 className="h-3.5 w-3.5 text-signal-emerald" />
                  )}
                  <span>{spec.label}</span>
                </button>
              );
            })}
          </div>

          {/* Zero-Dropdown Drag-and-Drop Zone */}
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setIsDraggingStatement(true);
            }}
            onDragLeave={() => setIsDraggingStatement(false)}
            onDrop={(e) => void handleStatementDrop(e)}
            className={`mt-4 rounded-md border border-dashed p-5 transition ${
              isDraggingStatement
                ? "border-signal-emerald bg-signal-emerald-bg"
                : "border-hairline-strong bg-canvas"
            }`}
          >
            <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
              <div className="flex items-start gap-3">
                <Upload className="mt-0.5 h-5 w-5 shrink-0 text-signal-champagne" />
                <div>
                  <p className="text-xs font-semibold text-ink sm:text-sm">
                    Drag &amp; drop any brokerage statement or journal export — zero
                    format dropdowns required
                  </p>
                  <p className="mt-0.5 text-[11.5px] text-ink-muted">
                    Automatically fingerprints IBKR Flex XML, DEGIRO (EN / NL / DE),
                    Robinhood, Schwab, MT4/MT5 HTML &amp; CSV, Tradovate Futures CSV,
                    and 1-Click Leave TraderSync / TradeZella migrations.
                  </p>
                </div>
              </div>

              <label className="inline-flex shrink-0 cursor-pointer items-center gap-2 rounded border border-signal-emerald bg-signal-emerald px-4 py-2 font-mono text-xs font-semibold text-canvas transition hover:opacity-90">
                <span>Drop or Choose Any File</span>
                <input
                  type="file"
                  accept=".xml,.csv,.html,.htm,.json,text/xml,text/csv,text/html,application/json"
                  className="hidden"
                  onChange={async (e) => {
                    const file = e.target.files?.[0];
                    if (file) {
                      await applyStatementContent(await file.text(), file.name);
                    }
                  }}
                />
              </label>
            </div>

            {/* Live Sniffer Inspection Telemetry Card */}
            {sniffedMeta && (
              <div className="mt-4 space-y-3 rounded border border-hairline-strong bg-panel p-4 font-mono text-xs tabular-nums">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    {sniffedMeta.paperAccountRejected ? (
                      <XCircle className="h-4 w-4 text-signal-vermilion" />
                    ) : (
                      <CheckCircle2 className="h-4 w-4 text-signal-emerald" />
                    )}
                    <span className="font-semibold text-ink">
                      Auto-Detected: {sniffedMeta.formatLabel}
                    </span>
                    {sniffedMeta.detectedLocale && (
                      <span className="badge-champagne rounded px-2 py-0.5 text-[10px]">
                        LOCALE: {sniffedMeta.detectedLocale}
                      </span>
                    )}
                  </div>
                  <span className="text-[11px] text-ink-muted">
                    {sniffedMeta.byteLength.toLocaleString()} bytes • SHA-256:{" "}
                    {sniffedMeta.sha256Hex.slice(0, 18)}…
                  </span>
                </div>

                {/* Transparent Badge Preview (Crucial for Journal Migration & Offline Exports) */}
                <div className="grid grid-cols-1 gap-2 rounded border border-hairline bg-elevated p-3 sm:grid-cols-3">
                  <div>
                    <span className="block text-[9.5px] uppercase text-ink-muted">
                      Preview Origin Badge
                    </span>
                    <span className="mt-0.5 inline-block font-semibold text-signal-ochre">
                      {sniffedMeta.previewOrigin.toUpperCase()} (
                      {ORIGIN_ASSURANCE_META[sniffedMeta.previewOrigin].shortLabel})
                    </span>
                  </div>
                  <div>
                    <span className="block text-[9.5px] uppercase text-ink-muted">
                      Preview Reconciliation Badge
                    </span>
                    <span
                      className={`mt-0.5 inline-block font-semibold ${
                        sniffedMeta.previewReconciliation ===
                        "reconciled_within_tolerance"
                          ? "text-signal-emerald"
                          : "text-signal-ochre"
                      }`}
                    >
                      {sniffedMeta.previewReconciliation.toUpperCase()} (
                      {
                        RECONCILIATION_STATUS_META[sniffedMeta.previewReconciliation]
                          .shortLabel
                      }
                      )
                    </span>
                  </div>
                  <div>
                    <span className="block text-[9.5px] uppercase text-ink-muted">
                      Preview Account Scope
                    </span>
                    <span className="mt-0.5 inline-block font-semibold text-ink">
                      {ACCOUNT_SCOPE_META[sniffedMeta.previewScope].shortLabel}
                    </span>
                  </div>
                </div>

                {/* Preserved Coaching Tags on TraderSync / TradeZella Migration */}
                {sniffedMeta.importedJournalTags.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5 rounded border border-signal-emerald-border bg-signal-emerald-bg px-3 py-2 text-[11px]">
                    <span className="font-semibold text-signal-emerald">
                      Coaching Tags Preserved ({sniffedMeta.importedJournalTags.length}):
                    </span>
                    {sniffedMeta.importedJournalTags.map((tag) => (
                      <span
                        key={tag}
                        className="rounded border border-hairline-strong bg-panel px-2 py-0.5 text-ink"
                      >
                        #{tag}
                      </span>
                    ))}
                  </div>
                )}

                <div className="flex flex-wrap items-center gap-1.5 text-[10.5px]">
                  {sniffedMeta.sectionsFound.map((sec) => (
                    <span key={sec} className="badge-emerald rounded px-2 py-0.5">
                      ✓ {sec}
                    </span>
                  ))}
                  {sniffedMeta.missingSections.map((missing) => (
                    <span key={missing} className="badge-ochre rounded px-2 py-0.5">
                      Missing: {missing}
                    </span>
                  ))}
                  {sniffedMeta.paperAccountRejected && (
                    <span className="badge-vermilion rounded px-2 py-0.5 font-semibold">
                      PAPER / DEMO ACCOUNT DETECTED — LIVE GATE BLOCKS ISSUANCE
                    </span>
                  )}
                </div>

                <p className="font-sans text-[11.5px] leading-relaxed text-ink-secondary">
                  {sniffedMeta.transparencyNotice}
                </p>
              </div>
            )}

            <textarea
              value={rawStatementInput}
              onChange={(e) => void applyStatementContent(e.target.value)}
              placeholder="Or paste raw IBKR Flex XML, DEGIRO/Robinhood/Schwab CSV, MT4/MT5 report, Tradovate CSV, or TraderSync/TradeZella export here..."
              spellCheck={false}
              className="mt-3 h-24 w-full rounded border border-hairline bg-panel p-3 font-mono text-[11px] text-ink focus:border-signal-emerald focus:outline-none"
            />

            <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
              <div className="flex flex-wrap items-center gap-4 text-xs text-ink-secondary">
                <label className="inline-flex cursor-pointer items-center gap-2">
                  <input
                    type="checkbox"
                    checked={publishProof}
                    onChange={(e) => setPublishProof(e.target.checked)}
                    className="accent-emerald-500"
                  />
                  <span>Publish redacted bundle to /p/[proofId]</span>
                </label>
                {publishProof && (
                  <label className="inline-flex cursor-pointer items-center gap-2">
                    <input
                      type="checkbox"
                      checked={optInLeaderboard}
                      onChange={(e) => setOptInLeaderboard(e.target.checked)}
                      className="accent-emerald-500"
                    />
                    <span>List on Verified Registry</span>
                  </label>
                )}
              </div>

              <button
                type="button"
                disabled={
                  submittingVerify ||
                  !configuredApiUrl ||
                  Boolean(sniffedMeta?.paperAccountRejected)
                }
                onClick={() => void handleLiveStatementVerify()}
                className="rounded border border-signal-emerald bg-signal-emerald px-4 py-2 font-mono text-xs font-semibold text-canvas transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-45"
              >
                {submittingVerify
                  ? "Running RLIMIT_CORE=0 Worker…"
                  : "Issue Signed .verify.json Bundle"}
              </button>
            </div>

            {verifyError && (
              <div className="mt-3 rounded border border-signal-vermilion-border bg-signal-vermilion-bg p-3 font-mono text-xs text-signal-vermilion">
                Verification Error: {verifyError}
              </div>
            )}

            {verifyResult && (
              <div className="mt-4 space-y-4">
                <div className="rounded border border-signal-emerald-border bg-signal-emerald-bg p-3.5 font-mono text-xs text-ink tabular-nums">
                  ISOLATED WORKER RECEIPT • pid={verifyResult.isolation_receipt.worker_pid} •{" "}
                  RLIMIT_CORE={verifyResult.isolation_receipt.rlimit_core_soft}/
                  {verifyResult.isolation_receipt.rlimit_core_hard} • db_rows=
                  {verifyResult.isolation_receipt.persistent_rows_written}
                </div>
                <TearSheetView
                  bundle={verifyResult.proof_bundle}
                  registryDoc={liveRegistryDoc}
                  title={`Issued Proof Bundle • ${verifyResult.proof_bundle.proof_id}`}
                />
              </div>
            )}
          </div>
        </section>

        {/* ====================================================================
            COLLAPSIBLE IBKR FLEX QUERY 60-SECOND SETUP CHECKLIST (ALL 9 SECTIONS)
            ==================================================================== */}
        <section className="inst-panel rounded-md p-5 sm:p-6">
          <button
            type="button"
            onClick={() => setChecklistOpen((v) => !v)}
            aria-expanded={checklistOpen}
            className="flex w-full items-center justify-between gap-3 text-left"
          >
            <div>
              <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] text-signal-champagne">
                <Clock className="h-3.5 w-3.5" />
                <span className="font-semibold uppercase tracking-wider">
                  IBKR Flex Query 60-Second Setup Checklist (All 9 Sections + 6h Expiry + IP
                  Restriction)
                </span>
              </div>
              <h2 className="editorial-serif mt-0.5 text-xl text-ink sm:text-2xl">
                Interactive Brokers Activity Flex XML v3 Complete Reconciliation Spec
              </h2>
            </div>

            <span className="inline-flex shrink-0 items-center gap-1.5 rounded border border-hairline-strong bg-elevated px-3 py-1.5 font-mono text-xs text-ink">
              <span>{checklistOpen ? "Collapse" : "Expand 9-Section Checklist"}</span>
              {checklistOpen ? (
                <ChevronUp className="h-3.5 w-3.5" />
              ) : (
                <ChevronDown className="h-3.5 w-3.5" />
              )}
            </span>
          </button>

          {checklistOpen && (
            <div className="mt-4 space-y-4 border-t border-hairline pt-4">
              <div className="flex flex-wrap items-center justify-between gap-2 rounded border border-signal-emerald-border bg-signal-emerald-bg px-3.5 py-2.5 font-mono text-xs">
                <span className="font-semibold text-signal-emerald">
                  Web Service Token Security: Set Token Expiry = 6 Hours &amp; Enable IP
                  Restriction (CIDR Lock)
                </span>
                <span className="text-[11px] text-ink-secondary">
                  Query params <code className="text-ink">t=</code> &amp;{" "}
                  <code className="text-ink">q=</code> redacted before MPC-TLS witness
                </span>
              </div>

              <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
                {IBKR_FLEX_60S_CHECKLIST.map((sec) => {
                  const checked = Boolean(flexChecks[sec.xmlTag]);
                  return (
                    <label
                      key={sec.id}
                      className={`flex cursor-pointer items-start gap-2.5 rounded border p-3 text-xs transition ${
                        checked
                          ? "border-signal-emerald-border bg-elevated"
                          : "border-signal-ochre-border bg-signal-ochre-bg"
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() =>
                          setFlexChecks((prev) => ({
                            ...prev,
                            [sec.xmlTag]: !prev[sec.xmlTag],
                          }))
                        }
                        className="mt-0.5 accent-emerald-500"
                      />
                      <div>
                        <div className="flex flex-wrap items-center gap-1.5 font-mono">
                          <span className="rounded bg-panel px-1.5 py-0.5 text-[10px] text-signal-champagne tabular-nums">
                            {sec.stepTime}
                          </span>
                          <span className="font-semibold text-ink">{sec.xmlTag}</span>
                        </div>
                        <p className="mt-1 text-[11px] leading-relaxed text-ink-secondary">
                          {sec.purpose}
                        </p>
                      </div>
                    </label>
                  );
                })}
              </div>

              {!allRequiredFlexChecked && (
                <div className="flex items-center gap-2 rounded border border-signal-ochre-border bg-signal-ochre-bg px-3 py-2 font-mono text-xs text-signal-ochre">
                  <ShieldAlert className="h-4 w-4 shrink-0" />
                  <span>
                    Omitting any mandatory section causes ReconciliationReport to flag
                    INSUFFICIENT_SECTIONS instead of RECONCILED_WITHIN_TOLERANCE.
                  </span>
                </div>
              )}
            </div>
          )}
        </section>

        {/* ====================================================================
            STEP 1: Read-Only Live Broker & OAuth Catalog (Includes cTrader Scope: ACCOUNTS)
            ==================================================================== */}
        <section className="inst-panel rounded-md p-5 sm:p-6">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-hairline pb-4">
            <div>
              <span className="font-mono text-[11px] font-semibold uppercase tracking-widest text-signal-champagne">
                Live API &amp; Witnessed Channels
              </span>
              <h2 className="editorial-serif mt-0.5 text-2xl text-ink">
                Read-Only Brokerage OAuth &amp; MPC-TLS Catalog
              </h2>
            </div>
            <span className="font-mono text-xs text-ink-muted">
              Honest provider approval pills • Zero credential scrapers
            </span>
          </div>

          <div className="mt-5 grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-4">
            {BROKERS.map((item) => {
              const active = item.id === selectedBroker;
              const pillClass =
                item.statusVariant === "emerald"
                  ? "badge-emerald"
                  : item.statusVariant === "champagne"
                    ? "badge-champagne"
                    : item.statusVariant === "ochre"
                      ? "badge-ochre"
                      : "badge-neutral";
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setSelectedBroker(item.id)}
                  className={`flex flex-col justify-between rounded border p-4 text-left transition ${
                    active
                      ? "border-signal-emerald bg-elevated ring-1 ring-signal-emerald"
                      : "border-hairline-strong bg-canvas hover:border-ink-muted"
                  }`}
                >
                  <div>
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <span className="text-sm font-semibold tracking-telemetry text-ink">
                          {item.name}
                        </span>
                        <p className="font-mono text-[10.5px] text-ink-muted">
                          {item.category}
                        </p>
                      </div>
                      <span
                        className={`shrink-0 rounded px-2 py-0.5 font-mono text-[9.5px] font-semibold ${pillClass}`}
                      >
                        {item.statusPill}
                      </span>
                    </div>
                    <p className="mt-2.5 text-xs leading-relaxed text-ink-secondary">
                      {item.securityNote}
                    </p>
                  </div>

                  <div className="mt-3 flex items-center justify-between border-t border-hairline pt-2 font-mono text-[10px] text-ink-muted">
                    <span>{ORIGIN_ASSURANCE_META[item.defaultOrigin].shortLabel}</span>
                    <span>{ACCOUNT_SCOPE_META[item.accountScope].shortLabel}</span>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Live Read-Only Cryptographic Scope-Check Indicator */}
          <div className="mt-5 rounded border border-hairline-strong bg-elevated p-4">
            <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
              <div className="flex items-center gap-2.5">
                {simulateUnsafeWriteKey ? (
                  <XCircle className="h-4 w-4 shrink-0 text-signal-vermilion" />
                ) : (
                  <ShieldCheck className="h-4 w-4 shrink-0 text-signal-emerald" />
                )}
                <div>
                  <span className="font-mono text-xs font-semibold text-ink">
                    Live Pre-Fetch Read-Only Scope Gate (cTrader{" "}
                    <code className="text-signal-emerald">Scope: ACCOUNTS</code> / CEX
                    Bitmask)
                  </span>
                  <p className="text-[11.5px] text-ink-secondary">
                    Introspects OAuth / API capability bits before reading any ledger
                    endpoint; immediately aborts if{" "}
                    <code className="text-ink">Scope: TRADING</code> or withdrawal scopes
                    exist.
                  </p>
                </div>
              </div>

              <button
                type="button"
                onClick={() => setSimulateUnsafeWriteKey((v) => !v)}
                className={`shrink-0 rounded border px-3 py-1.5 font-mono text-[11px] font-medium transition ${
                  simulateUnsafeWriteKey
                    ? "border-signal-vermilion bg-signal-vermilion-bg text-signal-vermilion"
                    : "border-hairline-strong bg-panel text-ink-secondary hover:border-signal-champagne hover:text-ink"
                }`}
              >
                {simulateUnsafeWriteKey
                  ? "Reset to Read-Only Key"
                  : "Test Unsafe Write-Key Abort"}
              </button>
            </div>

            <div className="mt-3 grid grid-cols-2 gap-2 font-mono text-[11px] sm:grid-cols-4 tabular-nums">
              <ScopeBit label="oauth_scope" allowed value="ACCOUNTS (Read-Only)" />
              <ScopeBit
                label="spot_or_margin_trade"
                allowed={!simulateUnsafeWriteKey}
                value={simulateUnsafeWriteKey ? "TRADING (ABORT)" : "false"}
              />
              <ScopeBit
                label="withdraw_or_transfer"
                allowed={!simulateUnsafeWriteKey}
                value="false"
              />
              <ScopeBit
                label="verdict"
                allowed={!simulateUnsafeWriteKey}
                value={simulateUnsafeWriteKey ? "HARD_ABORT_403" : "SCOPE_VERIFIED"}
              />
            </div>
          </div>

          {/* Dual-Track IBKR Provenance Selector */}
          {selectedBroker === "ibkr" && (
            <div className="mt-5 rounded border border-hairline-strong bg-canvas p-4">
              <div className="flex flex-wrap items-center justify-between gap-2 pb-3">
                <span className="font-mono text-xs font-semibold text-ink">
                  IBKR Provenance Channel
                </span>
                <button
                  type="button"
                  onClick={() => setIbkrOauthLivePreview((v) => !v)}
                  className="rounded border border-hairline-strong bg-panel px-2.5 py-1 font-mono text-[11px] text-ink-secondary hover:text-ink"
                >
                  Third-Party OAuth Slot:{" "}
                  <span
                    className={
                      ibkrOauthLivePreview ? "text-signal-emerald" : "text-signal-ochre"
                    }
                  >
                    {ibkrOauthLivePreview ? "Live" : "Pending Provider Approval"}
                  </span>
                </button>
              </div>
              <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2 lg:grid-cols-4">
                <TrackPill
                  active={ibkrTrack === "flex_wizard"}
                  onClick={() => setIbkrTrack("flex_wizard")}
                  title="1. Flex v3 Guided Token"
                  badge="LIVE • 6h + IP LOCK"
                  variant="emerald"
                  desc="ndcdyn.interactivebrokers.com read-only query with 6h expiry & CIDR lock."
                />
                <TrackPill
                  active={ibkrTrack === "local_cli"}
                  onClick={() => setIbkrTrack("local_cli")}
                  title="2. Local Gateway CLI"
                  badge="LIVE • DAY-1"
                  variant="emerald"
                  desc="Authenticated local Client Portal Gateway + k>=2 disjoint MPC-TLS witnesses."
                />
                <TrackPill
                  active={ibkrTrack === "oauth"}
                  onClick={() => setIbkrTrack("oauth")}
                  title="3. Institutional OAuth 2.0"
                  badge={ibkrOauthLivePreview ? "LIVE" : "PENDING APPROVAL"}
                  variant={ibkrOauthLivePreview ? "emerald" : "ochre"}
                  desc="Direct OAuth read-only portfolio & sub-account enumeration."
                />
                <TrackPill
                  active={ibkrTrack === "offline_xml"}
                  onClick={() => setIbkrTrack("offline_xml")}
                  title="4. Air-Gapped XML Drop"
                  badge="SELF-REPORTED"
                  variant="neutral"
                  desc="Offline XML reconciliation & coaching without live notary claims."
                />
              </div>
            </div>
          )}
        </section>

        {/* ====================================================================
            STEP 2 & STEP 3: Storage Isolation + Salted Merkle Disclosure
            ==================================================================== */}
        <section className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          <div className="inst-panel space-y-4 rounded-md p-5 lg:col-span-6">
            <div className="border-b border-hairline pb-3">
              <span className="font-mono text-[11px] font-semibold uppercase tracking-widest text-signal-champagne">
                Subprocess Isolation &amp; Salted Merkle Redaction
              </span>
              <h2 className="editorial-serif mt-0.5 text-2xl text-ink">
                Retention Mode &amp; Optional Leaf Disclosure
              </h2>
            </div>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <button
                type="button"
                onClick={() => setRetentionMode("no_persistent_storage")}
                className={`rounded border p-3.5 text-left transition ${
                  retentionMode === "no_persistent_storage"
                    ? "border-signal-emerald bg-elevated ring-1 ring-signal-emerald"
                    : "border-hairline-strong bg-canvas hover:border-ink-muted"
                }`}
              >
                <div className="flex items-center justify-between gap-1">
                  <span className="text-xs font-semibold text-ink">
                    Zero DB Storage
                  </span>
                  <span className="badge-emerald rounded px-1.5 py-0.5 font-mono text-[9.5px] font-semibold">
                    0 ROWS
                  </span>
                </div>
                <p className="mt-1.5 text-[11px] leading-relaxed text-ink-secondary">
                  Single-use worker (<code className="text-ink">RLIMIT_CORE=0</code>);
                  raw statement zeroized on exit.
                </p>
              </button>

              <button
                type="button"
                onClick={() => setRetentionMode("opt_in_encrypted_sync")}
                className={`rounded border p-3.5 text-left transition ${
                  retentionMode === "opt_in_encrypted_sync"
                    ? "border-signal-champagne bg-elevated ring-1 ring-signal-champagne"
                    : "border-hairline-strong bg-canvas hover:border-ink-muted"
                }`}
              >
                <div className="flex items-center justify-between gap-1">
                  <span className="text-xs font-semibold text-ink">
                    Encrypted Chain Sync
                  </span>
                  <span className="badge-champagne rounded px-1.5 py-0.5 font-mono text-[9.5px] font-semibold">
                    AES-256-GCM
                  </span>
                </div>
                <p className="mt-1.5 text-[11px] leading-relaxed text-ink-secondary">
                  Automated prospective chain cadence with signed disconnect destruction
                  receipt.
                </p>
              </button>
            </div>

            <div className="space-y-2.5 pt-1">
              <DisclosureToggle
                checked={discloseBracket}
                onChange={() => setDiscloseBracket((v) => !v)}
                title="Reveal Coarse Capital Tier (capital_bracket)"
                desc="Discloses logarithmic USD bracket while keeping exact dollar NAV unrevealed."
              />
              <DisclosureToggle
                checked={discloseAlpha}
                onChange={() => setDiscloseAlpha((v) => !v)}
                title="Reveal Benchmark Excess Alpha (benchmark_alpha)"
                desc="Publishes flow-matched benchmark comparison, information ratio, and beta."
              />
              <DisclosureToggle
                checked={discloseDelayedTrades}
                onChange={() => setDiscloseDelayedTrades((v) => !v)}
                title="Reveal 7-Day Delayed Closed Trades (delayed_closed_trades)"
                desc="Enforces a 7-day front-running embargo and strips share/dollar quantities."
              />
              <DisclosureToggle
                checked={enrollProspectiveChain}
                onChange={() => setEnrollProspectiveChain((v) => !v)}
                title="Enroll in <=24h Genesis Prospective Continuous Chain"
                desc="Commits blinded_account_tag + immutable cadence to the C2SP log."
                highlight
              />
            </div>
          </div>

          <div className="inst-panel flex flex-col justify-between rounded-md p-5 lg:col-span-6">
            <div className="space-y-3.5">
              <div className="flex items-center justify-between font-mono text-xs">
                <span className="font-semibold uppercase tracking-wider text-signal-champagne">
                  Resulting Bundle Assurance Profile
                </span>
                <span className="text-signal-emerald tabular-nums">
                  {4 + disclosedOptionalCount}/7 leaves disclosed
                </span>
              </div>

              <div className="space-y-2 rounded border border-hairline bg-elevated p-4 font-mono text-xs tabular-nums">
                <div className="flex justify-between gap-2">
                  <span className="text-ink-muted">effective_origin:</span>
                  <span className="font-semibold text-signal-champagne">
                    {ORIGIN_ASSURANCE_META[previewOrigin].shortLabel}
                  </span>
                </div>
                <div className="flex justify-between gap-2">
                  <span className="text-ink-muted">account_scope:</span>
                  <span className="text-ink">
                    {ACCOUNT_SCOPE_META[previewScope].shortLabel}
                  </span>
                </div>
                <div className="flex justify-between gap-2">
                  <span className="text-ink-muted">chain_continuity:</span>
                  <span className="text-signal-emerald">
                    {CHAIN_CONTINUITY_META[previewContinuity].shortLabel}
                  </span>
                </div>
                <div className="flex justify-between gap-2">
                  <span className="text-ink-muted">retention_mode:</span>
                  <span className="text-ink">{retentionMode}</span>
                </div>
              </div>

              <div className="rounded border border-hairline bg-elevated p-3.5 font-mono text-[11px] text-ink-secondary">
                <div className="flex items-center gap-1.5 text-[10px] uppercase text-ink-muted">
                  <Lock className="h-3 w-3 text-signal-emerald" />
                  <span>Air-Gapped Local CLI Equivalent</span>
                </div>
                <p className="mt-1.5 break-all text-signal-emerald">
                  n170-verify ingest --auto-detect statement_export
                  {!discloseBracket ? " --redact capital_bracket" : ""}
                  {!discloseAlpha ? " --redact benchmark_alpha" : ""}
                  {!discloseDelayedTrades ? " --redact delayed_closed_trades" : ""}
                </p>
              </div>
            </div>

            <div className="mt-5 flex flex-wrap items-center gap-2.5">
              <Link
                href={
                  selectedBroker === "alpaca" || !discloseBracket
                    ? "/p/prf-coach-studio-009"
                    : !allRequiredFlexChecked
                      ? "/p/prf-xray-residual-004"
                      : "/p/prf-inst-alpha-012"
                }
                className="inline-flex flex-1 items-center justify-center rounded border border-signal-emerald bg-signal-emerald px-4 py-2.5 font-mono text-xs font-semibold text-canvas transition hover:opacity-90"
              >
                Preview Matching LP Tear Sheet →
              </Link>
              <Link
                href="/verify"
                className="inline-flex items-center justify-center rounded border border-hairline-strong bg-panel px-4 py-2.5 font-mono text-xs text-ink transition hover:border-signal-champagne"
              >
                Verify .json
              </Link>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

function ScopeBit({
  label,
  allowed,
  value,
}: {
  label: string;
  allowed: boolean;
  value: string;
}) {
  return (
    <div className="flex items-center justify-between rounded border border-hairline bg-panel px-2.5 py-2">
      <span className="truncate text-ink-muted">{label}</span>
      <span
        className={`ml-2 font-semibold ${
          allowed ? "text-signal-emerald" : "text-signal-vermilion"
        }`}
      >
        {value}
      </span>
    </div>
  );
}

function TrackPill({
  active,
  onClick,
  title,
  badge,
  variant,
  desc,
}: {
  active: boolean;
  onClick: () => void;
  title: string;
  badge: string;
  variant: "emerald" | "ochre" | "neutral";
  desc: string;
}) {
  const bStyle =
    variant === "emerald"
      ? "badge-emerald"
      : variant === "ochre"
        ? "badge-ochre"
        : "badge-neutral";

  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded border p-3.5 text-left transition ${
        active
          ? "border-signal-emerald bg-elevated ring-1 ring-signal-emerald"
          : "border-hairline bg-panel hover:border-ink-muted"
      }`}
    >
      <span
        className={`inline-block rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold ${bStyle}`}
      >
        {badge}
      </span>
      <p className="mt-1.5 text-xs font-semibold text-ink">{title}</p>
      <p className="mt-1 text-[11px] leading-relaxed text-ink-secondary">{desc}</p>
    </button>
  );
}

function DisclosureToggle({
  checked,
  onChange,
  title,
  desc,
  highlight = false,
}: {
  checked: boolean;
  onChange: () => void;
  title: string;
  desc: string;
  highlight?: boolean;
}) {
  return (
    <label
      className={`flex cursor-pointer items-start gap-3 rounded border p-3 transition ${
        checked
          ? highlight
            ? "border-signal-champagne bg-signal-champagne-bg"
            : "border-hairline-strong bg-canvas"
          : "border-hairline bg-elevated/50"
      }`}
    >
      <input
        type="checkbox"
        checked={checked}
        onChange={onChange}
        className="mt-1 accent-emerald-500"
      />
      <div>
        <span className="text-xs font-semibold text-ink">{title}</span>
        <p className="mt-0.5 text-[11px] leading-relaxed text-ink-secondary">{desc}</p>
      </div>
    </label>
  );
}
