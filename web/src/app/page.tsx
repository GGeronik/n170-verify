"use client";

import {
  ArrowRight,
  Calculator,
  MessageSquareHeart,
  ShieldCheck,
  Swords,
  Upload,
} from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import {
  LiveProofDissector,
  type DissectorSpecimenConfig,
  type SpecimenId,
} from "@/components/LiveProofDissector.tsx";
import { TearSheetView, type StudioTabId } from "@/components/TearSheetView.tsx";
import type { VerifyProofBundle } from "@/lib/contracts.ts";
import {
  BUNDLE_COACHING_STUDIO_FULL,
  BUNDLE_DISCREPANCY_XRAY,
  BUNDLE_INSTITUTIONAL_FUND,
  BUNDLE_INSTITUTIONAL_SEQ0,
  BUNDLE_INSTITUTIONAL_SEQ1,
  DEMO_CONTINUITY_LOG_LEAVES,
  DEMO_REGISTRY_DOCUMENT,
} from "@/lib/demoFixtures.ts";

const DISSECTOR_SPECIMENS: readonly (DissectorSpecimenConfig & {
  defaultTab: StudioTabId;
})[] = [
  {
    id: "fund_chain_12",
    tabLabel: "Prospective Continuous Fund Chain #12",
    shortTag: "SPECIMEN 01 • FUND CHAIN",
    strategyTitle: "Meridian Systematic Multi-Asset Master",
    subtitle:
      "k=3 Org/ASN-Disjoint MPC-TLS Notaries • Prospective Continuous Chain • All Enumerated Sub-Accounts",
    handle: "@meridian-systematic",
    rawBundle: BUNDLE_INSTITUTIONAL_FUND,
    chainHistory: [BUNDLE_INSTITUTIONAL_SEQ0, BUNDLE_INSTITUTIONAL_SEQ1],
    continuityLogLeaves: DEMO_CONTINUITY_LOG_LEAVES,
    defaultTab: "performance",
  },
  {
    id: "multicurrency_options",
    tabLabel: "Multi-Currency Options Portfolio",
    shortTag: "SPECIMEN 02 • OPTIONS & FX",
    strategyTitle: "Apex Multi-Currency Options & Catalyst Studio",
    subtitle:
      "k=2 Disjoint Notaries • Salted Selective-Disclosure Tier • 5-Part FX/Borrow Drag Waterfall",
    handle: "@apex-momentum-lab",
    rawBundle: BUNDLE_COACHING_STUDIO_FULL,
    chainHistory: [],
    defaultTab: "coaching",
  },
  {
    id: "nav_discrepancy",
    tabLabel: "Unexplained NAV Discrepancy Caught",
    shortTag: "SPECIMEN 03 • RESIDUAL CAUGHT",
    strategyTitle: "Event-Driven Tech Swing (Discrepancy X-Ray)",
    subtitle:
      "Single-Notary Dynamic Downgrade • +64.80 bps Missing-Section Residual Caught • T=22 PSR Gate",
    handle: "@swing-xray-audit",
    rawBundle: BUNDLE_DISCREPANCY_XRAY,
    chainHistory: [],
    defaultTab: "reconciliation",
  },
];

export default function LandingPage() {
  const [specimenId, setSpecimenId] = useState<SpecimenId>("fund_chain_12");
  const activeSpecimen =
    DISSECTOR_SPECIMENS.find((s) => s.id === specimenId) ?? DISSECTOR_SPECIMENS[0]!;
  const [liveWorkingBundle, setLiveWorkingBundle] = useState<VerifyProofBundle>(
    activeSpecimen.rawBundle,
  );

  const handleSelectSpecimen = (nextId: SpecimenId) => {
    setSpecimenId(nextId);
    const found = DISSECTOR_SPECIMENS.find((s) => s.id === nextId);
    if (found) {
      setLiveWorkingBundle(found.rawBundle);
    }
  };

  return (
    <div className="bg-institutional-grid">
      {/* Compact Swiss Editorial Masthead + Above-the-Fold Live Proof Dissector */}
      <section className="mx-auto max-w-7xl px-4 pt-8 pb-10 sm:px-6 lg:px-8">
        <div className="mb-6 flex flex-col justify-between gap-5 lg:flex-row lg:items-end">
          <div className="max-w-3xl space-y-2.5">
            <div className="inline-flex flex-wrap items-center gap-2 font-mono text-[11px]">
              <span className="badge-emerald rounded px-2 py-0.5 font-semibold uppercase tracking-wider">
                Apache-2.0 Open Standard
              </span>
              <span className="text-ink-muted">•</span>
              <span className="text-signal-champagne">
                RFC 8785 JCS + k&ge;2 Disjoint MPC-TLS + Salted 7-Leaf Merkle
              </span>
            </div>

            <h1 className="editorial-serif text-3xl leading-[1.08] text-ink sm:text-5xl">
              Cryptographic Performance Provenance &amp; Archival Due Diligence.
            </h1>

            <p className="max-w-2xl text-sm leading-relaxed text-ink-secondary sm:text-[15px]">
              Verify institutional track records and self-directed brokerage ledgers
              directly in <code className="text-ink">window.crypto.subtle</code> — zero
              screenshots, zero exact-dollar NAV leaks, zero unverifiable single-notary
              trust claims.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <Link
              href="/connect"
              className="inline-flex items-center gap-2 rounded border border-signal-emerald bg-signal-emerald px-4 py-2.5 font-mono text-xs font-semibold text-canvas transition hover:opacity-90"
            >
              <span>Connect Read-Only Broker</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
            <Link
              href="/verify"
              className="inline-flex items-center gap-1.5 rounded border border-hairline-strong bg-panel px-3.5 py-2.5 font-mono text-xs font-medium text-ink transition hover:border-signal-champagne"
            >
              <ShieldCheck className="h-3.5 w-3.5 text-signal-champagne" />
              <span>Air-Gapped Verifier</span>
            </Link>
          </div>
        </div>

        {/* Hero Experience 1: Interactive Above-the-Fold Live Proof Dissector */}
        <LiveProofDissector
          specimens={DISSECTOR_SPECIMENS}
          activeSpecimenId={specimenId}
          onSelectSpecimen={handleSelectSpecimen}
          registryDoc={DEMO_REGISTRY_DOCUMENT}
          onActiveBundleChange={setLiveWorkingBundle}
        />
      </section>

      {/* Full Interactive Institutional Tear Sheet Synchronized with Live Dissector */}
      <section className="mx-auto max-w-7xl px-4 pb-16 sm:px-6 lg:px-8">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2 border-b border-hairline pb-2.5">
          <div className="flex items-center gap-2 font-mono text-xs">
            <span className="text-signal-champagne font-semibold uppercase tracking-wider">
              Synchronized LP Tear-Sheet Studio
            </span>
            <span className="text-ink-muted">•</span>
            <span className="text-ink-secondary">
              Reflecting live Merkle redaction state of {liveWorkingBundle.proof_id}
            </span>
          </div>
          <Link
            href={`/p/${liveWorkingBundle.proof_id}`}
            className="font-mono text-xs text-signal-emerald underline-offset-4 hover:underline"
          >
            Open Dedicated Tear-Sheet Route (/p/{liveWorkingBundle.proof_id}) →
          </Link>
        </div>

        <TearSheetView
          bundle={liveWorkingBundle}
          registryDoc={DEMO_REGISTRY_DOCUMENT}
          chainHistory={activeSpecimen.chainHistory}
          continuityLogLeaves={activeSpecimen.continuityLogLeaves}
          title={activeSpecimen.strategyTitle}
          subtitle={activeSpecimen.subtitle}
          handle={activeSpecimen.handle}
          defaultTab={activeSpecimen.defaultTab}
        />
      </section>

      {/* Viral Acquisition & Zero-Login Tools Strip */}
      <section className="mx-auto max-w-7xl px-4 pb-14 sm:px-6 lg:px-8">
        <div className="mb-4 flex flex-wrap items-end justify-between gap-2">
          <div>
            <p className="font-mono text-[11px] font-semibold uppercase tracking-widest text-signal-emerald">
              Zero-Login Public Verification &amp; Econometric Suite
            </p>
            <h2 className="editorial-serif mt-0.5 text-2xl text-ink sm:text-3xl">
              Instant Econometric Reality Checks, Polite Invites &amp; Head-to-Head Duels
            </h2>
          </div>
          <span className="font-mono text-xs text-ink-muted">
            100% Client-Side WebCrypto • Shareable Debate Permalinks
          </span>
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Link
            href="/tools/plausibility"
            className="inst-panel group flex flex-col justify-between rounded-md p-4 transition hover:border-signal-emerald"
          >
            <div>
              <div className="flex items-center justify-between">
                <Calculator className="h-4 w-4 text-signal-emerald" />
                <span className="badge-emerald rounded px-2 py-0.5 font-mono text-[9.5px] font-semibold">
                  PSR + MinTRL
                </span>
              </div>
              <h3 className="mt-2.5 text-sm font-semibold text-ink group-hover:text-signal-emerald">
                Claim Plausibility &amp; MinTRL Buster
              </h3>
              <p className="mt-1 text-xs leading-relaxed text-ink-secondary">
                Test any claimed Sharpe against skewness, fat tails, and track-record
                days T with shareable Fintwit/Reddit query links.
              </p>
            </div>
            <span className="mt-3 inline-flex items-center gap-1 font-mono text-[11px] font-semibold text-signal-emerald">
              Open /tools/plausibility <ArrowRight className="h-3 w-3" />
            </span>
          </Link>

          <Link
            href="/challenge"
            className="inst-panel group flex flex-col justify-between rounded-md p-4 transition hover:border-signal-champagne"
          >
            <div>
              <div className="flex items-center justify-between">
                <MessageSquareHeart className="h-4 w-4 text-signal-champagne" />
                <span className="badge-champagne rounded px-2 py-0.5 font-mono text-[9.5px] font-semibold">
                  ZERO $ LEAK
                </span>
              </div>
              <h3 className="mt-2.5 text-sm font-semibold text-ink group-hover:text-signal-champagne">
                Polite Proof Challenge Generator
              </h3>
              <p className="mt-1 text-xs leading-relaxed text-ink-secondary">
                Diplomatic 1-click invitation card explaining how to prove % returns in
                60s while keeping $ NAV and live positions 100% private.
              </p>
            </div>
            <span className="mt-3 inline-flex items-center gap-1 font-mono text-[11px] font-semibold text-signal-champagne">
              Open /challenge <ArrowRight className="h-3 w-3" />
            </span>
          </Link>

          <Link
            href="/vs/demo-tls-alpha/demo-ibkr-flex"
            className="inst-panel group flex flex-col justify-between rounded-md p-4 transition hover:border-signal-emerald"
          >
            <div>
              <div className="flex items-center justify-between">
                <Swords className="h-4 w-4 text-signal-emerald" />
                <span className="badge-emerald rounded px-2 py-0.5 font-mono text-[9.5px] font-semibold">
                  DUAL WEBCRYPTO
                </span>
              </div>
              <h3 className="mt-2.5 text-sm font-semibold text-ink group-hover:text-signal-emerald">
                Head-to-Head Verified Arena
              </h3>
              <p className="mt-1 text-xs leading-relaxed text-ink-secondary">
                Synchronized Indexed-100 wealth &amp; underwater drawdown duels with
                automatic scope and origin comparability audits.
              </p>
            </div>
            <span className="mt-3 inline-flex items-center gap-1 font-mono text-[11px] font-semibold text-signal-emerald">
              Open /vs Duel <ArrowRight className="h-3 w-3" />
            </span>
          </Link>

          <Link
            href="/connect"
            className="inst-panel group flex flex-col justify-between rounded-md p-4 transition hover:border-signal-champagne"
          >
            <div>
              <div className="flex items-center justify-between">
                <Upload className="h-4 w-4 text-signal-champagne" />
                <span className="badge-champagne rounded px-2 py-0.5 font-mono text-[9.5px] font-semibold">
                  1-CLICK MIGRATE
                </span>
              </div>
              <h3 className="mt-2.5 text-sm font-semibold text-ink group-hover:text-signal-champagne">
                Universal Auto-Detect Dropzone
              </h3>
              <p className="mt-1 text-xs leading-relaxed text-ink-secondary">
                Zero-dropdown sniffer for IBKR Flex, DEGIRO, MT4/5, Tradovate, cTrader
                OAuth, and 1-Click Leave TraderSync / TradeZella.
              </p>
            </div>
            <span className="mt-3 inline-flex items-center gap-1 font-mono text-[11px] font-semibold text-signal-champagne">
              Open /connect <ArrowRight className="h-3 w-3" />
            </span>
          </Link>
        </div>
      </section>

      {/* Architectural Due-Diligence Matrix */}
      <section className="border-t border-hairline bg-panel/60 py-14">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="max-w-3xl">
            <p className="font-mono text-[11px] font-semibold uppercase tracking-widest text-signal-champagne">
              Institutional Due-Diligence Matrix
            </p>
            <h2 className="editorial-serif mt-1 text-2xl text-ink sm:text-3xl">
              Engineered for hedge-fund LP rooms and systematic traders
            </h2>
          </div>

          <div className="mt-6 overflow-x-auto rounded-md border border-hairline bg-panel">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-hairline bg-elevated font-mono text-[10.5px] uppercase tracking-wider text-ink-muted">
                <tr>
                  <th className="px-4 py-3.5">Verification Dimension</th>
                  <th className="px-4 py-3.5 text-signal-emerald">
                    N170 Verify v3 (Apache-2.0)
                  </th>
                  <th className="px-4 py-3.5">Legacy Trackers (Myfxbook / Kinfo)</th>
                  <th className="px-4 py-3.5">Paid SaaS Journals</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-hairline text-ink-secondary">
                <tr>
                  <td className="px-4 py-3 font-medium text-ink">Origin Assurance</td>
                  <td className="px-4 py-3 text-signal-emerald">
                    Dynamic k&ge;2 org/ASN-disjoint TLSNotary + Pinned Broker Ed25519 + C2SP
                  </td>
                  <td className="px-4 py-3 text-ink-muted">
                    Centralized database trust; opaque single-tier badge
                  </td>
                  <td className="px-4 py-3 text-ink-muted">
                    Unverified CSV/API uploads; zero cryptographic proof
                  </td>
                </tr>
                <tr>
                  <td className="px-4 py-3 font-medium text-ink">
                    Selective Disclosure &amp; Privacy
                  </td>
                  <td className="px-4 py-3 text-signal-emerald">
                    Indexed-100 curves + 256-bit salted 7-leaf RFC 8785 Merkle redaction
                  </td>
                  <td className="px-4 py-3 text-ink-muted">
                    Exposes raw dollar balances or live open positions
                  </td>
                  <td className="px-4 py-3 text-ink-muted">
                    Cloud-stored raw trade quantities
                  </td>
                </tr>
                <tr>
                  <td className="px-4 py-3 font-medium text-ink">
                    Survivorship &amp; Backfill Defense
                  </td>
                  <td className="px-4 py-3 text-signal-emerald">
                    Sub-account enumeration + 5 Prospective Chain invariants (&le;24h genesis)
                  </td>
                  <td className="px-4 py-3 text-ink-muted">
                    Vulnerable to deleting losing sub-accounts or cherry-picking windows
                  </td>
                  <td className="px-4 py-3 text-ink-muted">None</td>
                </tr>
                <tr>
                  <td className="px-4 py-3 font-medium text-ink">
                    Econometrics &amp; Execution Audit
                  </td>
                  <td className="px-4 py-3 text-signal-emerald">
                    GLM unsmoothing, PSR_GLM (T&ge;30), 5-part bps waterfall, Odean &amp; Ie
                  </td>
                  <td className="px-4 py-3 text-ink-muted">
                    Naive arithmetic return &amp; raw Sharpe; display ads
                  </td>
                  <td className="px-4 py-3 text-ink-muted">
                    $30–$80/mo closed subscription paywall
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </div>
  );
}
