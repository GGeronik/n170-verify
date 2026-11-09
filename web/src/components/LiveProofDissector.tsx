"use client";

import { CheckCircle2, EyeOff, Lock, ShieldAlert, ShieldCheck, Sparkles } from "lucide-react";
import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { redactProofBundleLeaves, verifyProofBundle } from "@/lib/browserVerify.ts";
import {
  computeMerkleTreeTopology,
  type MerkleTreeTopology,
} from "@/lib/ceremonyTelemetry.ts";
import {
  CAPITAL_BRACKET_LABELS,
  CANONICAL_LEAF_NAMES,
  LEAF_DISPLAY_META,
  ORIGIN_ASSURANCE_META,
  extractTypedLeaves,
  type BundleVerificationResult,
  type CanonicalLeafName,
  type ContinuityLogLeaf,
  type PublisherKeyRegistryDocument,
  type VerifyProofBundle,
} from "@/lib/contracts.ts";

export type SpecimenId = "fund_chain_12" | "multicurrency_options" | "nav_discrepancy";

export interface DissectorSpecimenConfig {
  id: SpecimenId;
  tabLabel: string;
  shortTag: string;
  strategyTitle: string;
  subtitle: string;
  handle: string;
  rawBundle: VerifyProofBundle;
  chainHistory: VerifyProofBundle[];
  continuityLogLeaves?: readonly ContinuityLogLeaf[];
}

export interface LiveProofDissectorProps {
  specimens: readonly DissectorSpecimenConfig[];
  activeSpecimenId: SpecimenId;
  onSelectSpecimen: (id: SpecimenId) => void;
  registryDoc: PublisherKeyRegistryDocument;
  onActiveBundleChange?: (workingBundle: VerifyProofBundle) => void;
}

const SHORT_LEAF_LABELS: Record<CanonicalLeafName, string> = {
  core_metrics: "L0 core",
  indexed_curve: "L1 curve",
  reconciliation: "L2 recon",
  coaching_and_context: "L3 coach",
  capital_bracket: "L4 tier",
  benchmark_alpha: "L5 alpha",
  delayed_closed_trades: "L6 trades",
};

/**
 * Computes which Level-1, Level-2, and Sibling nodes belong to the active leaf's
 * 7-leaf Merkle inclusion path (`[0,1] [2,3] [4,5] [6promoted]`).
 */
function getActiveInclusionNodes(leafIndex: number): {
  spineL1: number;
  siblingLeaf: number | null;
  spineL2: number;
  siblingL1: number;
  siblingL2: number;
} {
  if (leafIndex === 6) {
    // Leaf 6 promotes directly to Level1[3], pairs with Level1[2] (H45) -> Level2[1] (H456)
    return {
      spineL1: 3,
      siblingLeaf: null,
      spineL2: 1,
      siblingL1: 2,
      siblingL2: 0,
    };
  }
  const spineL1 = Math.floor(leafIndex / 2); // 0, 1, or 2
  const siblingLeaf = leafIndex % 2 === 0 ? leafIndex + 1 : leafIndex - 1;
  const spineL2 = spineL1 < 2 ? 0 : 1;
  const siblingL1 =
    spineL1 === 0 ? 1 : spineL1 === 1 ? 0 : 3; // H45 pairs with L6 (idx 3)
  const siblingL2 = spineL2 === 0 ? 1 : 0;
  return { spineL1, siblingLeaf, spineL2, siblingL1, siblingL2 };
}

export function LiveProofDissector({
  specimens,
  activeSpecimenId,
  onSelectSpecimen,
  registryDoc,
  onActiveBundleChange,
}: LiveProofDissectorProps) {
  const specimen =
    specimens.find((s) => s.id === activeSpecimenId) ?? specimens[0]!;

  const [hideDollarNav, setHideDollarNav] = useState(true);
  const [revealCapitalBracket, setRevealCapitalBracket] = useState(true);
  const [enforceFrontRunGuard, setEnforceFrontRunGuard] = useState(false);
  const [focusedLeaf, setFocusedLeaf] = useState<CanonicalLeafName>("capital_bracket");

  const [topology, setTopology] = useState<MerkleTreeTopology | null>(null);
  const [verification, setVerification] = useState<BundleVerificationResult | null>(null);
  const [verifyMs, setVerifyMs] = useState<number>(0);

  const workingBundle = useMemo(() => {
    const toRedact: CanonicalLeafName[] = [];
    if (!revealCapitalBracket) {
      toRedact.push("capital_bracket");
    }
    if (enforceFrontRunGuard) {
      toRedact.push("delayed_closed_trades");
    }
    return toRedact.length > 0
      ? redactProofBundleLeaves(specimen.rawBundle, toRedact)
      : specimen.rawBundle;
  }, [specimen.rawBundle, revealCapitalBracket, enforceFrontRunGuard]);

  useEffect(() => {
    onActiveBundleChange?.(workingBundle);
  }, [workingBundle, onActiveBundleChange]);

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      const t0 = performance.now();
      const [topo, res] = await Promise.all([
        computeMerkleTreeTopology(workingBundle),
        verifyProofBundle(workingBundle, {
          registryDoc,
          chainHistory: specimen.chainHistory,
          continuityLogLeaves: specimen.continuityLogLeaves ?? null,
        }),
      ]);
      const elapsed = Math.max(performance.now() - t0, 0.28);
      if (!cancelled) {
        setTopology(topo);
        setVerification(res);
        setVerifyMs(elapsed);
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
  }, [workingBundle, registryDoc, specimen]);

  const leaves = useMemo(() => extractTypedLeaves(workingBundle), [workingBundle]);
  const rawLeaves = useMemo(
    () => extractTypedLeaves(specimen.rawBundle),
    [specimen.rawBundle],
  );

  const focusedLeafIndex = Math.max(CANONICAL_LEAF_NAMES.indexOf(focusedLeaf), 0);
  const inclusion = getActiveInclusionNodes(focusedLeafIndex);
  const activeDisclosedObj = workingBundle.disclosed_leaves.find(
    (l) => l.leaf_name === focusedLeaf,
  );
  const activeUndisclosedHash = workingBundle.undisclosed_leaf_hashes?.[focusedLeaf];

  const bracketLabel = rawLeaves.capitalBracket
    ? CAPITAL_BRACKET_LABELS[rawLeaves.capitalBracket]
    : "$100K – $1M USD";

  const terminalIdx =
    leaves.coreMetrics != null
      ? (100 * (1 + leaves.coreMetrics.twr_decimal)).toFixed(2)
      : "100.00";

  return (
    <div className="inst-panel rounded-md p-4 shadow-2xl sm:p-6">
      {/* Row 1: Specimen Switcher */}
      <div className="flex flex-col justify-between gap-3 border-b border-hairline pb-4 lg:flex-row lg:items-center">
        <div className="flex items-center gap-2 font-mono text-[11px]">
          <span className="badge-champagne inline-flex items-center gap-1.5 rounded px-2 py-0.5 font-semibold uppercase tracking-wider">
            <Sparkles className="h-3 w-3" />
            Live Proof Dissector
          </span>
          <span className="text-ink-muted">
            Select signed specimen &amp; toggle salted Merkle leaves
          </span>
        </div>

        <div
          className="grid grid-cols-1 gap-1.5 sm:grid-cols-3"
          role="tablist"
          aria-label="Live Proof Specimens"
        >
          {specimens.map((sp) => {
            const active = sp.id === specimen.id;
            return (
              <button
                key={sp.id}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => onSelectSpecimen(sp.id)}
                className={`rounded border px-3 py-2 text-left transition ${
                  active
                    ? "border-signal-champagne bg-signal-champagne-bg text-ink"
                    : "border-hairline-strong bg-elevated text-ink-secondary hover:border-ink-muted hover:text-ink"
                }`}
              >
                <div className="flex items-center justify-between gap-2 font-mono text-[10px]">
                  <span
                    className={
                      active ? "font-semibold text-signal-champagne" : "text-ink-muted"
                    }
                  >
                    {sp.shortTag}
                  </span>
                  <span className="tabular-nums text-ink-muted">{sp.rawBundle.proof_id}</span>
                </div>
                <p className="mt-0.5 text-xs font-semibold tracking-telemetry text-ink">
                  {sp.tabLabel}
                </p>
              </button>
            );
          })}
        </div>
      </div>

      {/* Row 2: Live Salted Merkle Selective-Disclosure Switches */}
      <div className="mt-4 flex flex-col justify-between gap-3 rounded border border-hairline bg-elevated p-3.5 xl:flex-row xl:items-center">
        <div className="flex items-center gap-2 font-mono text-[11px]">
          <Lock className="h-3.5 w-3.5 text-signal-emerald" />
          <span className="font-semibold uppercase tracking-wider text-ink">
            Salted Selective Disclosure:
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          {/* Switch 1: [Hide $ NAV] */}
          <button
            type="button"
            onClick={() => {
              setHideDollarNav((v) => !v);
              setFocusedLeaf("indexed_curve");
            }}
            aria-pressed={hideDollarNav}
            className={`inline-flex items-center gap-2 rounded border px-3 py-1.5 transition ${
              hideDollarNav
                ? "border-signal-emerald bg-signal-emerald-bg text-signal-emerald"
                : "border-signal-ochre bg-signal-ochre-bg text-signal-ochre"
            }`}
          >
            <span
              className={`h-2 w-2 rounded-full ${
                hideDollarNav ? "bg-signal-emerald" : "bg-signal-ochre"
              }`}
            />
            <span>[Hide $ NAV]</span>
            <span className="text-[10px] opacity-85 tabular-nums">
              {hideDollarNav ? `Idx ${terminalIdx}` : "$ Stripped at Source"}
            </span>
          </button>

          {/* Switch 2: [Reveal $100k–$1M Bracket] */}
          <button
            type="button"
            onClick={() => {
              setRevealCapitalBracket((v) => !v);
              setFocusedLeaf("capital_bracket");
            }}
            aria-pressed={revealCapitalBracket}
            className={`inline-flex items-center gap-2 rounded border px-3 py-1.5 transition ${
              revealCapitalBracket
                ? "border-signal-emerald bg-signal-emerald-bg text-signal-emerald"
                : "border-signal-ochre bg-signal-ochre-bg text-signal-ochre"
            }`}
          >
            <span
              className={`h-2 w-2 rounded-full ${
                revealCapitalBracket ? "bg-signal-emerald" : "bg-signal-ochre"
              }`}
            />
            <span>[Reveal $100k–$1M Bracket]</span>
            <span className="text-[10px] opacity-85">
              {revealCapitalBracket ? bracketLabel : "Redacted"}
            </span>
          </button>

          {/* Switch 3: [Enforce 7-Day Front-Run Guard] */}
          <button
            type="button"
            onClick={() => {
              setEnforceFrontRunGuard((v) => !v);
              setFocusedLeaf("delayed_closed_trades");
            }}
            aria-pressed={enforceFrontRunGuard}
            className={`inline-flex items-center gap-2 rounded border px-3 py-1.5 transition ${
              enforceFrontRunGuard
                ? "border-signal-champagne bg-signal-champagne-bg text-signal-champagne"
                : "border-hairline-strong bg-panel text-ink-secondary hover:text-ink"
            }`}
          >
            <span
              className={`h-2 w-2 rounded-full ${
                enforceFrontRunGuard ? "bg-signal-champagne" : "bg-ink-muted"
              }`}
            />
            <span>[Enforce 7-Day Front-Run Guard]</span>
            <span className="text-[10px] opacity-85">
              {enforceFrontRunGuard ? "Leaf Sealed" : "7d Delayed"}
            </span>
          </button>
        </div>
      </div>

      {/* Row 3: 7-Leaf Salted Merkle Inclusion Path SVG + Live Payload / WebCrypto Inspector */}
      <div className="mt-5 grid grid-cols-1 gap-5 lg:grid-cols-12">
        {/* Left: Interactive 7-Leaf Salted Merkle Inclusion Tree */}
        <div className="rounded border border-hairline bg-canvas p-4 lg:col-span-7">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-hairline pb-2.5 font-mono text-[11px]">
            <span className="font-semibold text-ink">
              Domain-Separated 7-Leaf Merkle Inclusion Path (0x00 Leaf / 0x01 Node)
            </span>
            <span className="text-signal-emerald tabular-nums">
              merkle_root unchanged: {workingBundle.merkle_root.slice(0, 14)}…
            </span>
          </div>

          <MerkleInclusionSvg
            topology={topology}
            focusedLeafIndex={focusedLeafIndex}
            inclusion={inclusion}
            onSelectLeaf={(idx) => setFocusedLeaf(CANONICAL_LEAF_NAMES[idx]!)}
          />

          {/* Interactive Leaf Selector Pills */}
          <div className="mt-3 grid grid-cols-2 gap-1.5 sm:grid-cols-4 lg:grid-cols-7">
            {CANONICAL_LEAF_NAMES.map((leafName) => {
              const isSelected = leafName === focusedLeaf;
              const isRedacted = Boolean(workingBundle.undisclosed_leaf_hashes?.[leafName]);
              return (
                <button
                  key={leafName}
                  type="button"
                  onClick={() => setFocusedLeaf(leafName)}
                  className={`rounded border px-2 py-1.5 text-left font-mono text-[10px] transition ${
                    isSelected
                      ? "border-signal-champagne bg-signal-champagne-bg text-ink"
                      : isRedacted
                        ? "border-signal-ochre-border bg-signal-ochre-bg text-signal-ochre"
                        : "border-hairline bg-panel text-ink-secondary hover:border-ink-muted"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold">{SHORT_LEAF_LABELS[leafName]}</span>
                    <span>{isRedacted ? "🔒" : "✓"}</span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Right: Real-Time WebCrypto Verdict & Disclosed/Redacted Leaf X-Ray */}
        <div className="flex flex-col justify-between space-y-3 rounded border border-hairline bg-canvas p-4 lg:col-span-5">
          <div className="space-y-3">
            {/* Live WebCrypto Status Pill */}
            <div className="flex flex-wrap items-center justify-between gap-2 rounded border border-hairline-strong bg-panel px-3 py-2.5 font-mono text-[11px] tabular-nums">
              <div className="flex items-center gap-2">
                {verification?.valid ? (
                  <ShieldCheck className="h-4 w-4 text-signal-emerald" />
                ) : (
                  <ShieldAlert className="h-4 w-4 text-signal-ochre" />
                )}
                <span className="font-semibold text-ink">
                  {verification == null
                    ? "WebCrypto Verifying…"
                    : verification.valid
                      ? "Ed25519 + Merkle VALID"
                      : "Verification Rejected"}
                </span>
              </div>
              <span className="text-signal-emerald">
                {verifyMs.toFixed(2)} ms • 0B server
              </span>
            </div>

            {/* Specimen Assurance Summary */}
            <div className="grid grid-cols-2 gap-2 font-mono text-[11px] tabular-nums">
              <div className="rounded border border-hairline bg-panel p-2.5">
                <span className="text-[10px] uppercase text-ink-muted">Effective Origin</span>
                <p className="mt-0.5 font-semibold text-signal-champagne">
                  {verification
                    ? ORIGIN_ASSURANCE_META[verification.effective_origin_assurance].shortLabel
                    : "—"}
                </p>
              </div>
              <div className="rounded border border-hairline bg-panel p-2.5">
                <span className="text-[10px] uppercase text-ink-muted">
                  {hideDollarNav ? "Rebased Wealth" : "Dollar Redaction"}
                </span>
                <p className="mt-0.5 font-semibold text-signal-emerald">
                  {hideDollarNav ? `100.00 → ${terminalIdx}` : "0 Raw $ in Leaf"}
                </p>
              </div>
            </div>

            {/* Active Leaf Inspector */}
            <div className="rounded border border-hairline-strong bg-panel p-3 font-mono text-[11px] tabular-nums">
              <div className="flex items-center justify-between gap-2 border-b border-hairline pb-2">
                <span className="font-semibold text-ink">
                  Leaf #{focusedLeafIndex}: {focusedLeaf}
                </span>
                {activeDisclosedObj ? (
                  <span className="badge-emerald inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px]">
                    <CheckCircle2 className="h-3 w-3" />
                    DISCLOSED
                  </span>
                ) : (
                  <span className="badge-ochre inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px]">
                    <EyeOff className="h-3 w-3" />
                    SALTED-REDACTED
                  </span>
                )}
              </div>

              <p className="mt-2 font-sans text-xs text-ink-secondary">
                {LEAF_DISPLAY_META[focusedLeaf].description}
              </p>

              {activeDisclosedObj ? (
                <div className="mt-2.5 space-y-1.5 text-[10.5px]">
                  <div className="truncate text-ink-muted">
                    256b salt: <span className="text-ink-secondary">{activeDisclosedObj.salt_hex}</span>
                  </div>
                  <div className="truncate text-ink-muted">
                    0x00 hash:{" "}
                    <span className="text-signal-emerald">{activeDisclosedObj.leaf_hash_hex}</span>
                  </div>
                  <pre className="max-h-28 overflow-auto rounded border border-hairline bg-elevated p-2 text-[10px] text-ink">
                    {JSON.stringify(activeDisclosedObj.payload, null, 2).slice(0, 360)}
                    {JSON.stringify(activeDisclosedObj.payload, null, 2).length > 360
                      ? "\n  …"
                      : ""}
                  </pre>
                </div>
              ) : (
                <div className="mt-2.5 space-y-1.5 rounded border border-signal-ochre-border bg-signal-ochre-bg p-2.5 text-[10.5px]">
                  <p className="font-semibold text-signal-ochre">
                    Payload &amp; 256-Bit Salt Stripped Locally
                  </p>
                  <p className="font-sans text-[11px] text-ink-secondary">
                    Only the pre-image resistant salted SHA-256 commitment remains so
                    verifiers reconstruct the exact same publisher-signed{" "}
                    <code>merkle_root</code>:
                  </p>
                  <p className="truncate text-ink">{activeUndisclosedHash ?? "—"}</p>
                </div>
              )}
            </div>
          </div>

          <div className="flex items-center justify-between border-t border-hairline pt-2.5 font-mono text-[11px]">
            <span className="text-ink-muted tabular-nums">
              {workingBundle.disclosed_leaves.length}/7 disclosed •{" "}
              {Object.keys(workingBundle.undisclosed_leaf_hashes).length} redacted
            </span>
            <Link
              href={`/p/${workingBundle.proof_id}`}
              className="font-semibold text-signal-champagne underline-offset-4 hover:underline"
            >
              Open Full Tear Sheet →
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

function MerkleInclusionSvg({
  topology,
  focusedLeafIndex,
  inclusion,
  onSelectLeaf,
}: {
  topology: MerkleTreeTopology | null;
  focusedLeafIndex: number;
  inclusion: ReturnType<typeof getActiveInclusionNodes>;
  onSelectLeaf: (idx: number) => void;
}) {
  const width = 560;
  const height = 228;

  // Coordinates for 4 tiers: Root (y=28), Level2 (y=86), Level1 (y=144), Leaves (y=202)
  const rootPos = { x: 280, y: 26 };
  const l2Pos = [
    { x: 165, y: 84 },
    { x: 395, y: 84 },
  ];
  const l1Pos = [
    { x: 92, y: 142 },
    { x: 232, y: 142 },
    { x: 362, y: 142 },
    { x: 484, y: 142 },
  ];
  const leafPos = [
    { x: 52, y: 200 },
    { x: 126, y: 200 },
    { x: 198, y: 200 },
    { x: 270, y: 200 },
    { x: 336, y: 200 },
    { x: 406, y: 200 },
    { x: 484, y: 200 },
  ];

  const leafToL1 = [0, 0, 1, 1, 2, 2, 3];
  const l1ToL2 = [0, 0, 1, 1];

  return (
    <div className="mt-3 overflow-x-auto">
      <svg viewBox={`0 0 ${width} ${height}`} className="h-auto w-full min-w-[460px] select-none">
        {/* Edges: Level2 -> Root */}
        {l2Pos.map((pos, idx) => {
          const isSpine = idx === inclusion.spineL2;
          const isSibling = idx === inclusion.siblingL2;
          return (
            <line
              key={`l2-root-${idx}`}
              x1={pos.x}
              y1={pos.y}
              x2={rootPos.x}
              y2={rootPos.y}
              stroke={
                isSpine
                  ? "var(--signal-emerald)"
                  : isSibling
                    ? "var(--signal-champagne)"
                    : "var(--border-strong)"
              }
              strokeWidth={isSpine ? "2.3" : isSibling ? "1.6" : "1"}
              strokeDasharray={isSibling ? "4 3" : undefined}
            />
          );
        })}

        {/* Edges: Level1 -> Level2 */}
        {l1Pos.map((pos, idx) => {
          const parentIdx = l1ToL2[idx]!;
          const parent = l2Pos[parentIdx]!;
          const isSpine = idx === inclusion.spineL1;
          const isSibling = idx === inclusion.siblingL1;
          return (
            <line
              key={`l1-l2-${idx}`}
              x1={pos.x}
              y1={pos.y}
              x2={parent.x}
              y2={parent.y}
              stroke={
                isSpine
                  ? "var(--signal-emerald)"
                  : isSibling
                    ? "var(--signal-champagne)"
                    : "var(--border-strong)"
              }
              strokeWidth={isSpine ? "2.3" : isSibling ? "1.6" : "1"}
              strokeDasharray={isSibling ? "4 3" : undefined}
            />
          );
        })}

        {/* Edges: Leaves -> Level1 */}
        {leafPos.map((pos, idx) => {
          const parentIdx = leafToL1[idx]!;
          const parent = l1Pos[parentIdx]!;
          const isSpine = idx === focusedLeafIndex;
          const isSibling = idx === inclusion.siblingLeaf;
          return (
            <line
              key={`leaf-l1-${idx}`}
              x1={pos.x}
              y1={pos.y}
              x2={parent.x}
              y2={parent.y}
              stroke={
                isSpine
                  ? "var(--signal-emerald)"
                  : isSibling
                    ? "var(--signal-champagne)"
                    : "var(--border-strong)"
              }
              strokeWidth={isSpine ? "2.3" : isSibling ? "1.6" : "1"}
              strokeDasharray={isSibling ? "4 3" : undefined}
            />
          );
        })}

        {/* Root Node */}
        <g transform={`translate(${rootPos.x - 74}, ${rootPos.y - 14})`}>
          <rect
            width="148"
            height="28"
            rx="4"
            fill="var(--bg-panel)"
            stroke="var(--signal-emerald)"
            strokeWidth="1.5"
          />
          <text
            x="74"
            y="18"
            textAnchor="middle"
            fontSize="10"
            fontWeight="700"
            fill="var(--signal-emerald)"
            className="mono-num"
          >
            ROOT {topology ? topology.root.slice(0, 10) : "0x01…"}
          </text>
        </g>

        {/* Level 2 Nodes */}
        {l2Pos.map((pos, idx) => {
          const isSpine = idx === inclusion.spineL2;
          const isSibling = idx === inclusion.siblingL2;
          const hash = topology?.level2[idx]?.slice(0, 8) ?? "0x01";
          return (
            <g key={`node-l2-${idx}`} transform={`translate(${pos.x - 52}, ${pos.y - 12})`}>
              <rect
                width="104"
                height="24"
                rx="3.5"
                fill="var(--bg-panel)"
                stroke={
                  isSpine
                    ? "var(--signal-emerald)"
                    : isSibling
                      ? "var(--signal-champagne)"
                      : "var(--border-strong)"
                }
                strokeWidth={isSpine || isSibling ? "1.4" : "1"}
              />
              <text
                x="52"
                y="15.5"
                textAnchor="middle"
                fontSize="9.5"
                fill={
                  isSpine
                    ? "var(--signal-emerald)"
                    : isSibling
                      ? "var(--signal-champagne)"
                      : "var(--text-secondary)"
                }
                className="mono-num"
              >
                0x01:{hash}
              </text>
            </g>
          );
        })}

        {/* Level 1 Nodes */}
        {l1Pos.map((pos, idx) => {
          const isSpine = idx === inclusion.spineL1;
          const isSibling = idx === inclusion.siblingL1;
          const hash = topology?.level1[idx]?.slice(0, 6) ?? "0x01";
          return (
            <g key={`node-l1-${idx}`} transform={`translate(${pos.x - 42}, ${pos.y - 11})`}>
              <rect
                width="84"
                height="22"
                rx="3.5"
                fill="var(--bg-panel)"
                stroke={
                  isSpine
                    ? "var(--signal-emerald)"
                    : isSibling
                      ? "var(--signal-champagne)"
                      : "var(--border-strong)"
                }
                strokeWidth={isSpine || isSibling ? "1.4" : "1"}
              />
              <text
                x="42"
                y="14.5"
                textAnchor="middle"
                fontSize="9"
                fill={
                  isSpine
                    ? "var(--signal-emerald)"
                    : isSibling
                      ? "var(--signal-champagne)"
                      : "var(--text-muted)"
                }
                className="mono-num"
              >
                {idx === 3 ? `L6:${hash}` : `0x01:${hash}`}
              </text>
            </g>
          );
        })}

        {/* 7 Canonical Leaf Nodes */}
        {leafPos.map((pos, idx) => {
          const leafMeta = topology?.leaves[idx];
          const disclosed = leafMeta?.disclosed ?? true;
          const isFocused = idx === focusedLeafIndex;
          const isSibling = idx === inclusion.siblingLeaf;
          const name = CANONICAL_LEAF_NAMES[idx]!;
          return (
            <g
              key={`leaf-node-${name}`}
              transform={`translate(${pos.x - 31}, ${pos.y - 12})`}
              className="cursor-pointer"
              onClick={() => onSelectLeaf(idx)}
            >
              <rect
                width="62"
                height="24"
                rx="3.5"
                fill={
                  !disclosed
                    ? "var(--signal-ochre-bg)"
                    : isFocused
                      ? "var(--signal-emerald-bg)"
                      : "var(--bg-panel)"
                }
                stroke={
                  isFocused
                    ? "var(--signal-emerald)"
                    : !disclosed
                      ? "var(--signal-ochre)"
                      : isSibling
                        ? "var(--signal-champagne)"
                        : "var(--border-strong)"
                }
                strokeWidth={isFocused ? "1.8" : "1.1"}
              />
              <text
                x="31"
                y="15"
                textAnchor="middle"
                fontSize="8.8"
                fontWeight={isFocused ? "700" : "500"}
                fill={
                  !disclosed
                    ? "var(--signal-ochre)"
                    : isFocused
                      ? "var(--signal-emerald)"
                      : "var(--text-ink)"
                }
                className="mono-num"
              >
                {SHORT_LEAF_LABELS[name]}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
