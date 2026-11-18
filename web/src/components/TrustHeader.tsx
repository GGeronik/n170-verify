"use client";

import {
  CheckCircle2,
  Download,
  Eye,
  Printer,
  Share2,
  ShieldAlert,
  ShieldCheck,
  X,
} from "lucide-react";
import { useMemo, useState } from "react";
import {
  ACCOUNT_SCOPE_META,
  CHAIN_CONTINUITY_META,
  EnvironmentTier,
  ORIGIN_ASSURANCE_META,
  RECONCILIATION_STATUS_META,
  ReconciliationStatus,
  REQUIRED_TLSN_PROTOCOL,
  SIGNER_TRUST_META,
  SIGNING_DOMAIN_BUNDLE,
  extractTypedLeaves,
  type BundleVerificationResult,
  type PublisherKeyRegistryDocument,
  type VerifyProofBundle,
} from "@/lib/contracts.ts";
import { generateQrCode } from "@/lib/qrSvg.ts";

type SignalVariant = "emerald" | "champagne" | "ochre" | "vermilion" | "neutral";
type ChipId = "origin" | "signer" | "reconciliation" | "continuity";

const VARIANT_CLASSES: Record<
  SignalVariant,
  { card: string; pill: string; dot: string; accentText: string }
> = {
  emerald: {
    card: "border-signal-emerald-border bg-panel hover:border-signal-emerald",
    pill: "badge-emerald",
    dot: "bg-signal-emerald",
    accentText: "text-signal-emerald",
  },
  champagne: {
    card: "border-signal-champagne-border bg-panel hover:border-signal-champagne",
    pill: "badge-champagne",
    dot: "bg-signal-champagne",
    accentText: "text-signal-champagne",
  },
  ochre: {
    card: "border-signal-ochre-border bg-panel hover:border-signal-ochre",
    pill: "badge-ochre",
    dot: "bg-signal-ochre",
    accentText: "text-signal-ochre",
  },
  vermilion: {
    card: "border-signal-vermilion-border bg-panel hover:border-signal-vermilion",
    pill: "badge-vermilion",
    dot: "bg-signal-vermilion",
    accentText: "text-signal-vermilion",
  },
  neutral: {
    card: "border-hairline-strong bg-panel hover:border-ink-muted",
    pill: "badge-neutral",
    dot: "bg-ink-muted",
    accentText: "text-ink-secondary",
  },
};

export interface TrustHeaderProps {
  bundle: VerifyProofBundle;
  verification: BundleVerificationResult | null;
  registryDoc?: PublisherKeyRegistryDocument;
  verifyLatencyMs?: number | null;
  title?: string;
  subtitle?: string;
  handle?: string;
  onOpenVerifier: () => void;
  onOpenShareStudio?: () => void;
  onDownloadBundle?: () => void;
}

export function TrustHeader({
  bundle,
  verification,
  registryDoc,
  verifyLatencyMs,
  title,
  subtitle,
  handle,
  onOpenVerifier,
  onOpenShareStudio,
  onDownloadBundle,
}: TrustHeaderProps) {
  const [hoveredChip, setHoveredChip] = useState<ChipId | null>(null);
  const [pinnedChip, setPinnedChip] = useState<ChipId | null>(null);

  const activeXrayChip = pinnedChip ?? hoveredChip;

  const leaves = useMemo(() => extractTypedLeaves(bundle), [bundle]);
  const reconStatus =
    leaves.reconciliation?.status ?? ReconciliationStatus.REFERENCE_DATA_UNAVAILABLE;

  const effectiveOrigin =
    verification?.effective_origin_assurance ?? bundle.claimed_origin_assurance;
  const originDowngraded =
    verification != null &&
    verification.effective_origin_assurance !== bundle.claimed_origin_assurance;

  const originMeta = ORIGIN_ASSURANCE_META[effectiveOrigin];
  const originVariant: SignalVariant = originDowngraded
    ? "ochre"
    : effectiveOrigin === "broker_signed" ||
        effectiveOrigin === "independently_witnessed_tls"
      ? "champagne"
      : effectiveOrigin === "self_reported"
        ? "ochre"
        : "neutral";

  const signerStatus =
    verification?.signer_trust_status ?? "unrecognized_self_hosted_signer";
  const signerMeta = SIGNER_TRUST_META[signerStatus];
  const signerVariant: SignalVariant =
    signerStatus === "official_n170_hosted"
      ? "emerald"
      : signerStatus === "retired_historical_valid"
        ? "champagne"
        : signerStatus === "revoked_key"
          ? "vermilion"
          : "ochre";

  const reconMeta = RECONCILIATION_STATUS_META[reconStatus];
  const reconVariant: SignalVariant =
    reconStatus === "reconciled_within_tolerance"
      ? "emerald"
      : reconStatus === "unexplained_residual" || reconStatus === "insufficient_sections"
        ? "ochre"
        : "neutral";

  const scopeMeta = ACCOUNT_SCOPE_META[bundle.account_scope];
  const continuityMode =
    verification?.effective_chain_continuity_mode ??
    (bundle.prospective_chain_link
      ? "prospective_continuous"
      : "unenrolled_single_snapshot");
  const continuityMeta = CHAIN_CONTINUITY_META[continuityMode];

  const continuityVariant: SignalVariant =
    continuityMode === "continuity_broken"
      ? "vermilion"
      : bundle.account_scope === "all_enumerated_subaccounts" &&
          continuityMode === "prospective_continuous"
        ? "emerald"
        : continuityMode === "retrospective_backfill" ||
            bundle.account_scope === "single_account_survivorship_unverified" ||
            bundle.account_scope === "unknown_offline_scope"
          ? "ochre"
          : "neutral";

  const seqNum = bundle.prospective_chain_link?.sequence_number;
  const isLiveEnv = bundle.environment_tier === EnvironmentTier.LIVE_PRODUCTION;

  const printQr = useMemo(
    () => generateQrCode(`https://verify.n170.org/p/${bundle.proof_id}`),
    [bundle.proof_id],
  );

  const togglePin = (id: ChipId) => {
    setPinnedChip((prev) => (prev === id ? null : id));
  };

  const notaryDirectory = useMemo(() => {
    const map = new Map<string, { org: string; asn: string; enclave: string }>();
    for (const n of registryDoc?.notaries ?? []) {
      map.set(n.notary_id, {
        org: n.operator_org,
        asn: n.asn,
        enclave: n.attestation_type ?? "production",
      });
    }
    return map;
  }, [registryDoc]);

  return (
    <section className="inst-panel relative rounded-md p-5 sm:p-6 print-avoid-break">
      {/* Top Masthead Identity + Action Controls */}
      <div className="flex flex-col justify-between gap-4 border-b border-hairline pb-5 xl:flex-row xl:items-start">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
            {handle && (
              <span className="font-semibold text-signal-emerald">{handle}</span>
            )}
            <span className="rounded border border-hairline-strong bg-elevated px-2 py-0.5 text-ink tabular-nums">
              {bundle.proof_id}
            </span>
            <span
              className={`rounded px-2 py-0.5 font-semibold ${
                isLiveEnv ? "badge-emerald" : "badge-vermilion"
              }`}
            >
              {isLiveEnv ? "LIVE PRODUCTION" : "SANDBOX REJECTED"}
            </span>
            <span className="rounded border border-hairline bg-elevated px-2 py-0.5 text-ink-muted">
              {bundle.retention_mode === "no_persistent_storage"
                ? "Zero-DB Subprocess (RLIMIT_CORE=0)"
                : "Opt-In Encrypted Sync"}
            </span>
          </div>

          <h1 className="editorial-serif text-2xl leading-tight text-ink sm:text-3xl">
            {title ?? `Verified Performance Tear Sheet • ${bundle.broker_id.toUpperCase()}`}
          </h1>

          {subtitle ? (
            <p className="text-xs text-ink-secondary sm:text-[13px]">{subtitle}</p>
          ) : (
            <p className="font-mono text-xs text-ink-muted tabular-nums">
              Period {bundle.period_start_utc.slice(0, 10)} →{" "}
              {bundle.period_end_utc.slice(0, 10)} • Base {bundle.base_currency} • Blinded Tag{" "}
              {bundle.blinded_account_tag.slice(0, 12)}…
            </p>
          )}
        </div>

        {/* Right Controls (Hidden on Print, Replaced by Print QR Seal) */}
        <div className="no-print flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={onOpenVerifier}
            className={`inline-flex items-center gap-2 rounded border px-3.5 py-2 font-mono text-xs font-semibold transition ${
              verification == null
                ? "border-hairline-strong bg-elevated text-ink"
                : verification.valid
                  ? "border-signal-emerald bg-signal-emerald-bg text-signal-emerald hover:bg-signal-emerald hover:text-canvas"
                  : "border-signal-vermilion bg-signal-vermilion-bg text-signal-vermilion"
            }`}
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            <span>Verify Cryptographically in Browser</span>
            {verifyLatencyMs != null && (
              <span className="rounded border border-current/25 px-1.5 py-0.5 text-[10px] tabular-nums">
                {verifyLatencyMs.toFixed(1)}ms
              </span>
            )}
          </button>

          {onOpenShareStudio && (
            <button
              type="button"
              onClick={onOpenShareStudio}
              className="inline-flex items-center gap-1.5 rounded border border-signal-champagne-border bg-signal-champagne-bg px-3 py-2 font-mono text-xs font-medium text-signal-champagne transition hover:border-signal-champagne"
            >
              <Share2 className="h-3.5 w-3.5" />
              <span>Share &amp; Embed</span>
            </button>
          )}

          <button
            type="button"
            onClick={() => window.print()}
            title="Export 2-Page Archival Tear Sheet via Cmd+P"
            className="inline-flex items-center gap-1.5 rounded border border-hairline-strong bg-elevated px-3 py-2 font-mono text-xs text-ink-secondary transition hover:border-ink hover:text-ink"
          >
            <Printer className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">Tear Sheet PDF</span>
          </button>

          {onDownloadBundle && (
            <button
              type="button"
              onClick={onDownloadBundle}
              className="inline-flex items-center gap-1.5 rounded border border-hairline-strong bg-elevated px-3 py-2 font-mono text-xs text-ink-secondary transition hover:border-ink hover:text-ink"
            >
              <Download className="h-3.5 w-3.5" />
              <span>.json</span>
            </button>
          )}
        </div>

        {/* Print-Only Scannable QR Verification Block */}
        <div className="print-only hidden shrink-0 rounded border border-hairline-strong p-2 text-right">
          <div className="flex items-center gap-2.5">
            <div className="font-mono text-[9px] leading-tight text-ink-secondary">
              <div className="font-bold text-ink">N170 CRYPTOGRAPHIC SEAL</div>
              <div>Scan to verify Ed25519 + Merkle</div>
              <div className="tabular-nums">
                SHA256 {verification?.proof_hash.slice(0, 12) ?? bundle.merkle_root.slice(0, 12)}…
              </div>
            </div>
            <svg
              viewBox={`-1 -1 ${printQr.size + 2} ${printQr.size + 2}`}
              className="h-12 w-12 text-ink"
            >
              <path d={printQr.svgPath} fill="currentColor" shapeRendering="crispEdges" />
            </svg>
          </div>
        </div>
      </div>

      {/* Dynamic Origin Assurance Downgrade Banner */}
      {originDowngraded && verification && (
        <div className="mt-4 rounded border border-signal-ochre-border bg-signal-ochre-bg px-4 py-3 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2 font-mono font-semibold text-signal-ochre">
            <span className="inline-flex items-center gap-1.5">
              <ShieldAlert className="h-4 w-4" />
              Dynamic Origin-Assurance Downgrade Enforced Locally
            </span>
            <span className="text-[11px] tabular-nums">
              claimed: {bundle.claimed_origin_assurance} → effective:{" "}
              {verification.effective_origin_assurance}
            </span>
          </div>
          <ul className="mt-1.5 list-disc space-y-0.5 pl-5 text-ink-secondary">
            {verification.witness_quorum.downgrade_reasons.map((reason) => (
              <li key={reason}>{reason}</li>
            ))}
          </ul>
        </div>
      )}

      {verification && !verification.valid && verification.errors.length > 0 && (
        <div className="mt-4 rounded border border-signal-vermilion-border bg-signal-vermilion-bg px-4 py-3 text-xs">
          <p className="font-mono font-semibold text-signal-vermilion">
            Cryptographic Verification Rejected ({verification.errors.length})
          </p>
          <ul className="mt-1.5 list-disc space-y-0.5 pl-5 text-ink-secondary">
            {verification.errors.map((err) => (
              <li key={err}>{err}</li>
            ))}
          </ul>
        </div>
      )}

      {/* 4-Chip Orthogonal Trust Grid with Hover/Click Surgical X-Ray Popovers */}
      <div
        className="relative mt-5"
        onMouseLeave={() => setHoveredChip(null)}
      >
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
          {/* Chip 1: Origin Assurance */}
          <OrthogonalTrustChip
            indexLabel="01 • ORIGIN ASSURANCE"
            badgeText={originDowngraded ? "Downgraded" : originMeta.shortLabel}
            headline={originMeta.label}
            detail={
              verification?.witness_quorum.broker_signature_valid
                ? `Pinned ${bundle.broker_native_signature?.broker_id} Ed25519 custody key (${bundle.broker_native_signature?.key_id}).`
                : verification && verification.witness_quorum.valid_witness_count > 0
                  ? `Disjoint MPC-TLS clique k=${verification.witness_quorum.disjoint_quorum_size} (${verification.witness_quorum.distinct_org_count} orgs, ${verification.witness_quorum.distinct_asn_count} ASNs).`
                  : originMeta.summary
            }
            variant={originVariant}
            active={activeXrayChip === "origin"}
            pinned={pinnedChip === "origin"}
            onHover={() => setHoveredChip("origin")}
            onClick={() => togglePin("origin")}
          />

          {/* Chip 2: Signer Trust */}
          <OrthogonalTrustChip
            indexLabel="02 • SIGNER TRUST"
            badgeText={signerMeta.shortLabel}
            headline={signerMeta.label}
            detail={`kid: ${bundle.publisher_kid}${
              verification?.checkpoint_verified
                ? ` • C2SP tlog + ${verification.checkpoint_witness_count} cosigs • Base L2`
                : " • Ed25519 domain"
            }`}
            variant={signerVariant}
            active={activeXrayChip === "signer"}
            pinned={pinnedChip === "signer"}
            onHover={() => setHoveredChip("signer")}
            onClick={() => togglePin("signer")}
          />

          {/* Chip 3: Accounting Reconciliation */}
          <OrthogonalTrustChip
            indexLabel="03 • ACCOUNTING RECONCILIATION"
            badgeText={reconMeta.shortLabel}
            headline={reconMeta.label}
            detail={
              leaves.reconciliation
                ? `${leaves.reconciliation.checks_evaluated} identity & EODHD bounds • ${leaves.reconciliation.discrepancy_count} unexplained, ${leaves.reconciliation.explained_convention_count} explained.`
                : "Reconciliation leaf selectively redacted by holder."
            }
            variant={reconVariant}
            active={activeXrayChip === "reconciliation"}
            pinned={pinnedChip === "reconciliation"}
            onHover={() => setHoveredChip("reconciliation")}
            onClick={() => togglePin("reconciliation")}
          />

          {/* Chip 4: Account Scope & Continuity */}
          <OrthogonalTrustChip
            indexLabel="04 • ACCOUNT SCOPE & CONTINUITY"
            badgeText={
              seqNum != null && continuityMode === "prospective_continuous"
                ? `Prospective #${seqNum}`
                : continuityMeta.shortLabel
            }
            headline={scopeMeta.label}
            detail={
              seqNum != null
                ? `${continuityMeta.label} • Seq #${seqNum} (${
                    verification?.chain_verification?.verified_length ?? 1
                  } verified link${
                    (verification?.chain_verification?.verified_length ?? 1) === 1 ? "" : "s"
                  })`
                : continuityMeta.label
            }
            variant={continuityVariant}
            active={activeXrayChip === "continuity"}
            pinned={pinnedChip === "continuity"}
            onHover={() => setHoveredChip("continuity")}
            onClick={() => togglePin("continuity")}
          />
        </div>

        {/* Surgical X-Ray Inspection Popover Card */}
        {activeXrayChip && (
          <div
            role="region"
            aria-label={`Surgical X-Ray Evidence for ${activeXrayChip}`}
            className={`no-print z-30 mt-2.5 rounded-md border border-hairline-strong bg-elevated p-4 shadow-2xl xl:absolute xl:top-full xl:w-[580px] ${
              activeXrayChip === "reconciliation" || activeXrayChip === "continuity"
                ? "xl:right-0"
                : "xl:left-0"
            }`}
          >
            <div className="flex items-center justify-between border-b border-hairline pb-2.5">
              <div className="flex items-center gap-2 font-mono text-[11px]">
                <Eye className="h-3.5 w-3.5 text-signal-champagne" />
                <span className="font-semibold uppercase tracking-wider text-signal-champagne">
                  Surgical X-Ray Evidence
                </span>
                {pinnedChip === activeXrayChip && (
                  <span className="rounded border border-hairline-strong bg-panel px-1.5 py-0.5 text-[10px] text-ink-muted">
                    Pinned
                  </span>
                )}
              </div>
              <button
                type="button"
                onClick={() => {
                  setPinnedChip(null);
                  setHoveredChip(null);
                }}
                aria-label="Close X-Ray popover"
                className="rounded p-1 text-ink-muted transition hover:bg-panel hover:text-ink"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>

            {activeXrayChip === "origin" && (
              <div className="mt-3 space-y-2.5 text-xs">
                <div className="grid grid-cols-2 gap-2 font-mono text-[11px] tabular-nums">
                  <div className="rounded border border-hairline bg-panel p-2">
                    <span className="text-ink-muted">claimed_origin:</span>
                    <div className="mt-0.5 font-semibold text-ink">
                      {bundle.claimed_origin_assurance}
                    </div>
                  </div>
                  <div className="rounded border border-hairline bg-panel p-2">
                    <span className="text-ink-muted">effective_origin (verifier):</span>
                    <div className="mt-0.5 font-semibold text-signal-champagne">
                      {effectiveOrigin}
                    </div>
                  </div>
                </div>

                {bundle.broker_native_signature ? (
                  <div className="rounded border border-hairline bg-panel p-2.5 font-mono text-[11px] tabular-nums">
                    <div className="font-semibold text-signal-emerald">
                      First-Party Broker Custody Signature ({bundle.broker_native_signature.algorithm})
                    </div>
                    <div className="mt-1 text-ink-secondary">
                      key_id: {bundle.broker_native_signature.key_id} • body_sha256:{" "}
                      {bundle.broker_native_signature.signed_payload_sha256.slice(0, 20)}…
                    </div>
                  </div>
                ) : bundle.witness_attestations.length > 0 ? (
                  <div className="space-y-1.5">
                    <p className="font-mono text-[10.5px] uppercase text-ink-muted">
                      MPC-TLS Witness Attestations ({REQUIRED_TLSN_PROTOCOL})
                    </p>
                    <div className="divide-y divide-hairline rounded border border-hairline bg-panel font-mono text-[11px] tabular-nums">
                      {bundle.witness_attestations.map((att) => {
                        const info = notaryDirectory.get(att.notary_id);
                        return (
                          <div
                            key={`${att.notary_id}-${att.session_timestamp_utc}`}
                            className="flex flex-wrap items-center justify-between gap-2 px-2.5 py-2"
                          >
                            <div>
                              <span className="font-semibold text-ink">{att.notary_id}</span>
                              {info && (
                                <span className="ml-2 text-ink-muted">
                                  {info.org} • {info.asn} ({info.enclave})
                                </span>
                              )}
                            </div>
                            <span className="text-[10px] text-signal-emerald">
                              SNI {att.server_sni} • defer_decrypt=
                              {String(att.defer_decryption_from_start)}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                ) : (
                  <p className="text-ink-secondary">
                    No independent notary attestations or pinned broker signature attached;
                    classified strictly as self-reported statement provenance.
                  </p>
                )}

                <p className="font-mono text-[10.5px] text-ink-muted tabular-nums">
                  source_body_sha256: {bundle.source_body_sha256}
                </p>
              </div>
            )}

            {activeXrayChip === "signer" && (
              <div className="mt-3 space-y-2.5 font-mono text-[11px] tabular-nums">
                <div className="rounded border border-hairline bg-panel p-2.5 space-y-1">
                  <div className="flex justify-between">
                    <span className="text-ink-muted">Signing Domain:</span>
                    <span className="text-ink">{SIGNING_DOMAIN_BUNDLE}\x00</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-ink-muted">Publisher Key ID:</span>
                    <span className="font-semibold text-signal-emerald">
                      {bundle.publisher_kid}
                    </span>
                  </div>
                  <div className="truncate text-ink-secondary">
                    pubkey: {bundle.publisher_public_key_hex}
                  </div>
                </div>

                {registryDoc?.checkpoint && (
                  <div className="rounded border border-hairline bg-panel p-2.5 space-y-1">
                    <div className="flex justify-between">
                      <span className="text-ink-muted">C2SP Checkpoint Origin:</span>
                      <span className="text-signal-champagne">
                        {registryDoc.checkpoint.origin} (size #{registryDoc.checkpoint.size})
                      </span>
                    </div>
                    <div className="text-ink-secondary">
                      Cosigners:{" "}
                      {registryDoc.checkpoint.witness_cosignatures
                        .map((w) => w.witness_id)
                        .join(", ")}
                    </div>
                    {registryDoc.l2_anchor && (
                      <div className="truncate text-ink-muted">
                        Base L2 #{registryDoc.l2_anchor.chain_id} • block #
                        {registryDoc.l2_anchor.block_number ?? "-"} • tx{" "}
                        {registryDoc.l2_anchor.tx_hash.slice(0, 22)}…
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {activeXrayChip === "reconciliation" && (
              <div className="mt-3 space-y-2.5 text-xs">
                <p className="text-ink-secondary">
                  {leaves.reconciliation?.summary_text ?? reconMeta.summary}
                </p>
                <div className="grid grid-cols-2 gap-2 font-mono text-[11px] tabular-nums">
                  {[
                    "PriorPeriodPositions",
                    "Trades & CashFlows",
                    "Transfers (ACATS/Internal)",
                    "CorporateActions & OptionEAE",
                  ].map((sec) => {
                    const missing =
                      leaves.reconciliation?.missing_sections.some((m) =>
                        sec.toLowerCase().includes(m.toLowerCase().slice(0, 8)),
                      ) ?? false;
                    return (
                      <div
                        key={sec}
                        className="flex items-center justify-between rounded border border-hairline bg-panel px-2.5 py-1.5"
                      >
                        <span className="text-ink">{sec}</span>
                        <span
                          className={
                            missing ? "text-signal-ochre" : "text-signal-emerald"
                          }
                        >
                          {missing ? "MISSING" : "PRESENT"}
                        </span>
                      </div>
                    );
                  })}
                </div>
                {leaves.reconciliation && (
                  <div className="flex flex-wrap items-center justify-between gap-2 font-mono text-[11px] text-ink-muted tabular-nums">
                    <span>Ref Provider: {leaves.reconciliation.reference_provider.toUpperCase()}</span>
                    <span>Evaluated: {leaves.reconciliation.checks_evaluated}</span>
                    <span>Explained Conventions: {leaves.reconciliation.explained_convention_count}</span>
                    <span>Unexplained Residuals: {leaves.reconciliation.discrepancy_count}</span>
                  </div>
                )}
              </div>
            )}

            {activeXrayChip === "continuity" && (
              <div className="mt-3 space-y-2.5 text-xs">
                <div className="grid grid-cols-2 gap-2 font-mono text-[11px] tabular-nums">
                  <div className="rounded border border-hairline bg-panel p-2">
                    <span className="text-ink-muted">Sub-Account Scope:</span>
                    <div className="mt-0.5 font-semibold text-ink">{bundle.account_scope}</div>
                  </div>
                  <div className="rounded border border-hairline bg-panel p-2">
                    <span className="text-ink-muted">Continuity Mode:</span>
                    <div className="mt-0.5 font-semibold text-signal-emerald">
                      {continuityMode}
                    </div>
                  </div>
                </div>

                <div className="space-y-1 rounded border border-hairline bg-panel p-2.5 font-mono text-[11px]">
                  <div className="text-[10px] uppercase tracking-wider text-ink-muted">
                    5 Prospective Chain Invariants
                  </div>
                  {[
                    "1. <= 24h Genesis Enrollment Window vs Backfill Separation",
                    "2. Strict Monotonic Sequence & Prev-Proof SHA-256 Linkage",
                    "3. Immutable Cadence & Grace Window Policy",
                    "4. Contiguous Flow-Adjusted Index Boundary (<= 1e-4)",
                    "5. Transparency Log Anti-Reset & Parallel Chain Guard",
                  ].map((rule) => (
                    <div key={rule} className="flex items-center gap-2 text-ink-secondary">
                      <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-signal-emerald" />
                      <span>{rule}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Bottom Cryptographic Footprint Strip */}
      <div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t border-hairline pt-3 font-mono text-[11px] text-ink-muted tabular-nums">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
          <span>
            merkle_root:{" "}
            <span className="text-ink-secondary">{bundle.merkle_root.slice(0, 18)}…</span>
          </span>
          {verification && (
            <span>
              proof_hash:{" "}
              <span className="text-ink-secondary">
                {verification.proof_hash.slice(0, 18)}…
              </span>
            </span>
          )}
          <span>
            disclosure:{" "}
            <span className="font-semibold text-signal-emerald">
              {bundle.disclosed_leaves.length}/7 leaves
            </span>
            {Object.keys(bundle.undisclosed_leaf_hashes).length > 0 && (
              <span>
                {" "}
                ({Object.keys(bundle.undisclosed_leaf_hashes).length} salted-redacted)
              </span>
            )}
          </span>
        </div>

        <button
          type="button"
          onClick={onOpenVerifier}
          className="no-print font-semibold text-signal-champagne underline-offset-4 transition hover:underline"
        >
          Open 5-Step WebCrypto Telemetry Trace →
        </button>
      </div>
    </section>
  );
}

function OrthogonalTrustChip({
  indexLabel,
  badgeText,
  headline,
  detail,
  variant,
  active,
  pinned,
  onHover,
  onClick,
}: {
  indexLabel: string;
  badgeText: string;
  headline: string;
  detail: string;
  variant: SignalVariant;
  active: boolean;
  pinned: boolean;
  onHover: () => void;
  onClick: () => void;
}) {
  const styles = VARIANT_CLASSES[variant];
  return (
    <button
      type="button"
      onMouseEnter={onHover}
      onFocus={onHover}
      onClick={onClick}
      aria-expanded={active}
      className={`group flex flex-col justify-between rounded border p-3.5 text-left transition ${styles.card} ${
        active ? "ring-1 ring-signal-champagne" : ""
      }`}
    >
      <div className="w-full">
        <div className="flex items-center justify-between gap-2">
          <span className="font-mono text-[10px] font-semibold tracking-wider text-ink-muted">
            {indexLabel}
          </span>
          <span
            className={`inline-flex items-center gap-1.5 rounded px-2 py-0.5 font-mono text-[10px] font-medium tabular-nums ${styles.pill}`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${styles.dot}`} />
            {badgeText}
          </span>
        </div>

        <p className="mt-2 text-[13px] font-semibold tracking-telemetry text-ink">
          {headline}
        </p>
        <p className="mt-1 text-[11.5px] leading-relaxed text-ink-secondary tabular-nums">
          {detail}
        </p>
      </div>

      <div className="no-print mt-2.5 flex items-center justify-between border-t border-hairline pt-2 font-mono text-[10px] text-ink-muted">
        <span className="inline-flex items-center gap-1 group-hover:text-signal-champagne">
          <Eye className="h-3 w-3" />
          {pinned ? "X-Ray Pinned" : "X-Ray Inspect"}
        </span>
        <span className={styles.accentText}>→</span>
      </div>
    </button>
  );
}
