"use client";

import {
  ArrowRight,
  Check,
  Copy,
  EyeOff,
  Lock,
  MessageSquareHeart,
  ShieldCheck,
} from "lucide-react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useMemo, useState } from "react";
import {
  buildPoliteChallengeReply,
  type ChallengeTone,
} from "@/lib/plausibilityMath.ts";
import { generateQrCode } from "@/lib/qrSvg.ts";

const TONE_OPTIONS: { id: ChallengeTone; label: string; desc: string }[] = [
  {
    id: "peer_quant",
    label: "Peer Quant (Warm)",
    desc: "Collegial Fintwit / Discord / Substack invitation celebrating strong numbers.",
  },
  {
    id: "professional",
    label: "Professional Peer",
    desc: "Allocator & peer-review framing for portfolio managers and systematic desks.",
  },
  {
    id: "concise_reply",
    label: "Concise Thread Reply",
    desc: "Compact single-sentence reply optimized for X / Reddit character limits.",
  },
];

export default function PoliteChallengePage() {
  return (
    <Suspense
      fallback={
        <div className="mx-auto max-w-7xl px-4 py-16 font-mono text-xs text-ink-muted">
          Preparing Diplomatic Proof Invitation Studio…
        </div>
      }
    >
      <PoliteChallengeStudio />
    </Suspense>
  );
}

function PoliteChallengeStudio() {
  const searchParams = useSearchParams();

  const [rawHandle, setRawHandle] = useState(
    () => searchParams.get("handle") ?? "@systematic_alpha",
  );
  const [rawClaim, setRawClaim] = useState(
    () => searchParams.get("claim") ?? "+84.5% YTD (Sharpe 3.1)",
  );
  const [rawContext, setRawContext] = useState(
    () => searchParams.get("context") ?? "Multi-Asset / Options",
  );
  const [tone, setTone] = useState<ChallengeTone>("peer_quant");
  const [copiedKey, setCopiedKey] = useState<"reply" | "url" | null>(null);

  useEffect(() => {
    const h = searchParams.get("handle");
    const c = searchParams.get("claim");
    const ctx = searchParams.get("context");
    if (h) setRawHandle(h);
    if (c) setRawClaim(c);
    if (ctx) setRawContext(ctx);
  }, [searchParams]);

  const originUrl =
    typeof window !== "undefined" && window.location?.origin
      ? window.location.origin
      : "https://verify.example.org";

  const generated = useMemo(
    () =>
      buildPoliteChallengeReply({
        handle: rawHandle,
        claimText: rawClaim,
        assetContext: rawContext,
        tone,
        originUrl,
      }),
    [rawHandle, rawClaim, rawContext, tone, originUrl],
  );

  const connectQr = useMemo(
    () => generateQrCode(`${originUrl}/connect`),
    [originUrl],
  );

  const handleCopy = async (key: "reply" | "url", text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => {
        setCopiedKey((prev) => (prev === key ? null : prev));
      }, 1800);
    } catch {
      // Clipboard fallback
    }
  };

  return (
    <div className="bg-telemetry-grid">
      <div className="mx-auto max-w-7xl space-y-8 px-4 py-10 sm:px-6 lg:px-8">
        {/* Masthead */}
        <div className="flex flex-col justify-between gap-4 border-b border-hairline pb-6 lg:flex-row lg:items-end">
          <div className="max-w-3xl space-y-2">
            <div className="flex flex-wrap items-center gap-2 font-mono text-[11px]">
              <span className="badge-emerald rounded px-2 py-0.5 font-semibold uppercase tracking-wider">
                Constructive Peer Standard • Zero Hostility
              </span>
              <span className="text-ink-muted">•</span>
              <span className="text-signal-champagne">
                60-Second Read-Only Proof • Private Dollar NAV &amp; Open Positions
              </span>
            </div>
            <h1 className="editorial-serif text-3xl text-ink sm:text-5xl">
              Polite Cryptographic Proof Invitation Generator
            </h1>
            <p className="text-sm leading-relaxed text-ink-secondary">
              Invite any trader, educator, or emerging manager to verify pure percentage
              returns on N170 Verify in 60 seconds, removing every legitimate privacy
              objection around account size, account IDs, or front-running live positions.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <Link
              href="/tools/plausibility"
              className="inline-flex items-center gap-1.5 rounded border border-hairline-strong bg-panel px-3.5 py-2.5 font-mono text-xs text-ink transition hover:border-signal-champagne"
            >
              <span>Run MinTRL Calculator</span>
            </Link>
            <Link
              href="/connect"
              className="inline-flex items-center gap-1.5 rounded border border-signal-emerald bg-signal-emerald px-4 py-2.5 font-mono text-xs font-semibold text-canvas transition hover:opacity-90"
            >
              <span>Verify Your Own Return (60s)</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </Link>
          </div>
        </div>

        {/* Main 12-Column Studio */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          {/* Left 5 Cols: Sanitized Inputs & Tone Selector */}
          <div className="peer-panel space-y-5 rounded-md p-5 lg:col-span-5">
            <div className="flex items-center gap-2 border-b border-hairline pb-3">
              <MessageSquareHeart className="h-4 w-4 text-signal-emerald" />
              <h2 className="text-sm font-semibold tracking-telemetry text-ink">
                Customize Diplomatic Invitation
              </h2>
            </div>

            <div className="space-y-3.5">
              <div>
                <label className="block font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-secondary">
                  Peer Handle or Strategy Name (Sanitized)
                </label>
                <input
                  type="text"
                  maxLength={40}
                  value={rawHandle}
                  onChange={(e) => setRawHandle(e.target.value)}
                  placeholder="@trader_handle"
                  className="mt-1.5 w-full rounded border border-hairline-strong bg-canvas px-3 py-2 font-mono text-xs text-ink focus:border-signal-emerald focus:outline-none"
                />
              </div>

              <div>
                <label className="block font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-secondary">
                  Shared Return / Sharpe Milestone
                </label>
                <input
                  type="text"
                  maxLength={72}
                  value={rawClaim}
                  onChange={(e) => setRawClaim(e.target.value)}
                  placeholder="+120% YTD or Sharpe 3.4"
                  className="mt-1.5 w-full rounded border border-hairline-strong bg-canvas px-3 py-2 font-mono text-xs text-ink focus:border-signal-emerald focus:outline-none"
                />
              </div>

              <div>
                <label className="block font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-secondary">
                  Asset Class / Brokerage Context (Optional)
                </label>
                <input
                  type="text"
                  maxLength={48}
                  value={rawContext}
                  onChange={(e) => setRawContext(e.target.value)}
                  placeholder="IBKR Multi-Asset / Futures / Crypto"
                  className="mt-1.5 w-full rounded border border-hairline-strong bg-canvas px-3 py-2 font-mono text-xs text-ink focus:border-signal-emerald focus:outline-none"
                />
              </div>
            </div>

            {/* Tone Selector */}
            <div className="space-y-2 border-t border-hairline pt-4">
              <span className="block font-mono text-[11px] font-semibold uppercase tracking-wider text-signal-champagne">
                Reply Tone
              </span>
              <div className="space-y-2">
                {TONE_OPTIONS.map((opt) => {
                  const active = tone === opt.id;
                  return (
                    <button
                      key={opt.id}
                      type="button"
                      onClick={() => setTone(opt.id)}
                      className={`w-full rounded border p-3 text-left transition ${
                        active
                          ? "border-signal-emerald bg-elevated ring-1 ring-signal-emerald"
                          : "border-hairline bg-canvas hover:border-ink-muted"
                      }`}
                    >
                      <span className="block font-mono text-xs font-semibold text-ink">
                        {opt.label}
                      </span>
                      <span className="mt-0.5 block text-[11px] text-ink-secondary">
                        {opt.desc}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* 1-Click Copy Reply Box */}
            <div className="space-y-2.5 border-t border-hairline pt-4">
              <div className="flex items-center justify-between font-mono text-[11px]">
                <span className="font-semibold text-ink">
                  Ready-to-Paste Polite Reply
                </span>
                <span className="text-ink-muted tabular-nums">
                  {generated.replyText.length} chars
                </span>
              </div>
              <div className="rounded border border-hairline bg-elevated p-3 font-sans text-xs leading-relaxed text-ink">
                {generated.replyText}
              </div>

              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                <button
                  type="button"
                  onClick={() => void handleCopy("reply", generated.replyText)}
                  className="inline-flex items-center justify-center gap-1.5 rounded border border-signal-emerald bg-signal-emerald px-3 py-2 font-mono text-xs font-semibold text-canvas transition hover:opacity-90"
                >
                  {copiedKey === "reply" ? (
                    <>
                      <Check className="h-3.5 w-3.5" />
                      <span>Copied Reply Text</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3.5 w-3.5" />
                      <span>1-Click Copy Reply</span>
                    </>
                  )}
                </button>

                <button
                  type="button"
                  onClick={() => void handleCopy("url", generated.challengeUrl)}
                  className="inline-flex items-center justify-center gap-1.5 rounded border border-hairline-strong bg-panel px-3 py-2 font-mono text-xs text-ink transition hover:border-signal-champagne"
                >
                  {copiedKey === "url" ? (
                    <>
                      <Check className="h-3.5 w-3.5 text-signal-emerald" />
                      <span>Copied Invite Link</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3.5 w-3.5 text-signal-champagne" />
                      <span>Copy Invite URL</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>

          {/* Right 7 Cols: Camera-Ready Diplomatic Invitation Card */}
          <div className="peer-panel flex flex-col justify-between space-y-5 rounded-md bg-telemetry-grid p-5 sm:p-7 lg:col-span-7">
            <div className="relative overflow-hidden rounded-md border border-hairline-strong bg-canvas p-6 shadow-2xl">
              <div className="absolute inset-x-0 top-0 h-[3px] bg-signal-emerald" />

              <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
                <div className="space-y-2">
                  <div className="flex flex-wrap items-center gap-2 font-mono text-[10.5px]">
                    <span className="badge-champagne rounded px-2 py-0.5 font-semibold uppercase tracking-wider">
                      PEER INVITATION • APACHE-2.0 OPEN VERIFIER
                    </span>
                    {generated.sanitizedContext && (
                      <span className="rounded border border-hairline-strong bg-elevated px-2 py-0.5 text-ink-secondary">
                        {generated.sanitizedContext}
                      </span>
                    )}
                  </div>

                  <h3 className="editorial-serif text-2xl text-ink sm:text-3xl">
                    {generated.sanitizedHandle
                      ? `Invitation for ${generated.sanitizedHandle}`
                      : "Cryptographic Percentage Tear-Sheet Invitation"}
                  </h3>

                  {generated.sanitizedClaim && (
                    <p className="font-mono text-xs text-signal-emerald">
                      Referenced Milestone: <strong>{generated.sanitizedClaim}</strong>
                    </p>
                  )}
                </div>

                {/* Inline Scannable QR Code to /connect */}
                <div className="shrink-0 self-start rounded border border-hairline-strong bg-panel p-2 text-center">
                  <svg
                    viewBox={`-1 -1 ${connectQr.size + 2} ${connectQr.size + 2}`}
                    className="h-16 w-16 text-ink"
                    aria-label="Scan to open 60-second read-only connect studio"
                  >
                    <path
                      d={connectQr.svgPath}
                      fill="currentColor"
                      shapeRendering="crispEdges"
                    />
                  </svg>
                  <span className="mt-1 block font-mono text-[8.5px] uppercase text-ink-muted">
                    60s Setup
                  </span>
                </div>
              </div>

              <p className="mt-4 text-xs leading-relaxed text-ink-secondary sm:text-sm">
                N170 Verify lets systematic traders and portfolio managers publish a
                client-verifiable <code className="text-ink">Indexed-100</code> performance
                proof in 60 seconds while keeping all sensitive portfolio details strictly
                redacted:
              </p>

              {/* 3 Privacy Guarantees */}
              <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-3">
                <PrivacyGuaranteeCard
                  icon={<EyeOff className="h-4 w-4 text-signal-emerald" />}
                  title="$ NAV Stays Private"
                  desc="All curves rebase to Index = 100.00. Exact dollar deposits, withdrawals, and net worth never enter the public bundle."
                />
                <PrivacyGuaranteeCard
                  icon={<Lock className="h-4 w-4 text-signal-champagne" />}
                  title="Zero Account ID or Write Keys"
                  desc="Account IDs are HMAC-blinded. Read-only scope gates hard-abort any key carrying trading or withdrawal permissions."
                />
                <PrivacyGuaranteeCard
                  icon={<ShieldCheck className="h-4 w-4 text-signal-emerald" />}
                  title="7-Day Open-Position Guard"
                  desc="Live open holdings are never exposed. Optional closed trade percentages enforce a strict 7-day front-running embargo."
                />
              </div>

              <div className="mt-5 flex flex-wrap items-center justify-between gap-2 border-t border-hairline pt-3 font-mono text-[10.5px] text-ink-muted">
                <span>
                  Subprocess Isolation: <code className="text-ink">RLIMIT_CORE=0</code> •{" "}
                  <code className="text-ink">no_persistent_storage</code> default
                </span>
                <span className="text-signal-emerald">verify.example.org/connect</span>
              </div>
            </div>

            {/* Bottom Action Bar */}
            <div className="flex flex-wrap items-center justify-between gap-3 rounded border border-hairline bg-elevated p-4 font-mono text-xs">
              <span className="text-ink-secondary">
                Want to see what a finished cryptographic tear sheet looks like first?
              </span>
              <div className="flex flex-wrap gap-2">
                <Link
                  href="/p/demo-tls-alpha"
                  className="rounded border border-hairline-strong bg-panel px-3 py-1.5 text-ink transition hover:border-signal-emerald"
                >
                  Inspect Live Tear Sheet →
                </Link>
                <Link
                  href="/vs/demo-tls-alpha/demo-ibkr-flex"
                  className="rounded border border-signal-champagne-border bg-signal-champagne-bg px-3 py-1.5 text-signal-champagne transition hover:border-signal-champagne"
                >
                  Open /vs Arena →
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function PrivacyGuaranteeCard({
  icon,
  title,
  desc,
}: {
  icon: React.ReactNode;
  title: string;
  desc: string;
}) {
  return (
    <div className="rounded border border-hairline bg-panel p-3.5">
      <div className="flex items-center gap-2">
        {icon}
        <h4 className="font-mono text-[11px] font-semibold text-ink">{title}</h4>
      </div>
      <p className="mt-1.5 text-[11px] leading-relaxed text-ink-secondary">{desc}</p>
    </div>
  );
}
