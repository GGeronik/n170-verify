"use client";

import { ArrowRight, Swords } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { ARENA_PRESET_MATCHUPS, SHOWCASE_PROFILES } from "@/lib/demoFixtures.ts";
import { sanitizeProofIdSegment } from "@/lib/viralShareBuilders.ts";

export default function ArenaIndexPage() {
  const router = useRouter();
  const [slugA, setSlugA] = useState("demo-tls-alpha");
  const [slugB, setSlugB] = useState("demo-ibkr-flex");

  const handleLaunch = (e: React.FormEvent) => {
    e.preventDefault();
    const safeA = sanitizeProofIdSegment(slugA);
    const safeB = sanitizeProofIdSegment(slugB);
    router.push(`/vs/${encodeURIComponent(safeA)}/${encodeURIComponent(safeB)}`);
  };

  return (
    <div className="bg-institutional-grid">
      <div className="mx-auto max-w-7xl space-y-8 px-4 py-10 sm:px-6 lg:px-8">
        <div className="max-w-3xl space-y-2 border-b border-hairline pb-6">
          <div className="inline-flex items-center gap-2 font-mono text-[11px]">
            <span className="badge-emerald inline-flex items-center gap-1 rounded px-2 py-0.5 font-semibold uppercase tracking-wider">
              <Swords className="h-3 w-3" />
              Head-to-Head Verified Arena
            </span>
            <span className="text-ink-muted">•</span>
            <span className="text-signal-champagne">
              Synchronized Indexed-100 Wealth &amp; Drawdown Duels
            </span>
          </div>
          <h1 className="editorial-serif text-3xl text-ink sm:text-5xl">
            Compare Two Cryptographically Verified Track Records
          </h1>
          <p className="text-sm text-ink-secondary">
            Pit any two N170 proof bundles side-by-side in browser{" "}
            <code className="text-ink">window.crypto.subtle</code> with automatic
            origin-assurance, sub-account scope, and measurement-window comparability
            audits.
          </p>
        </div>

        {/* Preset Matchup Cards */}
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          {ARENA_PRESET_MATCHUPS.map((m) => (
            <Link
              key={`${m.slugA}-${m.slugB}`}
              href={`/vs/${m.slugA}/${m.slugB}`}
              className="inst-panel group flex flex-col justify-between rounded-md p-5 transition hover:border-signal-emerald"
            >
              <div>
                <span className="font-mono text-[10px] font-semibold uppercase tracking-widest text-signal-champagne">
                  {m.slugA} vs {m.slugB}
                </span>
                <h2 className="editorial-serif mt-1.5 text-xl text-ink group-hover:text-signal-emerald">
                  {m.label}
                </h2>
                <p className="mt-1.5 text-xs leading-relaxed text-ink-secondary">
                  {m.tagline}
                </p>
              </div>
              <div className="mt-4 inline-flex items-center gap-1.5 font-mono text-xs font-semibold text-signal-emerald">
                <span>Enter Verified Duel</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </div>
            </Link>
          ))}
        </div>

        {/* Custom Proof ID Launcher */}
        <form
          onSubmit={handleLaunch}
          className="inst-panel grid grid-cols-1 items-end gap-4 rounded-md p-5 md:grid-cols-12"
        >
          <div className="md:col-span-5">
            <label className="block font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-secondary">
              Contender A Proof ID / Alias
            </label>
            <input
              type="text"
              value={slugA}
              onChange={(e) => setSlugA(e.target.value)}
              list="arena-proof-options"
              className="mt-1.5 w-full rounded border border-hairline-strong bg-canvas px-3 py-2 font-mono text-xs text-ink focus:border-signal-emerald focus:outline-none"
            />
          </div>
          <div className="md:col-span-5">
            <label className="block font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-secondary">
              Contender B Proof ID / Alias
            </label>
            <input
              type="text"
              value={slugB}
              onChange={(e) => setSlugB(e.target.value)}
              list="arena-proof-options"
              className="mt-1.5 w-full rounded border border-hairline-strong bg-canvas px-3 py-2 font-mono text-xs text-ink focus:border-signal-emerald focus:outline-none"
            />
          </div>
          <div className="md:col-span-2">
            <button
              type="submit"
              className="inline-flex w-full items-center justify-center gap-1.5 rounded border border-signal-emerald bg-signal-emerald px-4 py-2 font-mono text-xs font-semibold text-canvas transition hover:opacity-90"
            >
              <span>Launch /vs</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>
          <datalist id="arena-proof-options">
            <option value="demo-tls-alpha" />
            <option value="demo-ibkr-flex" />
            <option value="demo-options-studio" />
            {SHOWCASE_PROFILES.map((p) => (
              <option key={p.proofId} value={p.proofId} />
            ))}
          </datalist>
        </form>
      </div>
    </div>
  );
}
