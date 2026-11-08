"use client";

import { FileText, Moon, ShieldCheck, Sun } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTheme } from "@/components/ThemeProvider.tsx";

const NAV_ITEMS = [
  { href: "/", label: "Dissector", matchPrefix: null },
  { href: "/connect", label: "Connect", matchPrefix: "/connect" },
  { href: "/p/prf-inst-alpha-012", label: "Tear Sheet", matchPrefix: "/p/" },
  {
    href: "/tools/plausibility",
    label: "MinTRL Buster",
    matchPrefix: "/tools/plausibility",
  },
  {
    href: "/vs/demo-tls-alpha/demo-ibkr-flex",
    label: "/vs Arena",
    matchPrefix: "/vs",
  },
  { href: "/challenge", label: "Challenge", matchPrefix: "/challenge" },
  { href: "/leaderboard", label: "Registry", matchPrefix: "/leaderboard" },
] as const;

export function Navbar() {
  const pathname = usePathname();
  const { theme, toggleTheme } = useTheme();

  if (pathname?.startsWith("/embed")) {
    return null;
  }

  const isVerifyActive = pathname?.startsWith("/verify");

  return (
    <header className="no-print sticky top-0 z-40 border-b border-hairline bg-canvas/90 backdrop-blur-md">
      <div className="mx-auto flex max-w-7xl items-center justify-between gap-3 px-4 py-3 sm:px-6 lg:px-8">
        {/* Brand Masthead */}
        <div className="flex items-center gap-3.5">
          <Link href="/" className="group flex items-center gap-2.5">
            <span className="flex h-8 w-8 items-center justify-center rounded border border-signal-champagne-border bg-signal-champagne-bg font-mono text-[11px] font-bold tracking-tight text-signal-champagne transition group-hover:border-signal-champagne">
              N170
            </span>
            <div className="leading-tight">
              <div className="flex items-center gap-2">
                <span className="text-[14px] font-semibold tracking-telemetry text-ink">
                  N170 Verify
                </span>
                <span className="rounded border border-hairline-strong bg-elevated px-1.5 py-0.5 font-mono text-[10px] font-medium text-ink-secondary">
                  v3.0
                </span>
              </div>
              <p className="hidden font-mono text-[10px] uppercase tracking-wider text-ink-muted xl:block">
                Cryptographic Provenance • Archival Tear Sheets
              </p>
            </div>
          </Link>

          <span className="hidden items-center gap-1.5 rounded border border-signal-emerald-border bg-signal-emerald-bg px-2 py-0.5 font-mono text-[10px] font-medium text-signal-emerald lg:inline-flex">
            <span className="h-1.5 w-1.5 rounded-full bg-signal-emerald" />
            WebCrypto Ed25519 Ready
          </span>
        </div>

        {/* Desktop Primary Navigation */}
        <nav className="hidden items-center gap-1 md:flex" aria-label="Primary">
          {NAV_ITEMS.map((item) => {
            const active =
              item.matchPrefix === null
                ? pathname === "/"
                : Boolean(pathname?.startsWith(item.matchPrefix));
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`rounded px-2.5 py-1.5 text-xs font-medium tracking-telemetry transition ${
                  active
                    ? "bg-elevated text-ink shadow-[inset_0_0_0_1px_var(--border-strong)]"
                    : "text-ink-secondary hover:bg-elevated/70 hover:text-ink"
                }`}
              >
                {item.label}
              </Link>
            );
          })}
        </nav>

        {/* Right Controls: 1-Click Obsidian / LP Archival Paper Toggle + Verifier CTA */}
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={toggleTheme}
            aria-label={
              theme === "obsidian"
                ? "Switch to LP Archival Paper theme"
                : "Switch to Institutional Obsidian theme"
            }
            title="1-Click Institutional Theme Toggle (Obsidian Telemetry / LP Archival Paper)"
            className="inline-flex items-center gap-1.5 rounded border border-hairline-strong bg-panel px-2.5 py-1.5 font-mono text-[11px] font-medium text-ink-secondary transition hover:border-signal-champagne hover:text-ink"
          >
            {theme === "obsidian" ? (
              <>
                <Moon className="h-3.5 w-3.5 text-signal-champagne" />
                <span className="hidden sm:inline">Obsidian</span>
                <span className="text-ink-muted">/</span>
                <FileText className="h-3 w-3 text-ink-muted" />
                <span className="hidden text-ink-muted lg:inline">Paper</span>
              </>
            ) : (
              <>
                <Sun className="h-3.5 w-3.5 text-signal-champagne" />
                <span className="hidden sm:inline">Archival Paper</span>
              </>
            )}
          </button>

          <Link
            href="/verify"
            className={`inline-flex items-center gap-1.5 rounded px-3 py-1.5 text-xs font-semibold tracking-telemetry transition ${
              isVerifyActive
                ? "border border-signal-emerald bg-signal-emerald text-canvas"
                : "border border-signal-emerald-border bg-signal-emerald-bg text-signal-emerald hover:border-signal-emerald"
            }`}
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            <span>Verify</span>
          </Link>
        </div>
      </div>

      {/* Compact Mobile Telemetry Nav Strip (< 768px) */}
      <nav
        aria-label="Mobile Primary"
        className="flex items-center gap-1 overflow-x-auto border-t border-hairline bg-panel/70 px-3 py-1.5 md:hidden"
      >
        {NAV_ITEMS.map((item) => {
          const active =
            item.matchPrefix === null
              ? pathname === "/"
              : Boolean(pathname?.startsWith(item.matchPrefix));
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`rounded px-2 py-1 text-[11px] font-medium transition ${
                active
                  ? "bg-elevated text-ink shadow-[inset_0_0_0_1px_var(--border-strong)]"
                  : "text-ink-muted hover:text-ink"
              }`}
            >
              {item.label}
            </Link>
          );
        })}
      </nav>
    </header>
  );
}
