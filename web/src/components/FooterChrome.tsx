"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

export function FooterChrome() {
  const pathname = usePathname();
  if (pathname?.startsWith("/embed")) {
    return null;
  }

  return (
    <footer className="no-print border-t border-hairline bg-panel/80 py-8 text-xs text-ink-muted">
      <div className="mx-auto flex max-w-7xl flex-col items-start justify-between gap-5 px-4 sm:flex-row sm:items-center sm:px-6 lg:px-8">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2.5">
            <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-ink">
              N170 VERIFY PROTOCOL
            </span>
            <span className="text-hairline-strong">•</span>
            <span className="font-mono text-[11px] text-signal-emerald">
              APACHE-2.0 OPEN STANDARD
            </span>
          </div>
          <p className="max-w-2xl text-[12px] leading-relaxed text-ink-muted">
            Read-only cryptographic provenance • Salted 7-leaf RFC 8785 JCS Merkle commitments •
            Zero dollar-NAV leakage • Client-side WebCrypto Ed25519 verification.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-4 font-mono text-[11px]">
          <a
            href="/.well-known/n170-verify-keys.json"
            target="_blank"
            rel="noreferrer"
            className="text-signal-champagne underline-offset-4 transition hover:underline"
          >
            /.well-known/n170-verify-keys.json
          </a>
          <Link
            href="/tools/plausibility"
            className="text-ink-secondary transition hover:text-ink"
          >
            MinTRL Buster
          </Link>
          <Link
            href="/vs/demo-tls-alpha/demo-ibkr-flex"
            className="text-ink-secondary transition hover:text-ink"
          >
            /vs Arena
          </Link>
          <Link href="/challenge" className="text-ink-secondary transition hover:text-ink">
            Polite Challenge
          </Link>
          <Link href="/verify" className="text-ink-secondary transition hover:text-ink">
            WebCrypto Verifier
          </Link>
          <Link href="/connect" className="text-ink-secondary transition hover:text-ink">
            Read-Only Scope Spec
          </Link>
        </div>
      </div>
    </footer>
  );
}
