import type { Metadata } from "next";
import type { ReactNode } from "react";
import { FooterChrome } from "@/components/FooterChrome.tsx";
import { Navbar } from "@/components/Navbar.tsx";
import { ThemeProvider } from "@/components/ThemeProvider.tsx";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "N170 Verify v3 — Institutional Cryptographic Performance & Ledger Provenance",
    template: "%s | N170 Verify v3",
  },
  description:
    "Open-source Apache-2.0 brokerage performance verification with k>=2 org/ASN-disjoint MPC-TLS witnesses, salted RFC 8785 JCS Merkle selective disclosure, calibrated accounting reconciliation, and institutional coaching telemetry.",
};

const THEME_BOOT_SCRIPT = `(function(){try{var p=new URLSearchParams(window.location.search).get('theme');var s=window.localStorage.getItem('n170-verify-theme');var t=(p==='paper'||p==='obsidian')?p:((s==='paper'||s==='obsidian')?s:'obsidian');document.documentElement.setAttribute('data-theme',t);}catch(e){document.documentElement.setAttribute('data-theme','obsidian');}})();`;

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html
      lang="en"
      data-theme="obsidian"
      suppressHydrationWarning
      className="font-sans antialiased"
    >
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_BOOT_SCRIPT }} />
      </head>
      <body className="min-h-screen bg-canvas text-ink selection:bg-signal-emerald-bg selection:text-ink">
        <ThemeProvider>
          <div className="flex min-h-screen flex-col">
            <Navbar />
            <main className="flex-1">{children}</main>
            <FooterChrome />
          </div>
        </ThemeProvider>
      </body>
    </html>
  );
}
