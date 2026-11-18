import Link from "next/link";
import { TearSheetView } from "@/components/TearSheetView.tsx";
import {
  fetchActiveRegistryDocument,
  resolveShowcaseOrLiveProfile,
  safeDecodeURIComponent,
} from "@/lib/apiClient.ts";
import {
  DEMO_CONTINUITY_LOG_LEAVES,
  SHOWCASE_PROFILES,
} from "@/lib/demoFixtures.ts";
import { sanitizePlainInput } from "@/lib/plausibilityMath.ts";

export default async function ProofTearSheetPage({
  params,
}: {
  params: Promise<{ proofId: string }>;
}) {
  const { proofId } = await params;
  const decodedId = safeDecodeURIComponent(proofId);
  const safeDisplayId = sanitizePlainInput(decodedId, 64);
  const [{ registryDoc }, profile] = await Promise.all([
    fetchActiveRegistryDocument(),
    resolveShowcaseOrLiveProfile(decodedId, {
      subtitleLabel: "Published Proof Record",
    }),
  ]);

  if (!profile) {
    return (
      <div className="bg-telemetry-grid py-16">
        <div className="mx-auto max-w-4xl px-4 sm:px-6">
          <div className="inst-panel rounded-md p-8 text-center">
            <p className="font-mono text-xs font-semibold uppercase tracking-widest text-signal-ochre">
              Zero-Retention Proof Lookup
            </p>
            <h1 className="editorial-serif mt-2 text-3xl text-ink">
              Proof Bundle <code className="text-signal-emerald">{safeDisplayId}</code> Not
              Hosted on Server
            </h1>
            <p className="mx-auto mt-3 max-w-xl text-sm text-ink-secondary">
              By default, N170 Verify executes in{" "}
              <code className="text-ink">no_persistent_storage</code> mode and never
              retains user proof bundles unless explicitly published. Drop your local{" "}
              <code className="text-ink">.verify.json</code> file into the offline
              verifier or inspect a signed public showcase specimen below.
            </p>

            <div className="mt-6 flex flex-wrap justify-center gap-2.5">
              <Link
                href="/verify"
                className="rounded border border-signal-emerald bg-signal-emerald px-5 py-2.5 font-mono text-xs font-semibold text-canvas transition hover:opacity-90"
              >
                Verify Local .json Bundle →
              </Link>
              {SHOWCASE_PROFILES.map((item) => (
                <Link
                  key={item.proofId}
                  href={`/p/${item.proofId}`}
                  className="rounded border border-hairline-strong bg-elevated px-3.5 py-2.5 font-mono text-xs text-ink transition hover:border-signal-champagne"
                >
                  {item.proofId}
                </Link>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  }

  const defaultTab =
    profile.previewMode === "discrepancy_xray"
      ? "reconciliation"
      : profile.previewMode === "coaching_studio"
        ? "coaching"
        : "performance";

  const useContinuityLog = profile.proofId === "prf-inst-alpha-012";

  return (
    <div className="bg-telemetry-grid">
      <div className="mx-auto max-w-7xl space-y-6 px-4 py-8 sm:px-6 lg:px-8">
        {/* Screen-Only Specimen Switcher Strip (Hidden on Cmd+P Print) */}
        <div className="no-print inst-panel flex flex-wrap items-center justify-between gap-2 rounded-md px-4 py-2.5 text-xs">
          <span className="font-mono text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
            Signed Archival Specimens:
          </span>
          <div className="flex flex-wrap items-center gap-1.5">
            {SHOWCASE_PROFILES.map((item) => {
              const active = item.proofId === profile.proofId;
              return (
                <Link
                  key={item.proofId}
                  href={`/p/${item.proofId}`}
                  className={`rounded border px-2.5 py-1 font-mono text-[11px] transition tabular-nums ${
                    active
                      ? "border-signal-champagne bg-signal-champagne-bg font-semibold text-signal-champagne"
                      : "border-hairline bg-elevated text-ink-secondary hover:border-ink-muted hover:text-ink"
                  }`}
                >
                  {item.handle} ({item.proofId})
                </Link>
              );
            })}
          </div>
        </div>

        <TearSheetView
          bundle={profile.bundle}
          registryDoc={registryDoc}
          chainHistory={profile.chainHistory}
          continuityLogLeaves={
            useContinuityLog ? DEMO_CONTINUITY_LOG_LEAVES : undefined
          }
          title={profile.strategyTitle}
          subtitle={profile.subtitle}
          handle={profile.handle}
          defaultTab={defaultTab}
        />
      </div>
    </div>
  );
}
