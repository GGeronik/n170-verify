import Link from "next/link";
import {
  HeadToHeadArena,
  type ArenaContenderSpec,
} from "@/components/HeadToHeadArena.tsx";
import {
  fetchActiveRegistryDocument,
  resolveShowcaseOrLiveProfile,
  safeDecodeURIComponent,
} from "@/lib/apiClient.ts";
import {
  ARENA_PRESET_MATCHUPS,
  DEMO_CONTINUITY_LOG_LEAVES,
} from "@/lib/demoFixtures.ts";
import { sanitizePlainInput } from "@/lib/plausibilityMath.ts";

async function resolveArenaContender(
  rawSlug: string,
): Promise<ArenaContenderSpec | null> {
  const decoded = safeDecodeURIComponent(rawSlug).trim();
  const profile = await resolveShowcaseOrLiveProfile(decoded);
  if (!profile) {
    return null;
  }
  return {
    routeSlug: decoded,
    handle: profile.handle,
    strategyTitle: profile.strategyTitle,
    brokerDisplay: profile.brokerDisplay,
    bundle: profile.bundle,
    chainHistory: profile.chainHistory,
    continuityLogLeaves:
      profile.proofId === "prf-inst-alpha-012"
        ? DEMO_CONTINUITY_LOG_LEAVES
        : undefined,
  };
}

export default async function HeadToHeadArenaPage({
  params,
}: {
  params: Promise<{ proofA: string; proofB: string }>;
}) {
  const { proofA, proofB } = await params;
  const [{ registryDoc }, contenderA, contenderB] = await Promise.all([
    fetchActiveRegistryDocument(),
    resolveArenaContender(proofA),
    resolveArenaContender(proofB),
  ]);

  if (!contenderA || !contenderB) {
    const safeA = sanitizePlainInput(safeDecodeURIComponent(proofA), 48);
    const safeB = sanitizePlainInput(safeDecodeURIComponent(proofB), 48);
    return (
      <div className="bg-institutional-grid py-16">
        <div className="mx-auto max-w-4xl px-4 sm:px-6">
          <div className="inst-panel space-y-4 rounded-md p-8 text-center">
            <p className="font-mono text-xs font-semibold uppercase tracking-widest text-signal-ochre">
              Zero-Retention Arena Lookup
            </p>
            <h1 className="editorial-serif text-3xl text-ink">
              One or More Contenders Not Found ({safeA} vs {safeB})
            </h1>
            <p className="mx-auto max-w-xl text-sm text-ink-secondary">
              Only published proof bundles or signed public showcase aliases (e.g.{" "}
              <code className="text-ink">demo-tls-alpha</code> and{" "}
              <code className="text-ink">demo-ibkr-flex</code>) can be compared via URL.
            </p>

            <div className="flex flex-wrap justify-center gap-2.5 pt-2">
              {ARENA_PRESET_MATCHUPS.map((m) => (
                <Link
                  key={`${m.slugA}-${m.slugB}`}
                  href={`/vs/${m.slugA}/${m.slugB}`}
                  className="rounded border border-signal-emerald bg-signal-emerald px-4 py-2 font-mono text-xs font-semibold text-canvas transition hover:opacity-90"
                >
                  {m.label} →
                </Link>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-institutional-grid">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        <HeadToHeadArena
          contenderA={contenderA}
          contenderB={contenderB}
          registryDoc={registryDoc}
        />
      </div>
    </div>
  );
}
