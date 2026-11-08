import { ImageResponse } from "next/og";
import { safeDecodeURIComponent } from "@/lib/apiClient.ts";
import { verifyProofBundle } from "@/lib/browserVerify.ts";
import {
  ACCOUNT_SCOPE_META,
  CHAIN_CONTINUITY_META,
  ORIGIN_ASSURANCE_META,
  RECONCILIATION_STATUS_META,
  ReconciliationStatus,
  SIGNER_TRUST_META,
  extractTypedLeaves,
} from "@/lib/contracts.ts";
import {
  BUNDLE_INSTITUTIONAL_FUND,
  DEMO_CONTINUITY_LOG_LEAVES,
  DEMO_REGISTRY_DOCUMENT,
  findShowcaseProfile,
} from "@/lib/demoFixtures.ts";

export const alt = "N170 Verify v3 Institutional Performance Tear Sheet";
export const size = {
  width: 1200,
  height: 630,
};
export const contentType = "image/png";

export default async function OpenGraphImage({
  params,
}: {
  params: Promise<{ proofId: string }>;
}) {
  const { proofId } = await params;
  const profile = findShowcaseProfile(safeDecodeURIComponent(proofId));
  const bundle = profile?.bundle ?? BUNDLE_INSTITUTIONAL_FUND;

  const verified = await verifyProofBundle(bundle, {
    registryDoc: DEMO_REGISTRY_DOCUMENT,
    chainHistory: profile?.chainHistory ?? [],
    continuityLogLeaves:
      bundle.proof_id === "prf-inst-alpha-012" ? DEMO_CONTINUITY_LOG_LEAVES : null,
  });

  const leaves = extractTypedLeaves(bundle);
  const twrPct =
    leaves.coreMetrics != null
      ? `${leaves.coreMetrics.twr_decimal >= 0 ? "+" : ""}${(
          leaves.coreMetrics.twr_decimal * 100
        ).toFixed(2)}%`
      : "Redacted";

  const psrGlm =
    leaves.coreMetrics?.psr_sample_eligible &&
    leaves.coreMetrics.psr_glm_unsmoothed != null
      ? `${(leaves.coreMetrics.psr_glm_unsmoothed * 100).toFixed(1)}%`
      : `Gated (T=${leaves.coreMetrics?.observation_count ?? 0}<30)`;

  const maxDd =
    leaves.coreMetrics != null
      ? `-${Math.abs(leaves.coreMetrics.max_drawdown_decimal * 100).toFixed(2)}%`
      : "—";

  const reconStatus =
    leaves.reconciliation?.status ?? ReconciliationStatus.REFERENCE_DATA_UNAVAILABLE;

  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          justifyContent: "space-between",
          backgroundColor: "#090A0D",
          color: "#F3F4F6",
          padding: "52px 60px",
          fontFamily: "sans-serif",
          border: "2px solid rgba(255,255,255,0.12)",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
            <div
              style={{
                display: "flex",
                padding: "8px 14px",
                borderRadius: "4px",
                backgroundColor: "rgba(214, 179, 106, 0.14)",
                border: "1px solid rgba(214, 179, 106, 0.45)",
                color: "#D6B36A",
                fontSize: "20px",
                fontWeight: 700,
              }}
            >
              N170 VERIFY v3
            </div>
            <div style={{ fontSize: "20px", color: "#8A919E" }}>
              {profile?.handle ?? bundle.proof_id} • Institutional Cryptographic Proof
            </div>
          </div>
          <div
            style={{
              display: "flex",
              padding: "8px 16px",
              borderRadius: "4px",
              backgroundColor: verified.valid
                ? "rgba(16, 185, 129, 0.16)"
                : "rgba(239, 68, 68, 0.18)",
              color: verified.valid ? "#10B981" : "#EF4444",
              fontSize: "17px",
              fontWeight: 700,
            }}
          >
            {verified.valid ? "WEBCRYPTO ED25519 VERIFIED" : "VERIFICATION REJECTED"}
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: "22px" }}>
          <div style={{ fontSize: "44px", fontWeight: 600, color: "#F3F4F6" }}>
            {profile?.strategyTitle ?? `Verified Tear Sheet (${bundle.proof_id})`}
          </div>

          <div style={{ display: "flex", gap: "24px" }}>
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                padding: "20px 28px",
                borderRadius: "6px",
                backgroundColor: "#101217",
                border: "1px solid rgba(255,255,255,0.1)",
                minWidth: "280px",
              }}
            >
              <span style={{ fontSize: "15px", color: "#8A919E" }}>
                CUMULATIVE TWR (INDEXED-100)
              </span>
              <span style={{ fontSize: "44px", fontWeight: 700, color: "#10B981" }}>
                {twrPct}
              </span>
            </div>

            <div
              style={{
                display: "flex",
                flexDirection: "column",
                padding: "20px 28px",
                borderRadius: "6px",
                backgroundColor: "#101217",
                border: "1px solid rgba(255,255,255,0.1)",
                minWidth: "260px",
              }}
            >
              <span style={{ fontSize: "15px", color: "#8A919E" }}>
                PSR (GLM UNSMOOTHED)
              </span>
              <span style={{ fontSize: "44px", fontWeight: 700, color: "#F3F4F6" }}>
                {psrGlm}
              </span>
            </div>

            <div
              style={{
                display: "flex",
                flexDirection: "column",
                padding: "20px 28px",
                borderRadius: "6px",
                backgroundColor: "#101217",
                border: "1px solid rgba(255,255,255,0.1)",
                minWidth: "240px",
              }}
            >
              <span style={{ fontSize: "15px", color: "#8A919E" }}>MAX DRAWDOWN</span>
              <span style={{ fontSize: "44px", fontWeight: 700, color: "#EF4444" }}>
                {maxDd}
              </span>
            </div>
          </div>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
          <div style={{ display: "flex", gap: "14px", fontSize: "15px" }}>
            <div
              style={{
                display: "flex",
                padding: "10px 16px",
                borderRadius: "4px",
                backgroundColor: "#101217",
                border: "1px solid rgba(214, 179, 106, 0.35)",
                color: "#D6B36A",
              }}
            >
              Origin: {ORIGIN_ASSURANCE_META[verified.effective_origin_assurance].shortLabel}
            </div>
            <div
              style={{
                display: "flex",
                padding: "10px 16px",
                borderRadius: "4px",
                backgroundColor: "#101217",
                border: "1px solid rgba(255,255,255,0.12)",
                color: "#F3F4F6",
              }}
            >
              Signer: {SIGNER_TRUST_META[verified.signer_trust_status].shortLabel}
            </div>
            <div
              style={{
                display: "flex",
                padding: "10px 16px",
                borderRadius: "4px",
                backgroundColor: "#101217",
                border: "1px solid rgba(255,255,255,0.12)",
                color: "#F3F4F6",
              }}
            >
              Recon: {RECONCILIATION_STATUS_META[reconStatus].shortLabel}
            </div>
            <div
              style={{
                display: "flex",
                padding: "10px 16px",
                borderRadius: "4px",
                backgroundColor: "#101217",
                border: "1px solid rgba(255,255,255,0.12)",
                color: "#F3F4F6",
              }}
            >
              Scope: {ACCOUNT_SCOPE_META[bundle.account_scope].shortLabel} •{" "}
              {CHAIN_CONTINUITY_META[verified.effective_chain_continuity_mode].shortLabel}
            </div>
          </div>

          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              fontSize: "14px",
              color: "#8A919E",
            }}
          >
            <span>proof_hash: {verified.proof_hash}</span>
            <span>Zero Dollar NAV Disclosed</span>
          </div>
        </div>
      </div>
    ),
    size,
  );
}
