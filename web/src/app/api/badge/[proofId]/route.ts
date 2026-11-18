import { NextResponse } from "next/server";
import {
  fetchActiveRegistryDocument,
  resolveShowcaseOrLiveProfile,
  safeDecodeURIComponent,
} from "@/lib/apiClient.ts";
import { renderArchivalBadgeSvg, xmlEscape } from "@/lib/badgeSvg.ts";
import { verifyProofBundle } from "@/lib/browserVerify.ts";
import { DEMO_CONTINUITY_LOG_LEAVES } from "@/lib/demoFixtures.ts";
import { sanitizePlainInput } from "@/lib/plausibilityMath.ts";

const SVG_HEADERS: Record<string, string> = {
  "Content-Type": "image/svg+xml; charset=utf-8",
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
  "X-Content-Type-Options": "nosniff",
  "Cache-Control": "no-store, max-age=0",
};

export async function GET(
  request: Request,
  context: { params: Promise<{ proofId: string }> },
) {
  const { proofId } = await context.params;
  const cleanedId = safeDecodeURIComponent(proofId).replace(/\.svg$/i, "");
  const url = new URL(request.url);
  const theme = url.searchParams.get("theme") === "paper" ? "paper" : "obsidian";
  const labelParam = url.searchParams.get("label");

  const [{ registryDoc }, profile] = await Promise.all([
    fetchActiveRegistryDocument(),
    resolveShowcaseOrLiveProfile(cleanedId),
  ]);

  if (!profile) {
    const safeMissing = xmlEscape(sanitizePlainInput(cleanedId, 48));
    const notFoundSvg =
      '<svg xmlns="http://www.w3.org/2000/svg" width="420" height="40" role="img">' +
      `<title>Proof Not Found: ${safeMissing}</title>` +
      '<rect width="420" height="40" rx="6" fill="#334155"/>' +
      '<text x="12" y="25" font-family="monospace" font-size="12" fill="#f8fafc">' +
      `N170 Verify: proof not found (${safeMissing})` +
      "</text></svg>";
    return new NextResponse(notFoundSvg, {
      status: 404,
      headers: SVG_HEADERS,
    });
  }

  const bundle = profile.bundle;
  const verified = await verifyProofBundle(bundle, {
    registryDoc,
    chainHistory: profile.chainHistory,
    continuityLogLeaves:
      bundle.proof_id === "prf-inst-alpha-012" ? DEMO_CONTINUITY_LOG_LEAVES : null,
  });

  const svg = renderArchivalBadgeSvg(bundle, verified, theme, labelParam);

  return new NextResponse(svg, {
    status: 200,
    headers: {
      ...SVG_HEADERS,
      "Cache-Control": "public, max-age=60, s-maxage=300",
    },
  });
}
