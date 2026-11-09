import { NextResponse } from "next/server";
import { fetchActiveRegistryDocument } from "@/lib/apiClient.ts";

export async function GET() {
  const { registryDoc } = await fetchActiveRegistryDocument();
  return NextResponse.json(registryDoc, {
    status: 200,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "public, max-age=60, must-revalidate",
    },
  });
}
