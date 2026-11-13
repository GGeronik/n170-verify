#!/usr/bin/env node
/**
 * N170 Verify - Browser Pyodide Failsafe Wheel Builder.
 *
 * Packages `core/n170_verify` into a pure-Python wheel (`n170_verify-0.3.0-py3-none-any.whl`)
 * under `web/public/pyodide/` and computes its pinned SHA-384 integrity hash.
 * Employs deterministic zip timestamp pinning (2026-01-01) for reproducible builds.
 */

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const REPO_ROOT = path.resolve(__dirname, "../..");
const CORE_DIR = path.join(REPO_ROOT, "core/n170_verify");
const OUT_DIR = path.join(REPO_ROOT, "web/public/pyodide");
const WHEEL_NAME = "n170_verify-0.3.0-py3-none-any.whl";
const OUT_WHEEL = path.join(OUT_DIR, WHEEL_NAME);
const MANIFEST_PATH = path.join(OUT_DIR, "wheel-manifest.json");
const GITIGNORE_PATH = path.join(OUT_DIR, ".gitignore");

export function buildPyodideWheel(options = {}) {
  const coreDir = options.coreDir ?? CORE_DIR;
  const outDir = options.outDir ?? OUT_DIR;
  const outWheel = options.outWheel ?? OUT_WHEEL;
  const manifestPath = options.manifestPath ?? MANIFEST_PATH;

  if (!fs.existsSync(coreDir)) {
    throw new Error(`Core directory not found: ${coreDir}`);
  }

  fs.mkdirSync(outDir, { recursive: true });

  // Python builder script using stdlib zipfile with deterministic ZipInfo timestamps
  const pyScript = String.raw`
import os, sys, zipfile, hashlib, base64

core_pkg_dir = sys.argv[1]
out_file = sys.argv[2]
base_core_dir = os.path.dirname(core_pkg_dir)

dist_info = "n170_verify-0.3.0.dist-info"
metadata = """Metadata-Version: 2.1
Name: n170-verify
Version: 0.3.0
Summary: Cryptographic verification engine
License: Apache-2.0
Requires-Python: >=3.11
"""

wheel_info = """Wheel-Version: 1.0
Generator: n170-build-pyodide-wheel
Root-Is-Purelib: true
Tag: py3-none-any
"""

fixed_time = (2026, 1, 1, 0, 0, 0)
record_lines = []
with zipfile.ZipFile(out_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for root, _, files in sorted(os.walk(core_pkg_dir)):
        if "__pycache__" in root:
            continue
        for file in sorted(files):
            if file.endswith(".pyc") or file.startswith("."):
                continue
            src_path = os.path.join(root, file)
            rel_path = os.path.relpath(src_path, base_core_dir)
            with open(src_path, "rb") as f:
                data = f.read()
            zi = zipfile.ZipInfo(filename=rel_path, date_time=fixed_time)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o644 << 16
            zf.writestr(zi, data)
            h = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii").rstrip("=")
            record_lines.append(f"{rel_path},sha256={h},{len(data)}")

    zi_meta = zipfile.ZipInfo(filename=f"{dist_info}/METADATA", date_time=fixed_time)
    zi_meta.compress_type = zipfile.ZIP_DEFLATED
    zi_meta.external_attr = 0o644 << 16
    zf.writestr(zi_meta, metadata)
    hm = base64.urlsafe_b64encode(hashlib.sha256(metadata.encode("utf-8")).digest()).decode("ascii").rstrip("=")
    record_lines.append(f"{dist_info}/METADATA,sha256={hm},{len(metadata)}")

    zi_wheel = zipfile.ZipInfo(filename=f"{dist_info}/WHEEL", date_time=fixed_time)
    zi_wheel.compress_type = zipfile.ZIP_DEFLATED
    zi_wheel.external_attr = 0o644 << 16
    zf.writestr(zi_wheel, wheel_info)
    hw = base64.urlsafe_b64encode(hashlib.sha256(wheel_info.encode("utf-8")).digest()).decode("ascii").rstrip("=")
    record_lines.append(f"{dist_info}/WHEEL,sha256={hw},{len(wheel_info)}")

    record_lines.append(f"{dist_info}/RECORD,,")
    rec_bytes = "\n".join(record_lines).encode("utf-8") + b"\n"
    zi_rec = zipfile.ZipInfo(filename=f"{dist_info}/RECORD", date_time=fixed_time)
    zi_rec.compress_type = zipfile.ZIP_DEFLATED
    zi_rec.external_attr = 0o644 << 16
    zf.writestr(zi_rec, rec_bytes)
`;

  const res = spawnSync("python3", ["-", coreDir, outWheel], {
    input: pyScript,
    encoding: "utf-8",
  });

  if (res.status !== 0) {
    throw new Error(`Failed to build wheel with python3: ${res.stderr || res.stdout}`);
  }

  const wheelBuffer = fs.readFileSync(outWheel);
  const sha384Hex = crypto.createHash("sha384").update(wheelBuffer).digest("hex");
  const sha256Hex = crypto.createHash("sha256").update(wheelBuffer).digest("hex");

  let builtAt = "2026-01-01T00:00:00.000Z";
  if (fs.existsSync(manifestPath)) {
    try {
      const existing = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));
      if (existing.sha384 === sha384Hex && existing.built_at) {
        builtAt = existing.built_at;
      }
    } catch {
      // ignore
    }
  }

  const manifest = {
    wheel_name: WHEEL_NAME,
    version: "0.3.0",
    bytes: wheelBuffer.length,
    sha384: sha384Hex,
    sha256: sha256Hex,
    built_at: builtAt,
  };

  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n", "utf-8");

  // Maintain .gitignore to ignore built .whl artifacts
  if (!fs.existsSync(GITIGNORE_PATH)) {
    fs.writeFileSync(GITIGNORE_PATH, "*.whl\n", "utf-8");
  }

  return manifest;
}

if (process.argv[1] === __filename) {
  try {
    const manifest = buildPyodideWheel();
    console.log(`[build-pyodide-wheel] Successfully built ${manifest.wheel_name}`);
    console.log(`[build-pyodide-wheel] Size: ${manifest.bytes} bytes`);
    console.log(`[build-pyodide-wheel] SHA-384: ${manifest.sha384}`);
    console.log(`[build-pyodide-wheel] SHA-256: ${manifest.sha256}`);
    console.log(`[build-pyodide-wheel] Manifest saved to ${MANIFEST_PATH}`);
  } catch (err) {
    console.error("[build-pyodide-wheel] Error:", err.message);
    process.exit(1);
  }
}
