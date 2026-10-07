import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import worker, { utf8DocumentationContentType } from "./worker/index.js";
import { fileURLToPath } from "node:url";

// Enforce the actual first-party module graph, including ?raw imports outside
// src/. Installed dependencies remain a separate locked installation boundary.
function publicModuleInventory() {
  const root = fileURLToPath(new URL(".", import.meta.url));
  const policy = JSON.parse(readFileSync(path.join(root, "scripts/public-source-inventory.json"), "utf8"));
  const allowed = new Set(policy.files.map(name => path.resolve(root, name)));
  function check(id) {
    if (id.startsWith("\0")) return; // Rollup virtual helpers have no source file.
    const file = id.split("?")[0];
    if (!path.isAbsolute(file)) return;
    if (file.startsWith(path.join(root, "node_modules") + path.sep)) return;
    if (!allowed.has(path.normalize(file))) throw new Error("Unlisted first-party build input: " + path.relative(root, file));
  }
  return {
    name: "n170-public-module-inventory",
    apply: "build",
    configResolved(config) {
      for (const file of config.configFileDependencies ?? []) check(file);
    },
    generateBundle() {
      for (const id of this.getModuleIds()) check(id);
      for (const file of this.getWatchFiles()) check(file);
    },
  };
}

// Reuse the deployed worker's security headers, so `vite preview` behaves like
// production and the built page carries the same Content Security Policy.
const probe = await worker.fetch(new Request("https://verify.invalid/"), {
  ASSETS: { fetch: async () => new Response(null, { status: 200 }) },
});
const securityHeaders = Object.fromEntries(probe.headers);
const directives = securityHeaders["content-security-policy"].split(";").map((directive) => directive.trim()).filter(Boolean);
const withoutUpgrade = directives.filter((directive) => directive !== "upgrade-insecure-requests");

// A meta tag can't carry frame-ancestors (it only works as a header), and
// upgrade-insecure-requests would break plain-HTTP local previews.
const portablePolicy = withoutUpgrade.filter((directive) => !directive.startsWith("frame-ancestors")).join("; ");

// Vite's static server retains a pre-set Content-Type. Target only known,
// existing documentation files; do not intercept bodies or unrelated requests.
function previewDocumentationCharset() {
  return {
    name: "n170-preview-documentation-charset",
    configurePreviewServer(server) {
      const policy = JSON.parse(readFileSync(path.join(server.config.root, "scripts/public-source-inventory.json"), "utf8"));
      const documents = new Map();
      const entries = [...Object.entries(policy.documents), ...Object.entries(policy.downloads ?? {}).map(([source, entry]) => [source, entry.path])];
      for (const [, destination] of entries) {
        const contentType = utf8DocumentationContentType(null, `/${destination}`);
        if (contentType) documents.set(`/${destination}`, contentType);
      }
      for (const name of ["third-party-licenses.txt", "n170-verify-source.zip.sha256", "n170-verify-toolkit.zip.sha256"]) {
        documents.set(`/${name}`, "text/plain; charset=utf-8");
      }
      const directory = path.resolve(server.config.root, server.config.build.outDir);
      server.middlewares.use((request, response, next) => {
        if (!["GET", "HEAD"].includes(request.method)) return next();
        let pathname;
        try { pathname = decodeURIComponent(new URL(request.url, "http://localhost").pathname); }
        catch { return next(); }
        const contentType = documents.get(pathname);
        if (contentType && existsSync(path.join(directory, pathname.slice(1)))) response.setHeader("Content-Type", contentType);
        next();
      });
    },
  };
}

function embedContentSecurityPolicy() {
  return {
    name: "n170-verify-embed-csp",
    apply: "build",
    transformIndexHtml(html) {
      return {
        html,
        tags: [{ tag: "meta", attrs: { "http-equiv": "Content-Security-Policy", content: portablePolicy }, injectTo: "head-prepend" }],
      };
    },
  };
}

// Minified bundles drop most license headers, so ship the license text of every
// third-party package that ends up in the browser bundle alongside the site.
function thirdPartyLicenses() {
  return {
    name: "n170-verify-third-party-licenses",
    apply: "build",
    generateBundle(_options, bundle) {
      const packageRoots = new Map();
      for (const output of Object.values(bundle)) {
        if (output.type !== "chunk") continue;
        for (const id of output.moduleIds) {
          // Rollup prefixes helper modules with a NUL character and may append a query string.
          const fileId = (id.startsWith(String.fromCharCode(0)) ? id.slice(1) : id).split("?")[0];
          const normalized = fileId.split(path.sep).join("/");
          const marker = normalized.lastIndexOf("/node_modules/");
          if (marker === -1) continue;
          const segments = normalized.slice(marker + "/node_modules/".length).split("/");
          const name = segments[0].startsWith("@") ? `${segments[0]}/${segments[1]}` : segments[0];
          packageRoots.set(name, `${normalized.slice(0, marker)}/node_modules/${name}`);
        }
      }
      const isLicenseFile = (file) => /^licen[cs]e(\.|$)/i.test(file);
      const sections = [...packageRoots.keys()].sort().map((name) => {
        const root = packageRoots.get(name);
        const manifest = JSON.parse(readFileSync(`${root}/package.json`, "utf8"));
        const heading = `${manifest.name}@${manifest.version} (${manifest.license ?? "license not declared"})`;
        const licenseFile = readdirSync(root).find(isLicenseFile);
        if (licenseFile) return `${heading}\n\n${readFileSync(`${root}/${licenseFile}`, "utf8").trim()}`;
        // Some packages vendor other libraries and ship only those libraries' license files.
        const repository = typeof manifest.repository === "string" ? manifest.repository : manifest.repository?.url;
        const nested = readdirSync(root, { withFileTypes: true })
          .filter((entry) => entry.isDirectory() && entry.name !== "node_modules")
          .flatMap((entry) => readdirSync(`${root}/${entry.name}`, { withFileTypes: true })
            .filter((child) => child.isDirectory())
            .flatMap((child) => readdirSync(`${root}/${entry.name}/${child.name}`).filter(isLicenseFile).map((file) => `${entry.name}/${child.name}/${file}`)))
          .sort();
        const note = `This package ships no top-level license text. Its declared license is ${manifest.license ?? "not stated"}${repository ? `; see ${repository}` : ""}.`;
        return [heading, note, ...nested.map((file) => `${file}:\n\n${readFileSync(`${root}/${file}`, "utf8").trim()}`)].join("\n\n");
      });
      this.emitFile({
        type: "asset",
        fileName: "third-party-licenses.txt",
        source: `Third-party software bundled in N170 Verify\n\n${sections.join(`\n\n${"-".repeat(72)}\n\n`)}\n`,
      });
    },
  };
}

export default defineConfig({
  build: {
    outDir: "dist/client",
    sourcemap: false,
    // The preload polyfill fetches modules, which the policy blocks; current browsers don't need it.
    modulePreload: { polyfill: false },
  },
  optimizeDeps: {
    include: ["react", "react-dom/client"],
  },
  server: {
    host: "127.0.0.1",
    warmup: {
      clientFiles: ["./src/main.jsx"],
    },
  },
  preview: {
    host: "127.0.0.1",
    headers: { ...securityHeaders, "content-security-policy": withoutUpgrade.join("; ") },
  },
  plugins: [react(), publicModuleInventory(), embedContentSecurityPolicy(), thirdPartyLicenses(), previewDocumentationCharset()],
});
