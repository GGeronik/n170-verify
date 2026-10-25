import assert from "node:assert/strict";
import { access, readFile, readdir } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { preview } from "vite";
import worker from "../worker/index.js";

const requiredSecurityHeaders = {
  "content-security-policy": "default-src 'none'",
  "cross-origin-embedder-policy": "require-corp",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "origin-agent-cluster": "?1",
  "permissions-policy": "camera=()",
  "referrer-policy": "no-referrer",
  "strict-transport-security": "max-age=31536000",
  "x-content-type-options": "nosniff",
  "x-dns-prefetch-control": "off",
  "x-frame-options": "DENY",
};
const requiredDirectives = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self'",
  "connect-src 'none'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "worker-src 'none'",
  "require-trusted-types-for 'script'",
  "trusted-types 'none'",
];

function assertSecurityHeaders(response) {
  for (const [name, expected] of Object.entries(requiredSecurityHeaders)) {
    assert.ok(response.headers.get(name)?.includes(expected), `${name} should include ${expected}`);
  }
}

function assertStrictPolicy(policy, label) {
  const directives = policy.split(";").map((directive) => directive.trim());
  for (const directive of requiredDirectives) assert.ok(directives.includes(directive), `${label} should include ${directive}`);
  assert.equal(policy.includes("unsafe-inline"), false, `${label} must not allow inline scripts or styles`);
  assert.equal(policy.includes("unsafe-eval"), false, `${label} must not allow eval`);
}

test("serves existing static assets without a fallback", async () => {
  const calls = [];
  const response = await worker.fetch(new Request("https://example.test/assets/app.js"), {
    ASSETS: {
      fetch: async (request) => {
        calls.push(new URL(request.url).pathname);
        return new Response("asset", { status: 200 });
      },
    },
  });

  assert.equal(response.status, 200);
  assert.deepEqual(calls, ["/assets/app.js"]);
  assertSecurityHeaders(response);
});

test("falls back to index.html for an unknown app route", async () => {
  const calls = [];
  const response = await worker.fetch(
    new Request("https://example.test/flow/step-two?source=share", {
      headers: { accept: "text/html" },
    }),
    {
      ASSETS: {
        fetch: async (request) => {
          const url = new URL(request.url);
          calls.push(url.pathname + url.search);
          return new Response(url.pathname === "/index.html" ? "app" : "missing", {
            status: url.pathname === "/index.html" ? 200 : 404,
          });
        },
      },
    },
  );

  assert.equal(response.status, 200);
  assert.deepEqual(calls, ["/flow/step-two?source=share", "/index.html"]);
  assertSecurityHeaders(response);
});

test("parses HTML accept media types without substring matching", async () => {
  for (const [accept, shouldFallback] of [
    ["TEXT/HTML; charset=utf-8", true],
    ["application/xhtml+xml, text/html;q=0.9", true],
    ["application/not-text/html", false],
  ]) {
    const calls = [];
    const response = await worker.fetch(
      new Request("https://example.test/missing", { headers: { accept } }),
      {
        ASSETS: {
          fetch: async (request) => {
            const pathname = new URL(request.url).pathname;
            calls.push(pathname);
            return new Response(pathname === "/index.html" ? "app" : "missing", {
              status: pathname === "/index.html" ? 200 : 404,
            });
          },
        },
      },
    );

    assert.deepEqual(calls, shouldFallback ? ["/missing", "/index.html"] : ["/missing"]);
    assert.equal(response.status, shouldFallback ? 200 : 404);
    assertSecurityHeaders(response);
  }
});

test("does not turn missing API or write requests into the app shell", async () => {
  for (const request of [
    new Request("https://example.test/api/missing", { headers: { accept: "application/json" } }),
    new Request("https://example.test/flow", { method: "POST", headers: { accept: "text/html" } }),
  ]) {
    let calls = 0;
    const response = await worker.fetch(request, {
      ASSETS: {
        fetch: async () => {
          calls += 1;
          return new Response("missing", { status: 404 });
        },
      },
    });

    assert.equal(response.status, 404);
    assert.equal(calls, 1);
    assertSecurityHeaders(response);
  }
});

test("security policy denies by default, enforces Trusted Types and blocks framing", async () => {
  const response = await worker.fetch(new Request("https://example.test/"), {
    ASSETS: { fetch: async () => new Response("app", { status: 200 }) },
  });
  const policy = response.headers.get("content-security-policy");
  assertStrictPolicy(policy, "header policy");
  assert.ok(policy.includes("frame-ancestors 'none'"), "header policy should block framing");
});

test("emits the worker packaging files and the hosting configuration", async () => {
  await access(new URL("../dist/client/index.html", import.meta.url));
  await access(new URL("../dist/server/index.js", import.meta.url));

  assert.deepEqual((await readdir(new URL("../dist", import.meta.url))).sort(), ["client", "server"]);
  assert.deepEqual(await readdir(new URL("../dist/server", import.meta.url)), ["index.js"]);
  assert.deepEqual(
    await readFile(new URL("../dist/server/index.js", import.meta.url)),
    await readFile(new URL("../worker/index.js", import.meta.url)),
  );
  const hosting = JSON.parse(await readFile(new URL("../wrangler.jsonc", import.meta.url), "utf8"));
  assert.match(hosting.compatibility_date, /^\d{4}-\d{2}-\d{2}$/);
  assert.deepEqual(hosting, {
    name: "n170-verify",
    main: "dist/server/index.js",
    compatibility_date: hosting.compatibility_date,
    no_bundle: true,
    find_additional_modules: false,
    workers_dev: true,
    preview_urls: false,
    assets: {
      directory: "dist/client",
      binding: "ASSETS",
      run_worker_first: true,
      html_handling: "auto-trailing-slash",
      not_found_handling: "none",
    },
    observability: { enabled: false },
  });
});

test("built page embeds the strict policy, has no inline scripts and ships no source maps", async () => {
  const html = await readFile(new URL("../dist/client/index.html", import.meta.url), "utf8");
  const meta = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]*)"/);
  assert.ok(meta, "index.html must embed a Content-Security-Policy meta tag");
  const embeddedPolicy = meta[1].replaceAll("&#39;", "'").replaceAll("&quot;", '"').replaceAll("&amp;", "&");
  assertStrictPolicy(embeddedPolicy, "embedded policy");
  assert.ok(html.indexOf("Content-Security-Policy") < html.indexOf("<script"), "the policy must precede every script");
  assert.equal(/<script(?![^>]*\bsrc=)[^>]*>/i.test(html), false, "index.html must not contain inline scripts");
  const policy = JSON.parse(await readFile(new URL("../scripts/public-source-inventory.json", import.meta.url), "utf8"));
  assert.deepEqual((await readdir(new URL("../dist/client", import.meta.url))).sort(), [...Object.values(policy.documents), ...new Set(Object.values(policy.downloads ?? {}).map(entry => entry.path.split("/")[0])), "assets", "index.html", "third-party-licenses.txt", "n170-verify-source.zip", "n170-verify-source.zip.sha256", "n170-verify-toolkit.zip", "n170-verify-toolkit.zip.sha256", "verify_release.py"].sort());
  for (const name of await readdir(new URL("../dist/client/assets", import.meta.url))) {
    assert.match(name, /^[A-Za-z0-9_-]+-[A-Za-z0-9_-]{8}\.(?:js|css)$/);
    const content = await readFile(new URL(`../dist/client/assets/${name}`, import.meta.url), "utf8");
    assert.equal(content.includes("sourceMappingURL"), false, `${name} must not reference a source map`);
  }
});

test("built site ships the license text of every bundled third-party package", async () => {
  const notices = await readFile(new URL("../dist/client/third-party-licenses.txt", import.meta.url), "utf8");
  for (const entry of ["react@19.2.0 (MIT)", "react-dom@19.2.0 (MIT)", "scheduler@0.27.0 (MIT)"]) {
    assert.ok(notices.includes(entry), `third-party-licenses.txt should list ${entry}`);
  }
  assert.equal(/@vitejs|vite@/.test(notices), false, "build-only tooling isn't bundled");
});


test("documentation charset preserves Unicode bytes and non-charset parameters in the worker", async () => {
  const expected = "“Private source” — café · Ελληνικά";
  const bytes = new TextEncoder().encode(expected);
  for (const [pathname, contentType, expectedType] of [
    ["/verify-reconciliation.md", "text/markdown", "text/markdown; charset=utf-8"],
    ["/guide.md", null, "text/markdown; charset=utf-8"],
    ["/notes.txt", null, "text/plain; charset=utf-8"],
    ["/NOTICE", null, "text/plain; charset=utf-8"],
    ["/private-source-challenge/README.md", 'text/markdown; variant="CommonMark;plain"; charset="ISO-8859-1"', 'text/markdown; variant="CommonMark;plain"; charset=utf-8'],
    ["/guide.md", "text/x-markdown; charset=windows-1252", "text/x-markdown; charset=utf-8"],
    ["/third-party-licenses.txt", "text/plain; charset=UTF-8", "text/plain; charset=utf-8"],
  ]) {
    const headers = { "Content-Length": String(bytes.length), ETag: '"unchanged"' };
    if (contentType) headers["Content-Type"] = contentType;
    const response = await worker.fetch(new Request(`https://example.test${pathname}`), {
      ASSETS: { fetch: async () => new Response(bytes, { headers }) },
    });
    assert.equal(response.headers.get("content-type"), expectedType);
    assert.equal(response.headers.get("content-length"), String(bytes.length));
    assert.equal(response.headers.get("etag"), '"unchanged"');
    assertSecurityHeaders(response);
    const actual = new Uint8Array(await response.arrayBuffer());
    assert.deepEqual(actual, bytes);
    const charset = response.headers.get("content-type").match(/charset=([^;]+)/i)[1];
    assert.equal(new TextDecoder(charset, { fatal: true }).decode(actual), expected);
  }
});

test("documentation charset preserves binary and other response types and HTML fallback", async () => {
  const bytes = new Uint8Array([0, 80, 75, 255, 195, 169]);
  for (const contentType of ["application/zip", "application/octet-stream", "application/json", "text/html; charset=utf-8", "text/javascript", "text/css", null]) {
    const headers = contentType ? { "Content-Type": contentType } : {};
    const response = await worker.fetch(new Request("https://example.test/toolkit.zip"), {
      ASSETS: { fetch: async () => new Response(bytes, { headers }) },
    });
    assert.equal(response.headers.get("content-type"), contentType);
    assert.deepEqual(new Uint8Array(await response.arrayBuffer()), bytes);
    assertSecurityHeaders(response);
  }
  const response = await worker.fetch(new Request("https://example.test/missing.md", { headers: { accept: "text/html" } }), {
    ASSETS: { fetch: async (request) => new URL(request.url).pathname === "/index.html"
      ? new Response(new TextEncoder().encode("<!doctype html>app"), { headers: { "Content-Type": "text/html; charset=utf-8" } })
      : new Response(null, { status: 404 }) },
  });
  assert.equal(response.headers.get("content-type"), "text/html; charset=utf-8");
  assert.equal(await response.text(), "<!doctype html>app");
  assertSecurityHeaders(response);
});

test("documentation charset reaches actual Vite preview before static serving without changing bodies", async () => {
  const server = await preview({ root: fileURLToPath(new URL("../", import.meta.url)), logLevel: "silent", preview: { host: "127.0.0.1", port: 0, strictPort: true, open: false } });
  try {
    const base = `http://127.0.0.1:${server.httpServer.address().port}`;
    for (const [name, expectedType] of [
      ["verify-reconciliation.md", "text/markdown; charset=utf-8"],
      ["third-party-licenses.txt", "text/plain; charset=utf-8"],
      ["LICENSE.txt", "text/plain; charset=utf-8"],
      ["agent-instructions.txt", "text/plain; charset=utf-8"],
      ["NOTICE", "text/plain; charset=utf-8"],
      ["private-source-challenge/README.md", "text/markdown; charset=utf-8"],
      ["private-source-challenge/SHA256SUMS", "text/plain; charset=utf-8"],
      ["n170-verify-toolkit.zip.sha256", "text/plain; charset=utf-8"],
    ]) {
      const expected = await readFile(new URL(`../dist/client/${name}`, import.meta.url));
      const response = await fetch(`${base}/${name}?delivery-check=1`);
      assert.equal(response.status, 200);
      assert.equal(response.headers.get("content-type"), expectedType, name);
      assertSecurityHeaders(response);
      const actual = Buffer.from(await response.arrayBuffer());
      assert.deepEqual(actual, expected, name);
      assert.equal(new TextDecoder("utf-8", { fatal: true }).decode(actual), expected.toString("utf8"));
      const head = await fetch(`${base}/${name}`, { method: "HEAD" });
      assert.equal(head.headers.get("content-type"), expectedType, name);
      assert.equal((await head.arrayBuffer()).byteLength, 0);
    }
    const binary = await fetch(`${base}/n170-verify-toolkit.zip`);
    assert.equal(binary.headers.get("content-type"), "application/zip");
    assert.deepEqual(Buffer.from(await binary.arrayBuffer()), await readFile(new URL("../dist/client/n170-verify-toolkit.zip", import.meta.url)));
    assertSecurityHeaders(binary);
    const fallback = await fetch(`${base}/not-an-inventoried-guide.md`, { headers: { accept: "text/html" } });
    assert.match(fallback.headers.get("content-type"), /^text\/html(?:;|$)/);
    assert.equal(await fallback.text(), await readFile(new URL("../dist/client/index.html", import.meta.url), "utf8"));
  } finally {
    server.httpServer.closeAllConnections?.();
    await new Promise((resolve, reject) => server.httpServer.close((error) => error ? reject(error) : resolve()));
  }
});
