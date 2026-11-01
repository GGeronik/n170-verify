// Original release-overlay controls. Expectations are reviewed source policy,
// not an inventory learned from the build being tested.
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { posix } from "node:path";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

const root = new URL("../../", import.meta.url);
const app = new URL("../", import.meta.url);
const policy = JSON.parse(await readFile(new URL("scripts/public-source-inventory.json", app), "utf8"));
assert.equal(policy.schema, "n170.public-source-inventory.v1");

async function readTree(directory, prefix = "") {
  const files = new Map();
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const name = prefix + entry.name;
    assert.equal(entry.isSymbolicLink(), false, `symlink: ${name}`);
    if (entry.isDirectory()) {
      for (const [child, raw] of await readTree(new URL(`${entry.name}/`, directory), `${name}/`)) files.set(child, raw);
    } else {
      assert.ok(entry.isFile(), `nonregular: ${name}`);
      files.set(name, await readFile(new URL(entry.name, directory)));
    }
  }
  return files;
}

const built = await readTree(new URL("dist/client/", app));
const jsx = new Map();
for (const name of await readdir(new URL("src/", app))) {
  if (name.endsWith(".jsx")) jsx.set(name, await readFile(new URL(`src/${name}`, app), "utf8"));
}

function checkInventory(files) {
  const assets = [...files.keys()].filter(name => name.startsWith("assets/"));
  const expected = [...Object.values(policy.documents), ...Object.values(policy.downloads ?? {}).map(entry => entry.path), "index.html", "third-party-licenses.txt", "n170-verify-source.zip", "n170-verify-source.zip.sha256", "n170-verify-toolkit.zip", "n170-verify-toolkit.zip.sha256", "verify_release.py", ...assets].sort();
  assert.deepEqual([...files.keys()].sort(), expected, "exact public file inventory");
  assert.equal(assets.filter(name => name.endsWith(".js")).length, 1, "inventory: one JavaScript entry");
  assert.equal(assets.filter(name => name.endsWith(".css")).length, 1, "inventory: one CSS entry");
  assert.equal(assets.length, 2, "inventory: only reviewed asset types");
  for (const name of assets) {
    assert.match(name, /^assets\/[A-Za-z0-9_-]+-[A-Za-z0-9_-]{8}\.(?:js|css)$/);
    assert.equal(files.get(name).toString().includes("sourceMappingURL"), false, "source map reference");
  }
}

function checkLinks(files, sources) {
  const links = [];
  for (const [name, text] of sources) {
    for (const match of text.matchAll(/href=["'](\/[^"']+)["']/g)) links.push([name, match[1]]);
  }
  for (const [name, raw] of files) {
    if (name.endsWith(".md") || name === "llms.txt") {
      for (const match of raw.toString().matchAll(/\]\(([^)]+)\)/g)) {
        if (!/^[a-z][a-z0-9+.-]*:/i.test(match[1]) && !match[1].startsWith("#")) links.push([name, match[1]]);
      }
    }
  }
  assert.ok(links.length > 0, "local link coverage must be nonempty");
  for (const [name, link] of links) {
    const target = posix.normalize(posix.join(link.startsWith("/") ? "/" : posix.dirname(name), link.split(/[?#]/)[0])).replace(/^\//, "");
    assert.ok(!target.startsWith("../") && files.has(target), `missing local link ${name}: ${link}`);
  }
}

function checkPublicMarkers(files) {
  // Bounded defense-in-depth markers, not proof of absence of arbitrary private data.
  for (const [name, raw] of files) {
    if (name.endsWith(".zip")) continue; // source ZIP is separately hash/inventory verified
    const text = raw.toString();
    assert.equal(/\/(?:Users|home)\/[A-Za-z0-9._-]+\//.test(text), false, `private filesystem marker: ${name}`);
    assert.equal(/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(text), false, `private key marker: ${name}`);
    assert.equal(/task[123]-(?:delivery|artifacts)\//.test(text), false, `internal evidence marker: ${name}`);
  }
}

function checkAuditBoundary(files) {
  const inventory = JSON.parse(files.get("auditzk-license-inventory.json"));
  const boundaries = JSON.parse(files.get("component-boundaries.json"));
  assert.equal(inventory.status, "no_upstream_code_included");
  assert.equal(inventory.ownerReportedForthcomingGrant, false);
  assert.equal(inventory.review.decision, "No upstream code is included; only the original Apache-2.0 mock interface is present.");
  assert.equal(inventory.upstreamCodeIncluded, false);
  assert.equal(inventory.requiredNoticesStatus, "pending");
  assert.equal(inventory.applicableComponentLicense, null);
  assert.equal(inventory.applicableMitRevision, null);
  assert.deepEqual(inventory.requiredNotices, []);
  assert.deepEqual(inventory.writtenGrant, { documentPath: null, sha256: null, issuer: null, issuedAt: null });
  assert.deepEqual(inventory.coveredSource, { repository: null, revision: null, components: [], fileInventorySha256: null });
  assert.deepEqual(inventory.rights, Object.fromEntries([
    "use", "modification", "sourceRedistribution", "binaryRedistribution",
    "downstreamModification", "downstreamSelfHosting", "downstreamRedistribution",
  ].map(name => [name, "pending"])));
  assert.equal(boundaries.auditzk.status, "not_integrated");
  assert.equal(boundaries.auditzk.upstream_code_bundled, false);
  assert.equal(boundaries.freqtrade.engine_bundled, false);
  assert.equal(boundaries.release.publication_asserted, false);
  assert.equal(Object.hasOwn(boundaries.release, "published"), false);
  assert.equal(boundaries.release.external_human_audit, false);
}

const noticeTexts = await Promise.all(policy.bundledPackages.map(async entry => {
  const metadata = JSON.parse(await readFile(new URL(`node_modules/${entry.name}/package.json`, app), "utf8"));
  assert.equal(metadata.version, entry.version);
  assert.equal(metadata.license, entry.license);
  return { ...entry, text: (await readFile(new URL(`node_modules/${entry.name}/LICENSE`, app), "utf8")).trim() };
}));
const originalLicense = await readFile(new URL("LICENSE", app));
const originalNotice = await readFile(new URL("NOTICE", app));

function checkNotices(files) {
  assert.deepEqual(files.get("LICENSE.txt"), originalLicense, "original license unchanged");
  assert.deepEqual(files.get("NOTICE"), originalNotice, "original notice unchanged");
  const notices = files.get("third-party-licenses.txt").toString();
  for (const entry of noticeTexts) {
    assert.ok(notices.includes(`${entry.name}@${entry.version} (${entry.license})\n\n${entry.text}`), `complete license text for ${entry.name}`);
  }
}

test("release public inventory and asset controls reject extras, omissions and source maps", () => {
  checkInventory(built);
  for (const name of ["innocuous.md", "private/report.json", "nested/readme.md", "assets/index-abcdefgh.js", "assets/index-abcdefgh.css", "assets/index.js.map"]) {
    assert.throws(() => checkInventory(new Map([...built, [name, Buffer.from("synthetic extra")]])), /inventory/);
  }
  for (const name of built.keys()) {
    const missing = new Map(built); missing.delete(name);
    assert.throws(() => checkInventory(missing), /inventory/);
  }
  const maps = new Map(built);
  maps.set([...built.keys()].find(name => name.endsWith(".js")), Buffer.from("//# sourceMappingURL=private.map"));
  assert.throws(() => checkInventory(maps), /source map/);
});

test("release local Markdown and JSX links reject broken targets", () => {
  checkLinks(built, jsx);
  assert.throws(() => checkLinks(new Map([...built, ["methods.md", Buffer.from("[broken](absent.md)")]]), jsx), /missing local link/);
  assert.throws(() => checkLinks(built, new Map([...jsx, ["Synthetic.jsx", '<a href="/absent.md">Broken</a>']])), /missing local link/);
});

test("release served text rejects private path, key and internal evidence markers", () => {
  checkPublicMarkers(built);
  for (const marker of ["/Users/synthetic/private.txt", "-----BEGIN PRIVATE KEY-----"]) {
    assert.throws(() => checkPublicMarkers(new Map([...built, ["methods.md", Buffer.from(marker)]])), /private .* marker/);
  }
  assert.throws(() => checkPublicMarkers(new Map([...built, ["reviewer-journey.md", Buffer.from("task2-delivery/synthetic/")]])), /internal evidence marker/);
});

test("release preserves pending AuditZK grant and absent upstream implementation", () => {
  checkAuditBoundary(built);
  for (const [file, field, value] of [
    ["auditzk-license-inventory.json", "status", "approved"],
    ["auditzk-license-inventory.json", "upstreamCodeIncluded", true],
    ["auditzk-license-inventory.json", "rights", {}],
    ["component-boundaries.json", "auditzk", { status: "MIT", upstream_code_bundled: true }],
  ]) {
    const json = JSON.parse(built.get(file)); json[field] = value;
    assert.throws(() => checkAuditBoundary(new Map([...built, [file, Buffer.from(JSON.stringify(json))]])));
  }
});

test("release license controls reject removed or altered original and third-party notices", () => {
  checkNotices(built);
  for (const name of ["LICENSE.txt", "NOTICE", "third-party-licenses.txt"]) {
    assert.throws(() => checkNotices(new Map([...built, [name, Buffer.from("changed notice")]])));
    const missing = new Map(built); missing.delete(name);
    assert.throws(() => checkNotices(missing));
  }
});

test("release dependency inventory equals independently read locked package identities", async () => {
  const lock = JSON.parse(await readFile(new URL("package-lock.json", app), "utf8"));
  const extraction = spawnSync("python3", ["-c", "import sys,zipfile; print(zipfile.ZipFile(sys.argv[1]).read('DEPENDENCIES.json').decode())", fileURLToPath(new URL("dist/client/n170-verify-source.zip", app))], { encoding: "utf8" });
  assert.equal(extraction.status, 0, extraction.stderr);
  const inventory = JSON.parse(extraction.stdout);
  const expected = Object.entries(lock.packages).filter(([path]) => path).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    .map(([install_path, entry]) => ({ lockfile: "app/package-lock.json", install_path,
      version: entry.version, license: entry.license, integrity: entry.integrity,
      resolved: entry.resolved ?? null, dev: Boolean(entry.dev), optional: Boolean(entry.optional) }));
  assert.ok(expected.length > 0);
  assert.deepEqual(inventory.packages, expected);
  for (const entry of expected) assert.ok(entry.version && entry.license && entry.integrity);
});

test("recipient instructions locate the app folder and execute both documented verifier commands", async () => {
  const guide = await readFile(new URL("docs/reviewer-journey.md", app), "utf8");
  const commands = guide.match(/```sh\n\s*(cd [^\n]+)\n\s*(node scripts\/verify-record\.mjs [^\n]+)\n\s*(node scripts\/verify-record\.mjs [^\n]+)\n/);
  assert.ok(commands, "recipient commands must first enter their folder from the extracted root");
  assert.equal(commands[1].trim(), "cd app");
  const cwd = app;
  await readFile(new URL("package.json", cwd));
  const fixture = fileURLToPath(new URL("examples/example-profile.json", app));
  for (const command of commands.slice(2)) {
    const args = [...command.matchAll(/"([^"]+)"|(\S+)/g)].map(match => match[1] || match[2]);
    assert.equal(args.shift(), "node");
    const result = spawnSync(process.execPath, args.map(arg => arg.startsWith("/path/to/") ? fixture : arg), { cwd, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).source_authenticated, false);
  }
  const bundle = await build({ entryPoints: [fileURLToPath(new URL("src/IndependentVerifierHelp.jsx", app))], bundle: true, platform: "node", format: "esm", jsx: "automatic", write: false, logLevel: "silent" });
  const { default: Component } = await import(`data:text/javascript;base64,${Buffer.from(bundle.outputFiles[0].text).toString("base64")}`);
  assert.match(renderToStaticMarkup(createElement(Component)), /open the app subfolder of the extracted release \(the folder containing package\.json\)/);
});
