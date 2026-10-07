#!/usr/bin/env node
import { copyFileSync, existsSync, mkdirSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dist = path.join(root, "dist");
const index = path.join(dist, "client", "index.html");
const worker = path.join(root, "worker", "index.js");

for (const file of [index, worker]) {
  if (!existsSync(file)) throw new Error("Missing hosting build input: " + file);
}

rmSync(path.join(dist, "server"), { recursive: true, force: true });
mkdirSync(path.join(dist, "server"), { recursive: true });
copyFileSync(worker, path.join(dist, "server", "index.js"));

console.log("Prepared hosting build: dist/server/index.js");
