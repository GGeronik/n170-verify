import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { createSigner, decodeBase64Url, encodeBase64Url, formatKeyCode, generateProfileKey, importVerificationKey, isPublicKeyText, isSignatureText, keyIdFromPublicKey, verifySignature } from "../src/signing.js";

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const keyIdOf = (raw) => createHash("sha256").update(Buffer.concat([Buffer.from("n170.verify.profile-key.v3\n"), raw])).digest("hex");

test("base64url round-trips and rejects padding, other alphabets, wrong lengths and non-canonical bits", () => {
  const bytes = Uint8Array.from({ length: 64 }, (_, index) => (index * 37) & 255);
  const text = encodeBase64Url(bytes);
  assert.equal(text.length, 86);
  assert.equal(text, Buffer.from(bytes).toString("base64url"));
  assert.deepEqual(decodeBase64Url(text, 64), bytes);
  for (const bad of [text + "=", text.slice(1), `+${text.slice(1)}`, `/${text.slice(1)}`, `${text.slice(0, -1)}!`, null, 42]) {
    assert.equal(decodeBase64Url(bad, 64), null);
  }
  const nonCanonical = text.slice(0, -1) + alphabet[alphabet.indexOf(text.at(-1)) | 1];
  assert.equal(decodeBase64Url(nonCanonical, 64), null);
});

test("generated keys are non-extractable P-256 keys with domain-separated IDs", async () => {
  const key = await generateProfileKey();
  assert.equal(key.privateKey.extractable, false);
  await assert.rejects(globalThis.crypto.subtle.exportKey("pkcs8", key.privateKey));
  assert.equal(isPublicKeyText(key.publicKey), true);
  const raw = Buffer.from(key.publicKey, "base64url");
  assert.equal(raw.length, 65);
  assert.equal(raw[0], 4);
  assert.equal(key.keyId, keyIdOf(raw));
  assert.equal(await keyIdFromPublicKey(key.publicKey), key.keyId);
  const code = formatKeyCode(key.keyId);
  assert.match(code, /^[a-f0-9]{4}(-[a-f0-9]{4}){4}$/);
  assert.equal(code.replaceAll("-", ""), key.keyId.slice(0, 20));
  for (const bad of ["", "g".repeat(64), "A".repeat(64), null]) assert.throws(() => formatKeyCode(bad), /key ID is invalid/);
});

test("signatures verify only with the signing key and the exact bytes", async () => {
  const a = await generateProfileKey();
  const b = await generateProfileKey();
  const signer = createSigner(a.privateKey, a.publicKey);
  const data = new TextEncoder().encode("record");
  const signature = await signer.sign(data);
  assert.equal(isSignatureText(signature), true);
  const keyA = await importVerificationKey(a.publicKey);
  const keyB = await importVerificationKey(b.publicKey);
  assert.equal(await verifySignature(keyA, signature, data), true);
  assert.equal(await verifySignature(keyB, signature, data), false);
  assert.equal(await verifySignature(keyA, signature, new TextEncoder().encode("recorD")), false);
  assert.equal(await verifySignature(keyA, "A".repeat(86), data), false);
  assert.equal(await verifySignature(null, signature, data), false);
});

test("malformed or off-curve public keys are rejected before use", async () => {
  const { publicKey } = await generateProfileKey();
  const raw = Buffer.from(publicKey, "base64url");
  const compressed = Buffer.concat([Buffer.from([2]), raw.subarray(1, 33)]);
  for (const bad of [encodeBase64Url(compressed), encodeBase64Url(Buffer.alloc(65)), "x".repeat(87)]) {
    assert.equal(await importVerificationKey(bad), null);
    await assert.rejects(keyIdFromPublicKey(bad), /public key is invalid/);
  }
  const offCurve = Buffer.from(raw);
  offCurve[64] ^= 1;
  assert.equal(await importVerificationKey(encodeBase64Url(offCurve)), null);
  assert.throws(() => createSigner({ type: "public" }, publicKey), /signing key is unavailable/);
});
