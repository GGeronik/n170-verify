// Profile signing with the browser's WebCrypto API only.
//
// Each profile gets its own ECDSA P-256 key. The private key is generated as
// non-extractable: page code can ask the browser to sign with it, but cannot
// read or export it. A valid signature shows that a record was made with this
// profile's key and has not changed since. It does not show who holds the key,
// or that the numbers came from a real account.

const KEY_ALGORITHM = Object.freeze({ name: "ECDSA", namedCurve: "P-256" });
const SIGNATURE_ALGORITHM = Object.freeze({ name: "ECDSA", hash: "SHA-256" });

const KEY_ID_DOMAIN = new TextEncoder().encode("n170.verify.profile-key.v3\n");
const PUBLIC_KEY_BYTES = 65; // uncompressed P-256 point: 0x04 || X || Y
const SIGNATURE_BYTES = 64; // IEEE P1363 r || s, as produced by WebCrypto
const base64UrlAlphabet = /^[A-Za-z0-9_-]+$/;
const keyIdPattern = /^[a-f0-9]{64}$/;

function subtle() {
  const api = globalThis.crypto?.subtle;
  if (typeof api?.sign !== "function") {
    throw new Error("Signing is unavailable in this browser context. Use a current browser over HTTPS or localhost.");
  }
  return api;
}

function toHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function encodeBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

// Strict decoding: exact length, URL-safe alphabet and canonical trailing bits,
// so every byte string has exactly one accepted text form.
export function decodeBase64Url(text, byteLength) {
  if (typeof text !== "string" || text.length !== Math.ceil((byteLength * 4) / 3) || !base64UrlAlphabet.test(text)) return null;
  let binary;
  try {
    binary = atob(text.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (text.length % 4)) % 4));
  } catch {
    return null;
  }
  if (binary.length !== byteLength) return null;
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  return encodeBase64Url(bytes) === text ? bytes : null;
}

export async function sha256Hex(bytes) {
  return toHex(new Uint8Array(await subtle().digest("SHA-256", bytes)));
}

function publicKeyBytes(publicKey) {
  const bytes = decodeBase64Url(publicKey, PUBLIC_KEY_BYTES);
  return bytes && bytes[0] === 4 ? bytes : null;
}

export function isPublicKeyText(publicKey) {
  return publicKeyBytes(publicKey) !== null;
}

export function isSignatureText(signature) {
  return decodeBase64Url(signature, SIGNATURE_BYTES) !== null;
}

// The key ID is a domain-separated SHA-256 of the public key. It is the profile
// ID, so a profile cannot keep its ID while swapping in a different key.
export async function keyIdFromPublicKey(publicKey) {
  const bytes = publicKeyBytes(publicKey);
  if (!bytes) throw new Error("The profile public key is invalid or unsupported.");
  const input = new Uint8Array(KEY_ID_DOMAIN.length + bytes.length);
  input.set(KEY_ID_DOMAIN);
  input.set(bytes, KEY_ID_DOMAIN.length);
  return sha256Hex(input);
}

// An 80-bit display form of the key ID for CVs and posts. The full 256-bit ID
// stays in the file; matching a chosen key code would take about 2^80 attempts.
export function formatKeyCode(keyId) {
  if (typeof keyId !== "string" || !keyIdPattern.test(keyId)) throw new Error("The profile key ID is invalid.");
  return keyId.slice(0, 20).match(/.{4}/g).join("-");
}

export async function generateProfileKey() {
  const api = subtle();
  const pair = await api.generateKey(KEY_ALGORITHM, false, ["sign", "verify"]);
  const publicKey = encodeBase64Url(new Uint8Array(await api.exportKey("raw", pair.publicKey)));
  return { privateKey: pair.privateKey, publicKey, keyId: await keyIdFromPublicKey(publicKey) };
}

export function createSigner(privateKey, publicKey) {
  if (privateKey?.type !== "private" || !isPublicKeyText(publicKey)) throw new Error("This profile's signing key is unavailable.");
  return Object.freeze({
    publicKey,
    async sign(bytes) {
      return encodeBase64Url(new Uint8Array(await subtle().sign(SIGNATURE_ALGORITHM, privateKey, bytes)));
    },
  });
}

export async function importVerificationKey(publicKey) {
  const bytes = publicKeyBytes(publicKey);
  if (!bytes) return null;
  try {
    return await subtle().importKey("raw", bytes, KEY_ALGORITHM, false, ["verify"]);
  } catch {
    return null;
  }
}

// ECDSA signatures are malleable ((r, s) and (r, n - s) both verify). Record
// identity, chain links and published fingerprints use the payload hash, never
// the signature text, so an altered signature cannot change what a record says.
export async function verifySignature(verificationKey, signature, bytes) {
  const signatureBytes = decodeBase64Url(signature, SIGNATURE_BYTES);
  if (!verificationKey || !signatureBytes) return false;
  try {
    return await subtle().verify(SIGNATURE_ALGORITHM, verificationKey, signatureBytes, bytes);
  } catch {
    return false;
  }
}
