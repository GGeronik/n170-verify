/**
 * Minimal Offline OpenTimestamps (.ots) Full Merkle-Path & Bitcoin Header Verifier
 * Zero-npm-dependency ES Module compatible with Browsers (globalThis.crypto.subtle).
 */
export const OTS_MAGIC = new Uint8Array([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
  0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
]);
export const TAG_PENDING = '83dfe30d2ef90c8e';
export const TAG_BITCOIN = '0588960d73d71901';
export const MAX_RESULT_LENGTH = 4096;
export const MAX_PAYLOAD_SIZE = 8192;
export const MAX_URI_LENGTH = 1000;
export const MAX_DEPTH = 256;
export const DIFF1_MAX_TARGET = 0xffffn << 208n;
const URI_RE = /^[A-Za-z0-9\-._/:]+$/;

export class OtsError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

const toHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (hex) => {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new OtsError('ERR_HEX', 'Invalid hex input');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
};
const eqBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const concatBytes = (a, b) => {
  const o = new Uint8Array(a.length + b.length);
  o.set(a, 0);
  o.set(b, a.length);
  return o;
};

async function webDigest(alg, data) {
  return new Uint8Array(await globalThis.crypto.subtle.digest(alg, data));
}

// Compact pure-JS RIPEMD-160 (0x03): works in browsers & OpenSSL 3.0+ without legacy provider
export function ripemd160(data) {
  const rl = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];
  const rr = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];
  const sl = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6];
  const sr = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];
  const kl = [0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
  const kr = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0];
  const rol = (x, n) => (x << n) | (x >>> (32 - n));
  const f = (j, x, y, z) => j < 16 ? x ^ y ^ z : j < 32 ? (x & y) | (~x & z) : j < 48 ? (x | ~y) ^ z : j < 64 ? (x & z) | (y & ~z) : x ^ (y | ~z);
  const padLen = ((data.length + 9 + 63) & ~63);
  const msg = new Uint8Array(padLen);
  const dv = new DataView(msg.buffer);
  msg.set(data);
  msg[data.length] = 0x80;
  dv.setUint32(padLen - 8, (data.length * 8) >>> 0, true);
  dv.setUint32(padLen - 4, Math.floor((data.length * 8) / 0x100000000), true);
  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
  for (let i = 0; i < padLen; i += 64) {
    let al = h0, bl = h1, cl = h2, dl = h3, el = h4, ar = h0, br = h1, cr = h2, dr = h3, er = h4;
    for (let j = 0; j < 80; j++) {
      const tl = (rol((al + f(j, bl, cl, dl) + dv.getUint32(i + rl[j] * 4, true) + kl[j >> 4]) | 0, sl[j]) + el) | 0;
      al = el; el = dl; dl = rol(cl, 10); cl = bl; bl = tl;
      const tr = (rol((ar + f(79 - j, br, cr, dr) + dv.getUint32(i + rr[j] * 4, true) + kr[j >> 4]) | 0, sr[j]) + er) | 0;
      ar = er; er = dr; dr = rol(cr, 10); cr = br; br = tr;
    }
    const t = (h1 + cl + dr) | 0;
    h1 = (h2 + dl + er) | 0;
    h2 = (h3 + el + ar) | 0;
    h3 = (h4 + al + br) | 0;
    h4 = (h0 + bl + cr) | 0;
    h0 = t;
  }
  const out = new Uint8Array(20);
  const odv = new DataView(out.buffer);
  [h0, h1, h2, h3, h4].forEach((v, i) => odv.setUint32(i * 4, v, true));
  return out;
}

// Compact pure-JS Keccak-256 (0x67): original 0x01 sponge padding (distinct from NIST SHA3-256 0x06)
export function keccak256(data) {
  const RC = [1n,0x8082n,0x800000000000808an,0x8000000080008000n,0x808bn,0x80000001n,0x8000000080008081n,0x8000000000008009n,0x8an,0x88n,0x80008009n,0x8000000an,0x8000808bn,0x800000000000008bn,0x8000000000008089n,0x8000000000008003n,0x8000000000008002n,0x8000000000000080n,0x800an,0x800000008000000an,0x8000000080008081n,0x8000000000008080n,0x80000001n,0x8000000080008008n];
  const R = [0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14].map(BigInt);
  const PI = [0,10,20,5,15,16,1,11,21,6,7,17,2,12,22,23,8,18,3,13,14,24,9,19,4];
  const M64 = 0xffffffffffffffffn;
  const rol64 = (x, n) => n === 0n ? x : ((x << n) | (x >> (64n - n))) & M64;
  const padLen = Math.ceil((data.length + 1) / 136) * 136;
  const msg = new Uint8Array(padLen);
  const dv = new DataView(msg.buffer);
  const S = new Array(25).fill(0n);
  msg.set(data);
  msg[data.length] = 0x01;
  msg[padLen - 1] ^= 0x80;
  for (let off = 0; off < padLen; off += 136) {
    for (let i = 0; i < 17; i++) S[i] ^= dv.getBigUint64(off + i * 8, true);
    for (let rnd = 0; rnd < 24; rnd++) {
      const C = [0,1,2,3,4].map((x) => S[x] ^ S[x + 5] ^ S[x + 10] ^ S[x + 15] ^ S[x + 20]);
      const D = [0,1,2,3,4].map((x) => C[(x + 4) % 5] ^ rol64(C[(x + 1) % 5], 1n));
      for (let i = 0; i < 25; i++) S[i] ^= D[i % 5];
      const B = new Array(25);
      for (let i = 0; i < 25; i++) B[PI[i]] = rol64(S[i], R[i]);
      for (let y = 0; y < 25; y += 5) {
        for (let x = 0; x < 5; x++) S[y + x] = B[y + x] ^ ((~B[y + ((x + 1) % 5)] & M64) & B[y + ((x + 2) % 5)]);
      }
      S[0] ^= RC[rnd];
    }
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < 4; i++) odv.setBigUint64(i * 8, S[i], true);
  return out;
}

class Reader {
  constructor(buf) {
    this.b = buf;
    this.p = 0;
  }
  eof() {
    return this.p === this.b.length;
  }
  u8() {
    if (this.p >= this.b.length) throw new OtsError('ERR_TRUNCATED', 'Unexpected EOF');
    return this.b[this.p++];
  }
  bytes(n) {
    if (n < 0 || this.p + n > this.b.length) throw new OtsError('ERR_TRUNCATED', 'Slice out of bounds');
    const s = this.b.subarray(this.p, this.p + n);
    this.p += n;
    return s;
  }
  varuint(maxVal = 0xffffffff) {
    let val = 0;
    let shift = 0;
    while (true) {
      if (shift >= 35) throw new OtsError('ERR_VARINT_OVERFLOW', 'LEB128 varint exceeds 32-bit bound');
      const byte = this.u8();
      val += (byte & 0x7f) * (2 ** shift);
      if (val > maxVal) throw new OtsError('ERR_VARINT_OVERFLOW', `Varint ${val} > max ${maxVal}`);
      if ((byte & 0x80) === 0) return val;
      shift += 7;
    }
  }
  varbytes(maxLen, minLen = 0) {
    const len = this.varuint(maxLen);
    if (len < minLen) throw new OtsError('ERR_VARBYTES_LEN', `Varbytes length ${len} < min ${minLen}`);
    return this.bytes(len);
  }
}

async function execOp(tag, r, msg) {
  let out;
  if (tag === 0xf0) out = concatBytes(msg, r.varbytes(MAX_RESULT_LENGTH, 1));
  else if (tag === 0xf1) out = concatBytes(r.varbytes(MAX_RESULT_LENGTH, 1), msg);
  else if (tag === 0xf2) out = Uint8Array.from(msg).reverse();
  else if (tag === 0xf3) {
    if (msg.length > MAX_RESULT_LENGTH / 2) throw new OtsError('ERR_MSG_LEN', 'Hexlify input > 2048B');
    out = new TextEncoder().encode(toHex(msg));
  } else if (tag === 0x08) out = await webDigest('SHA-256', msg);
  else if (tag === 0x02) out = await webDigest('SHA-1', msg);
  else if (tag === 0x03) out = ripemd160(msg);
  else if (tag === 0x67) out = keccak256(msg);
  else throw new OtsError('ERR_UNKNOWN_OP', `Unknown operation tag 0x${tag.toString(16)}`);
  if (out.length > MAX_RESULT_LENGTH) throw new OtsError('ERR_RESULT_LEN', 'Result exceeds 4096 bytes');
  return out;
}

function parseAttestation(r, msg, outList) {
  const tagHex = toHex(r.bytes(8));
  const payload = r.varbytes(MAX_PAYLOAD_SIZE);
  const pr = new Reader(payload);
  if (tagHex === TAG_PENDING) {
    const uriBytes = pr.varbytes(MAX_URI_LENGTH, 1);
    if (!pr.eof()) throw new OtsError('ERR_TRAILING_PAYLOAD', 'Trailing bytes in PendingAttestation');
    const uri = new TextDecoder('utf-8', { fatal: true }).decode(uriBytes);
    if (!URI_RE.test(uri)) throw new OtsError('ERR_INVALID_URI', `Disallowed chars in Pending URI: ${uri}`);
    outList.push({ type: 'pending', tag: tagHex, uri, commitment: msg });
  } else if (tagHex === TAG_BITCOIN) {
    const height = pr.varuint();
    if (!pr.eof()) throw new OtsError('ERR_TRAILING_PAYLOAD', 'Trailing bytes in BitcoinAttestation');
    outList.push({ type: 'bitcoin', tag: tagHex, height, commitment: msg });
  } else {
    outList.push({ type: 'unknown', tag: tagHex, payload, commitment: msg });
  }
}

async function walkTimestamp(r, msg, outList, depth = 0) {
  if (depth > MAX_DEPTH) throw new OtsError('ERR_DEPTH_LIMIT', 'Recursion depth > 256');
  let tag = r.u8();
  while (tag === 0xff) {
    const cur = r.u8();
    if (cur === 0xff) throw new OtsError('ERR_INVALID_FORK', 'Empty fork branch (0xff 0xff)');
    await doTagOrAttestation(r, cur, msg, outList, depth);
    tag = r.u8();
  }
  await doTagOrAttestation(r, tag, msg, outList, depth);
}

async function doTagOrAttestation(r, tag, msg, outList, depth) {
  if (tag === 0x00) parseAttestation(r, msg, outList);
  else await walkTimestamp(r, await execOp(tag, r, msg), outList, depth + 1);
}

export function expandCompactTarget(nBits) {
  const exp = nBits >>> 24;
  const mant = nBits & 0x007fffff;
  if (mant === 0 || (nBits & 0x00800000) !== 0) throw new OtsError('ERR_INVALID_NBITS', 'Invalid nBits mantissa/sign');
  return exp <= 3 ? BigInt(mant >>> (8 * (3 - exp))) : BigInt(mant) << BigInt(8 * (exp - 3));
}

export async function verifyBitcoinHeader(headerBytes, expectedMerkleRoot, maxTarget = DIFF1_MAX_TARGET) {
  const hdr = typeof headerBytes === 'string' ? fromHex(headerBytes) : headerBytes;
  const expRoot = typeof expectedMerkleRoot === 'string' ? fromHex(expectedMerkleRoot) : expectedMerkleRoot;
  if (!(hdr instanceof Uint8Array) || hdr.length !== 80) {
    throw new OtsError('ERR_HEADER_LEN', 'Bitcoin block header must be exactly 80 bytes');
  }
  if (!(expRoot instanceof Uint8Array) || expRoot.length !== 32) {
    throw new OtsError('ERR_DIGEST_LEN', 'Bitcoin commitment leaf must be 32 bytes');
  }
  const merkleRoot = hdr.subarray(36, 68);
  if (!eqBytes(merkleRoot, expRoot)) {
    throw new OtsError('ERR_MERKLE_MISMATCH', 'Leaf commitment does not match header merkle_root');
  }
  const dv = new DataView(hdr.buffer, hdr.byteOffset, 80);
  const nVersion = dv.getInt32(0, true);
  const nTime = dv.getUint32(68, true);
  const nBits = dv.getUint32(72, true);
  const nNonce = dv.getUint32(76, true);
  const target = expandCompactTarget(nBits);
  if (target > maxTarget) throw new OtsError('ERR_DIFFICULTY_TOO_LOW', 'Header target exceeds allowed maxTarget floor');
  const dsha = await webDigest('SHA-256', await webDigest('SHA-256', hdr));
  let hashInt = 0n;
  for (let i = 31; i >= 0; i--) hashInt = (hashInt << 8n) | BigInt(dsha[i]);
  if (hashInt > target) throw new OtsError('ERR_POW_INVALID', 'Block header double-SHA256 exceeds nBits target');
  return {
    nVersion,
    nTime,
    nBits,
    nNonce,
    merkleRoot: toHex(merkleRoot),
    blockHash: toHex(Uint8Array.from(dsha).reverse()),
  };
}

export async function verifyOtsProof(otsBytes, targetSha256, options = {}) {
  const rawOts = typeof otsBytes === 'string' ? fromHex(otsBytes) : otsBytes;
  const rawTarget = typeof targetSha256 === 'string' ? fromHex(targetSha256) : targetSha256;
  const r = new Reader(rawOts);
  if (!eqBytes(r.bytes(31), OTS_MAGIC)) throw new OtsError('ERR_MAGIC', 'Invalid OpenTimestamps magic header');
  if (r.varuint() !== 1) throw new OtsError('ERR_VERSION', 'Unsupported OpenTimestamps version');
  if (r.u8() !== 0x08) throw new OtsError('ERR_FILE_HASH_OP', 'Expected SHA-256 (0x08) file digest operation');
  const fileDigest = r.bytes(32);
  if (rawTarget && !eqBytes(fileDigest, rawTarget)) {
    throw new OtsError('ERR_DIGEST_MISMATCH', 'File digest does not match target SHA-256');
  }
  const attestations = [];
  await walkTimestamp(r, fileDigest, attestations, 0);
  if (!r.eof()) throw new OtsError('ERR_TRAILING_BYTES', 'Trailing bytes after .ots proof tree');
  if (attestations.length === 0) throw new OtsError('ERR_NO_ATTESTATIONS', 'No attestations in proof');
  const headers = options.headers || (options.header ? { default: options.header } : {});
  const maxTarget = options.maxTarget ?? DIFF1_MAX_TARGET;
  const errors = [];
  for (const att of attestations) {
    if (att.type !== 'bitcoin') continue;
    const hdr = headers[att.height] ?? headers.default;
    if (!hdr) continue;
    try {
      const info = await verifyBitcoinHeader(hdr, att.commitment, maxTarget);
      return { status: 'CONFIRMED', height: att.height, ...info, fileDigest: toHex(fileDigest), attestations };
    } catch (e) {
      errors.push({ height: att.height, code: e.code, message: e.message });
    }
  }
  if (errors.length > 0) throw new OtsError(errors[0].code, errors[0].message);
  return { status: 'PENDING', fileDigest: toHex(fileDigest), attestations };
}
