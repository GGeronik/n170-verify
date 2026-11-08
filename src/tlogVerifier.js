// src/tlogVerifier.js: RFC 6962 §2.1 hashing, RFC 9162 §2.1.3.2 inclusion + §2.1.4.2 consistency,
// C2SP signed-note Ed25519 + cosignature/v1 checkpoint verifier. Zero dependencies, no network.
const LEAF_LEN = 105;
const LEAF_VERSION = 0x01;
const ED25519 = 0x01;
const COSIG_V1 = 0x04;
const te = new TextEncoder();

export async function sha256(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const buf = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    buf.set(p, o);
    o += p.length;
  }
  return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', buf));
}

export const leafHash = (entry) => sha256(Uint8Array.of(0x00), entry);
export const nodeHash = (l, r) => sha256(Uint8Array.of(0x01), l, r);
const isHash = (x) => x instanceof Uint8Array && x.length === 32;

export function eq(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export function b64e(u) {
  let s = '';
  for (const b of u) s += String.fromCharCode(b);
  return btoa(s);
}

export function b64d(s) {
  if (typeof s !== 'string' || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) {
    throw new Error('bad base64');
  }
  const bin = atob(s);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  if (b64e(u) !== s) throw new Error('non-canonical base64');
  return u;
}

export const hexe = (u) => Array.from(u, (b) => b.toString(16).padStart(2, '0')).join('');

export function hexd(h) {
  if (typeof h !== 'string' || !/^(?:[0-9a-f]{2})*$/.test(h)) throw new Error('bad hex');
  return Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16));
}

export function u64(x) {
  if (typeof x === 'bigint' && x >= 0n && x < 2n ** 64n) return x;
  if (typeof x === 'number' && Number.isSafeInteger(x) && x >= 0) return BigInt(x);
  if (typeof x === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(x) && BigInt(x) < 2n ** 64n) return BigInt(x);
  throw new Error('bad uint64');
}

export function tileIndexPath(n) {
  const s = n.toString();
  const g = [];
  for (let e = s.length; e > 0; e -= 3) g.unshift(s.slice(Math.max(0, e - 3), e).padStart(3, '0'));
  return g.map((x, i) => (i < g.length - 1 ? 'x' + x : x)).join('/');
}

export function entryLocation(index, treeSize) {
  const idx = u64(index);
  const sz = u64(treeSize);
  const N = idx / 256n;
  const full = (N + 1n) * 256n <= sz;
  const sfx = full ? '' : `.p/${sz % 256n}`;
  return {
    tile: `tile/0/${tileIndexPath(N)}${sfx}`,
    bundle: `tile/entries/${tileIndexPath(N)}${sfx}`,
    offset: idx % 256n,
  };
}

export function parseLeaf(u) {
  if (!(u instanceof Uint8Array) || u.length !== LEAF_LEN || u[0] !== LEAF_VERSION) {
    throw new Error('bad leaf');
  }
  const dv = new DataView(u.buffer, u.byteOffset, u.length);
  return {
    key_code: u.slice(1, 33),
    sequence: dv.getBigUint64(33, false),
    event_sha256: u.slice(41, 73),
    predecessor_sha256: u.slice(73, 105),
  };
}

// RFC 9162 §2.1.3.2
export async function verifyInclusion(index, size, leafH, path, root) {
  let i;
  let n;
  try {
    i = u64(index);
    n = u64(size);
  } catch {
    return false;
  }
  if (i >= n || !isHash(leafH) || !isHash(root) || !Array.isArray(path) || !path.every(isHash)) return false;
  let fn = i;
  let sn = n - 1n;
  let r = leafH;
  for (const p of path) {
    if (sn === 0n) return false;
    if ((fn & 1n) === 1n || fn === sn) {
      r = await nodeHash(p, r);
      while ((fn & 1n) === 0n && fn !== 0n) {
        fn >>= 1n;
        sn >>= 1n;
      }
    } else {
      r = await nodeHash(r, p);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n && eq(r, root);
}

// RFC 9162 §2.1.4.2
export async function verifyConsistency(first, second, firstRoot, secondRoot, path) {
  let m;
  let n;
  try {
    m = u64(first);
    n = u64(second);
  } catch {
    return false;
  }
  if (m > n || !isHash(firstRoot) || !isHash(secondRoot) || !Array.isArray(path) || !path.every(isHash)) return false;
  if (m === n) return path.length === 0 && eq(firstRoot, secondRoot);
  if (m === 0n) return path.length === 0;
  if (path.length === 0) return false;
  const p = (m & (m - 1n)) === 0n ? [firstRoot, ...path] : path.slice();
  let fn = m - 1n;
  let sn = n - 1n;
  while ((fn & 1n) === 1n) {
    fn >>= 1n;
    sn >>= 1n;
  }
  let fr = p[0];
  let sr = p[0];
  for (const c of p.slice(1)) {
    if (sn === 0n) return false;
    if ((fn & 1n) === 1n || fn === sn) {
      fr = await nodeHash(c, fr);
      sr = await nodeHash(c, sr);
      while ((fn & 1n) === 0n && fn !== 0n) {
        fn >>= 1n;
        sn >>= 1n;
      }
    } else {
      sr = await nodeHash(sr, c);
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  return sn === 0n && eq(fr, firstRoot) && eq(sr, secondRoot);
}

export async function verifyN170Merkle(b, cp, pinnedKeyCode, prev) {
  const out = { ok: false, errors: [], warnings: [] };
  const fail = (e) => (out.errors.push(e), out);
  try {
    const expectedKeyCode = typeof pinnedKeyCode === 'string' ? hexd(pinnedKeyCode) : pinnedKeyCode;
    const leafBytes = b64d(b.leaf);
    const leaf = parseLeaf(leafBytes);
    const record = b64d(b.record);
    if (!eq(leaf.key_code, expectedKeyCode)) return fail('key_code does not match the pinned owner key');
    if (!eq(leaf.event_sha256, await sha256(record))) return fail('event_sha256 != SHA-256(bundled record)');
    if (!(await verifyInclusion(b.leaf_index, cp.size, await leafHash(leafBytes), b.inclusion_path.map(b64d), cp.root))) {
      return fail('inclusion proof does not verify against the checkpoint root');
    }
    if (leaf.sequence === 0n && !eq(leaf.predecessor_sha256, new Uint8Array(32))) {
      return fail('genesis predecessor must be zero');
    }
    if (prev) {
      const prevSeq = u64(prev.sequence);
      const prevEv = typeof prev.event_sha256 === 'string' ? hexd(prev.event_sha256) : prev.event_sha256;
      const prevRoot = typeof prev.checkpoint_root === 'string' ? b64d(prev.checkpoint_root) : prev.checkpoint_root;
      const prevSize = prev.checkpoint_size !== undefined ? u64(prev.checkpoint_size) : undefined;
      if (leaf.sequence === prevSeq && !eq(leaf.event_sha256, prevEv)) {
        return fail(`EQUIVOCATION: two different signed records for sequence ${leaf.sequence}`);
      }
      if (leaf.sequence === prevSeq + 1n && !eq(leaf.predecessor_sha256, prevEv)) {
        return fail('CHAIN BREAK: predecessor_sha256 != event_sha256 of your previous package');
      }
      if (leaf.sequence > prevSeq + 1n) out.warnings.push('sequence gap: intermediate records were not shown to you');
      if (leaf.sequence < prevSeq) out.warnings.push('this record is older than your previous package');
      if (b.consistency) {
        const c = b.consistency;
        if (u64(c.from_size) !== prevSize || !eq(b64d(c.from_root), prevRoot)) {
          return fail('consistency proof is not anchored at your previously pinned checkpoint');
        }
        if (!(await verifyConsistency(c.from_size, cp.size, prevRoot, cp.root, c.path.map(b64d)))) {
          return fail('LOG FORK: consistency proof fails, the log rewrote history');
        }
      } else if (prevSize !== undefined && prevSize !== u64(cp.size)) {
        out.warnings.push('no consistency proof from your pinned checkpoint');
      }
    }
    out.ok = true;
    out.leaf = leaf;
    return out;
  } catch (err) {
    return fail(err.message || 'malformed bundle');
  }
}

async function parseVkey(v) {
  const i = v.indexOf('+');
  const j = v.indexOf('+', i + 1);
  const name = v.slice(0, i);
  const idHex = v.slice(i + 1, j);
  const raw = b64d(v.slice(j + 1));
  const type = raw[0];
  const pub = raw.slice(1);
  if (i < 1 || j < 0 || !/^[0-9a-f]{8}$/.test(idHex) || ![ED25519, COSIG_V1].includes(type) || pub.length !== 32) {
    throw new Error('unsupported vkey: ' + name);
  }
  const id = (await sha256(te.encode(name + '\n'), Uint8Array.of(type), pub)).slice(0, 4);
  if (hexe(id) !== idHex) throw new Error('vkey key ID mismatch: ' + name);
  return {
    name,
    id,
    type,
    key: await globalThis.crypto.subtle.importKey('raw', pub, { name: 'Ed25519' }, false, ['verify']),
  };
}

function splitNote(text) {
  if (/[\x00-\x09\x0b-\x1f]/.test(text) || !text.endsWith('\n')) throw new Error('malformed note');
  const k = text.lastIndexOf('\n\n');
  if (k < 0) throw new Error('no signature block');
  const sigs = text.slice(k + 2, -1).split('\n').map((l) => {
    const m = /^\u2014 (\S+) (\S+)$/.exec(l);
    if (!m) throw new Error('bad signature line');
    const raw = b64d(m[2]);
    return { name: m[1], keyId: raw.slice(0, 4), sig: raw.slice(4) };
  });
  return { body: text.slice(0, k + 1), sigs };
}

export async function verifyCheckpoint(text, policy, now = Math.floor(Date.now() / 1000)) {
  if (!globalThis.crypto?.subtle) throw new Error('WebCrypto unavailable (needs a secure context)');
  const { body, sigs } = splitNote(text);
  const lines = body.split('\n');
  lines.pop();
  if (lines.length !== 3 || lines[0] !== policy.origin) {
    throw new Error('wrong origin or unexpected extension lines');
  }
  const size = u64(lines[1]);
  const root = b64d(lines[2]);
  if (root.length !== 32) throw new Error('bad root hash');
  const log = await parseVkey(policy.log);
  const wits = await Promise.all((policy.witnesses || []).map(parseVkey));
  const maxSkewSec = BigInt(policy.maxSkewSec ?? 600);
  const maxAgeSec = BigInt(policy.maxAgeSec ?? 400 * 86400);
  let logOk = false;
  const counted = new Set();
  const report = [];
  for (const s of sigs) {
    if (s.name === log.name && eq(s.keyId, log.id)) {
      if (s.sig.length !== 64 || !(await globalThis.crypto.subtle.verify('Ed25519', log.key, s.sig, te.encode(body)))) {
        throw new Error('log signature INVALID');
      }
      logOk = true;
      continue;
    }
    const w = wits.find((x) => x.name === s.name && eq(x.id, s.keyId));
    if (!w) {
      report.push({ name: s.name, status: 'ignored (unknown key)' });
      continue;
    }
    if (s.sig.length !== 72) throw new Error('bad cosignature length: ' + w.name);
    const ts = new DataView(s.sig.buffer, s.sig.byteOffset, 8).getBigUint64(0, false);
    const msg = te.encode(`cosignature/v1\ntime ${ts}\n${body}`);
    if (!(await globalThis.crypto.subtle.verify('Ed25519', w.key, s.sig.slice(8), msg))) {
      throw new Error('cosignature INVALID: ' + w.name);
    }
    const age = BigInt(now) - ts;
    if (ts === 0n || age < -maxSkewSec || age > maxAgeSec) {
      report.push({
        name: w.name,
        time: new Date(Number(ts) * 1000).toISOString(),
        status: 'valid, outside freshness window: NOT counted',
      });
      continue;
    }
    counted.add(w.name);
    report.push({ name: w.name, time: new Date(Number(ts) * 1000).toISOString(), status: 'counted' });
  }
  if (!logOk) throw new Error('no valid signature from the pinned log key');
  if (counted.size < policy.quorum) {
    throw new Error(`witness quorum not met: ${counted.size}/${policy.quorum}`);
  }
  return { origin: lines[0], size, root, witnesses: report };
}

export async function verifyTlogProofBundle(proofInput, policyInput, previousReceiptInput = null) {
  try {
    const proofBundle = typeof proofInput === 'string' ? JSON.parse(proofInput) : proofInput;
    if (!proofBundle || typeof proofBundle !== 'object' || Array.isArray(proofBundle) || typeof proofBundle.checkpoint !== 'string') {
      throw new Error('malformed transparency proof bundle');
    }
    const policy = typeof policyInput === 'string' ? JSON.parse(policyInput) : policyInput;
    if (
      !policy ||
      typeof policy !== 'object' ||
      Array.isArray(policy) ||
      typeof policy.origin !== 'string' ||
      !policy.origin.trim() ||
      typeof policy.log !== 'string' ||
      !policy.log.trim() ||
      !Array.isArray(policy.witnesses) ||
      policy.witnesses.length === 0 ||
      !Number.isSafeInteger(policy.quorum) ||
      policy.quorum < 1 ||
      typeof policy.key_code !== 'string' ||
      !/^[0-9a-f]{64}$/.test(policy.key_code)
    ) {
      throw new Error('transparency log policy requires origin, log, witnesses, positive integer quorum, and 64-hex key_code');
    }
    let previousReceipt = null;
    if (previousReceiptInput !== null && previousReceiptInput !== undefined && previousReceiptInput !== '') {
      if (typeof previousReceiptInput === 'string') {
        if (previousReceiptInput.trim() !== '') {
          previousReceipt = JSON.parse(previousReceiptInput);
        }
      } else {
        previousReceipt = previousReceiptInput;
      }
      if (
        previousReceipt !== null &&
        (!previousReceipt ||
          typeof previousReceipt !== 'object' ||
          Array.isArray(previousReceipt) ||
          previousReceipt.sequence === undefined ||
          !previousReceipt.event_sha256)
      ) {
        throw new Error('malformed previous transparency receipt');
      }
    }
    const cp = await verifyCheckpoint(proofBundle.checkpoint, policy, policy.now ?? Math.floor(Date.now() / 1000));
    const merkle = await verifyN170Merkle(proofBundle, cp, policy.key_code, previousReceipt);
    if (!merkle.ok) {
      const conflict = merkle.errors.some(
        (e) => e.startsWith('EQUIVOCATION:') || e.startsWith('CHAIN BREAK:') || e.startsWith('LOG FORK:')
      );
      return { ok: false, conflict, errors: merkle.errors, warnings: merkle.warnings };
    }
    return {
      ok: true,
      conflict: false,
      origin: cp.origin,
      treeSize: cp.size.toString(),
      rootBase64: b64e(cp.root),
      sequence: merkle.leaf.sequence.toString(),
      keyCodeHex: hexe(merkle.leaf.key_code),
      eventSha256Hex: hexe(merkle.leaf.event_sha256),
      predecessorSha256Hex: hexe(merkle.leaf.predecessor_sha256),
      witnesses: cp.witnesses,
      warnings: merkle.warnings,
      retentionReceipt: {
        sequence: merkle.leaf.sequence.toString(),
        event_sha256: hexe(merkle.leaf.event_sha256),
        checkpoint_size: cp.size.toString(),
        checkpoint_root: b64e(cp.root),
      },
    };
  } catch (err) {
    return { ok: false, conflict: false, errors: [err.message || 'malformed transparency proof'], warnings: [] };
  }
}

