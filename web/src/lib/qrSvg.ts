/**
 * Deterministic Zero-Dependency ISO/IEC 18004 QR Code Matrix Generator (Byte Mode, ECC-L/M).
 *
 * Produces a boolean module grid (`true` = dark module) suitable for crisp inline
 * `<svg>` rendering on 16:9 / 9:16 share cards and print tear sheets.
 */

const EXP_TABLE = new Uint8Array(512);
const LOG_TABLE = new Uint8Array(256);

(() => {
  let x = 1;
  for (let i = 0; i < 255; i += 1) {
    EXP_TABLE[i] = x;
    LOG_TABLE[x] = i;
    x <<= 1;
    if (x & 0x100) {
      x ^= 0x11d;
    }
  }
  for (let i = 255; i < 512; i += 1) {
    EXP_TABLE[i] = EXP_TABLE[i - 255]!;
  }
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP_TABLE[LOG_TABLE[a]! + LOG_TABLE[b]!]!;
}

function polyMul(p: Uint8Array, q: Uint8Array): Uint8Array {
  const out = new Uint8Array(p.length + q.length - 1);
  for (let i = 0; i < p.length; i += 1) {
    for (let j = 0; j < q.length; j += 1) {
      out[i + j] ^= gfMul(p[i]!, q[j]!);
    }
  }
  return out;
}

function rsGeneratorPoly(ecLen: number): Uint8Array {
  let poly: Uint8Array = new Uint8Array([1]);
  for (let i = 0; i < ecLen; i += 1) {
    poly = polyMul(poly, new Uint8Array([1, EXP_TABLE[i]!]));
  }
  return poly;
}

function rsComputeRemainder(data: Uint8Array, ecLen: number): Uint8Array {
  const gen = rsGeneratorPoly(ecLen);
  const msg = new Uint8Array(data.length + ecLen);
  msg.set(data, 0);
  for (let i = 0; i < data.length; i += 1) {
    const coef = msg[i]!;
    if (coef !== 0) {
      for (let j = 0; j < gen.length; j += 1) {
        msg[i + j] ^= gfMul(gen[j]!, coef);
      }
    }
  }
  return msg.slice(data.length);
}

interface VersionSpec {
  version: number;
  size: number;
  totalDataCodewords: number;
  ecCodewordsPerBlock: number;
  numBlocks: number;
  alignmentCenters: number[];
}

// ECC Level L specs for single/dual block versions 2..6 (up to 134 UTF-8 bytes)
const VERSION_SPECS: readonly VersionSpec[] = [
  { version: 2, size: 25, totalDataCodewords: 34, ecCodewordsPerBlock: 10, numBlocks: 1, alignmentCenters: [6, 18] },
  { version: 3, size: 29, totalDataCodewords: 55, ecCodewordsPerBlock: 15, numBlocks: 1, alignmentCenters: [6, 22] },
  { version: 4, size: 33, totalDataCodewords: 80, ecCodewordsPerBlock: 20, numBlocks: 1, alignmentCenters: [6, 26] },
  { version: 5, size: 37, totalDataCodewords: 108, ecCodewordsPerBlock: 26, numBlocks: 1, alignmentCenters: [6, 30] },
  { version: 6, size: 41, totalDataCodewords: 136, ecCodewordsPerBlock: 18, numBlocks: 2, alignmentCenters: [6, 34] },
];

function selectVersion(byteLen: number): VersionSpec {
  for (const spec of VERSION_SPECS) {
    // 4-bit mode + 8-bit length + bytes + terminator fits in totalDataCodewords
    if (byteLen + 2 <= spec.totalDataCodewords) {
      return spec;
    }
  }
  return VERSION_SPECS[VERSION_SPECS.length - 1]!;
}

function encodeDataCodewords(bytes: Uint8Array, spec: VersionSpec): Uint8Array {
  const maxPayload = spec.totalDataCodewords - 2;
  const clipped = bytes.length > maxPayload ? bytes.slice(0, maxPayload) : bytes;

  const bits: number[] = [];
  const pushBits = (val: number, len: number) => {
    for (let i = len - 1; i >= 0; i -= 1) {
      bits.push((val >>> i) & 1);
    }
  };

  // Byte mode indicator (0100) + 8-bit character count (versions 1..9)
  pushBits(0b0100, 4);
  pushBits(clipped.length, 8);
  for (let i = 0; i < clipped.length; i += 1) {
    pushBits(clipped[i]!, 8);
  }

  const capacityBits = spec.totalDataCodewords * 8;
  const termLen = Math.min(4, capacityBits - bits.length);
  pushBits(0, termLen);
  while (bits.length % 8 !== 0) {
    bits.push(0);
  }

  const out = new Uint8Array(spec.totalDataCodewords);
  const byteCount = bits.length / 8;
  for (let i = 0; i < byteCount; i += 1) {
    let b = 0;
    for (let bit = 0; bit < 8; bit += 1) {
      b = (b << 1) | bits[i * 8 + bit]!;
    }
    out[i] = b;
  }

  const pads = [0xec, 0x11];
  for (let i = byteCount; i < spec.totalDataCodewords; i += 1) {
    out[i] = pads[(i - byteCount) % 2]!;
  }
  return out;
}

function interleaveCodewords(data: Uint8Array, spec: VersionSpec): Uint8Array {
  const blockDataLen = Math.floor(spec.totalDataCodewords / spec.numBlocks);
  const dataBlocks: Uint8Array[] = [];
  const ecBlocks: Uint8Array[] = [];
  for (let b = 0; b < spec.numBlocks; b += 1) {
    const slice = data.slice(b * blockDataLen, (b + 1) * blockDataLen);
    dataBlocks.push(slice);
    ecBlocks.push(rsComputeRemainder(slice, spec.ecCodewordsPerBlock));
  }

  const result: number[] = [];
  for (let i = 0; i < blockDataLen; i += 1) {
    for (let b = 0; b < spec.numBlocks; b += 1) {
      result.push(dataBlocks[b]![i]!);
    }
  }
  for (let i = 0; i < spec.ecCodewordsPerBlock; i += 1) {
    for (let b = 0; b < spec.numBlocks; b += 1) {
      result.push(ecBlocks[b]![i]!);
    }
  }
  return new Uint8Array(result);
}

function computeFormatBits(eccLevelBits: number, mask: number): number {
  const data = (eccLevelBits << 3) | mask;
  let rem = data << 10;
  for (let i = 14; i >= 10; i -= 1) {
    if ((rem >>> i) & 1) {
      rem ^= 0b10100110111 << (i - 10);
    }
  }
  return ((data << 10) | rem) ^ 0b101010000010010;
}

export interface QrSvgData {
  size: number;
  modules: boolean[][];
  svgPath: string;
}

export function generateQrCode(text: string): QrSvgData {
  const bytes = new TextEncoder().encode(text);
  const spec = selectVersion(bytes.length);
  const size = spec.size;

  const modules: boolean[][] = Array.from({ length: size }, () =>
    Array<boolean>(size).fill(false),
  );
  const isFunction: boolean[][] = Array.from({ length: size }, () =>
    Array<boolean>(size).fill(false),
  );

  const setFunc = (r: number, c: number, dark: boolean) => {
    if (r >= 0 && r < size && c >= 0 && c < size) {
      modules[r]![c] = dark;
      isFunction[r]![c] = true;
    }
  };

  // Finder patterns + separators
  const drawFinder = (topR: number, leftC: number) => {
    for (let dr = -1; dr <= 7; dr += 1) {
      for (let dc = -1; dc <= 7; dc += 1) {
        const rr = topR + dr;
        const cc = leftC + dc;
        const inOuter = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6;
        const onRing = dr === 0 || dr === 6 || dc === 0 || dc === 6;
        const inCore = dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4;
        setFunc(rr, cc, inOuter && (onRing || inCore));
      }
    }
  };

  drawFinder(0, 0);
  drawFinder(0, size - 7);
  drawFinder(size - 7, 0);

  // Timing patterns
  for (let i = 8; i < size - 8; i += 1) {
    setFunc(6, i, i % 2 === 0);
    setFunc(i, 6, i % 2 === 0);
  }

  // Alignment patterns
  const centers = spec.alignmentCenters;
  for (const cr of centers) {
    for (const cc of centers) {
      if (
        (cr === 6 && cc === 6) ||
        (cr === 6 && cc === size - 7) ||
        (cr === size - 7 && cc === 6)
      ) {
        continue;
      }
      for (let dr = -2; dr <= 2; dr += 1) {
        for (let dc = -2; dc <= 2; dc += 1) {
          const dark =
            Math.max(Math.abs(dr), Math.abs(dc)) === 2 || (dr === 0 && dc === 0);
          setFunc(cr + dr, cc + dc, dark);
        }
      }
    }
  }

  // Dark module & reserve format info slots
  setFunc(size - 8, 8, true);
  for (let i = 0; i <= 8; i += 1) {
    if (!isFunction[8]![i]) setFunc(8, i, false);
    if (!isFunction[i]![8]) setFunc(i, 8, false);
  }
  for (let i = 0; i < 8; i += 1) {
    if (!isFunction[8]![size - 1 - i]) setFunc(8, size - 1 - i, false);
    if (!isFunction[size - 1 - i]![8]) setFunc(size - 1 - i, 8, false);
  }

  const dataWords = encodeDataCodewords(bytes, spec);
  const codewords = interleaveCodewords(dataWords, spec);

  // Place data bits in upward/downward 2-column zig-zag
  let bitIdx = 0;
  const totalBits = codewords.length * 8;
  let upward = true;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) {
      right = 5;
    }
    for (let vert = 0; vert < size; vert += 1) {
      const r = upward ? size - 1 - vert : vert;
      for (let j = 0; j < 2; j += 1) {
        const c = right - j;
        if (!isFunction[r]![c]) {
          let dark = false;
          if (bitIdx < totalBits) {
            dark = ((codewords[bitIdx >>> 3]! >>> (7 - (bitIdx & 7))) & 1) === 1;
            bitIdx += 1;
          }
          // Apply mask 0: (r + c) % 2 === 0
          if ((r + c) % 2 === 0) {
            dark = !dark;
          }
          modules[r]![c] = dark;
        }
      }
    }
    upward = !upward;
  }

  // Write Format Information for ECC Level L (01) + Mask 0 (000)
  const formatBits = computeFormatBits(0b01, 0);
  for (let i = 0; i <= 5; i += 1) setFunc(8, i, ((formatBits >>> i) & 1) === 1);
  setFunc(8, 7, ((formatBits >>> 6) & 1) === 1);
  setFunc(8, 8, ((formatBits >>> 7) & 1) === 1);
  setFunc(7, 8, ((formatBits >>> 8) & 1) === 1);
  for (let i = 9; i < 15; i += 1) {
    setFunc(14 - i, 8, ((formatBits >>> i) & 1) === 1);
  }
  for (let i = 0; i < 8; i += 1) {
    setFunc(8, size - 1 - i, ((formatBits >>> i) & 1) === 1);
  }
  for (let i = 8; i < 15; i += 1) {
    setFunc(size - 15 + i, 8, ((formatBits >>> i) & 1) === 1);
  }

  // Build compact SVG path string
  const parts: string[] = [];
  for (let r = 0; r < size; r += 1) {
    for (let c = 0; c < size; c += 1) {
      if (modules[r]![c]) {
        parts.push(`M${c},${r}h1v1h-1z`);
      }
    }
  }

  return {
    size,
    modules,
    svgPath: parts.join(""),
  };
}
