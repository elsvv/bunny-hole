// src/qr.ts — Minimal QR code generator (byte mode, ECC level L, versions 1–10)

// --- QR tables ---

// Total codewords per version (1-10)
const TOTAL_CW = [0, 26, 44, 70, 100, 134, 172, 196, 242, 292, 346];

// EC codewords per block for level L, versions 1-10
const EC_CW_PER_BLK = [0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18];

// Number of EC blocks for level L, versions 1-10
const EC_BLOCKS = [0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4];

// Data capacity in bytes for level L, versions 1-10 (byte mode)
const DATA_CAP = [0, 17, 32, 53, 78, 106, 134, 154, 192, 230, 271];

// Alignment pattern center positions (version 2+)
const ALIGN_POS: number[][] = [
  [], [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34],
  [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50],
];

// Size = 17 + version*4
function moduleCount(ver: number): number {
  return 17 + ver * 4;
}

// Character count bits for byte mode: 8 for v1-9, 16 for v10+
function ccBits(ver: number): number {
  return ver <= 9 ? 8 : 16;
}

// --- GF(2^8) arithmetic for Reed-Solomon ---

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);

(function initGF() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x = (x << 1) ^ (x & 128 ? 0x11d : 0);
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function rsGenPoly(degree: number): Uint8Array {
  const poly = new Uint8Array(degree + 1);
  poly[0] = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = degree; j >= 1; j--) {
      poly[j] = poly[j - 1] ^ gfMul(poly[j], GF_EXP[i]);
    }
    poly[0] = gfMul(poly[0], GF_EXP[i]);
  }
  return poly;
}

function rsEncode(data: Uint8Array, ecLen: number): Uint8Array {
  const gen = rsGenPoly(ecLen);
  const buf = new Uint8Array(data.length + ecLen);
  buf.set(data);
  for (let i = 0; i < data.length; i++) {
    const coef = buf[i];
    if (coef === 0) continue;
    for (let j = 0; j <= ecLen; j++) {
      buf[i + j] ^= gfMul(gen[ecLen - j], coef);
    }
  }
  return buf.slice(data.length);
}

// --- Data encoding (byte mode) ---

function encodeData(text: string, ver: number): Uint8Array {
  const totalCW = TOTAL_CW[ver];
  const ecPerBlk = EC_CW_PER_BLK[ver];
  const numBlks = EC_BLOCKS[ver];
  const totalEC = ecPerBlk * numBlks;
  const dataCW = totalCW - totalEC;

  // Build the bit stream
  const bytes: number[] = [];
  // Mode indicator: 0100 (byte mode)
  // Character count
  const ccLen = ccBits(ver);
  const textBytes: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c > 255) throw new Error('QR byte mode supports ISO 8859-1 only');
    textBytes.push(c);
  }

  // Build bit string
  let bits = '';
  bits += '0100'; // byte mode
  bits += textBytes.length.toString(2).padStart(ccLen, '0');
  for (const b of textBytes) bits += b.toString(2).padStart(8, '0');

  // Terminator (up to 4 zeros)
  const maxBits = dataCW * 8;
  const termLen = Math.min(4, maxBits - bits.length);
  bits += '0'.repeat(termLen);

  // Pad to byte boundary
  if (bits.length % 8 !== 0) {
    bits += '0'.repeat(8 - (bits.length % 8));
  }

  // Convert to bytes
  for (let i = 0; i < bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }

  // Pad with alternating 236/17
  const pads = [236, 17];
  let pi = 0;
  while (bytes.length < dataCW) {
    bytes.push(pads[pi]);
    pi ^= 1;
  }

  const dataArr = new Uint8Array(bytes);

  // Split into blocks and compute EC
  const shortBlkLen = Math.floor(dataCW / numBlks);
  const longBlks = dataCW % numBlks;
  const dataBlocks: Uint8Array[] = [];
  const ecBlocks: Uint8Array[] = [];

  let offset = 0;
  for (let i = 0; i < numBlks; i++) {
    const blkLen = shortBlkLen + (i >= numBlks - longBlks ? 1 : 0);
    const block = dataArr.slice(offset, offset + blkLen);
    dataBlocks.push(block);
    ecBlocks.push(rsEncode(block, ecPerBlk));
    offset += blkLen;
  }

  // Interleave data codewords
  const result: number[] = [];
  const maxDataLen = shortBlkLen + (longBlks > 0 ? 1 : 0);
  for (let i = 0; i < maxDataLen; i++) {
    for (let j = 0; j < numBlks; j++) {
      if (i < dataBlocks[j].length) result.push(dataBlocks[j][i]);
    }
  }

  // Interleave EC codewords
  for (let i = 0; i < ecPerBlk; i++) {
    for (let j = 0; j < numBlks; j++) {
      result.push(ecBlocks[j][i]);
    }
  }

  return new Uint8Array(result);
}

// --- Matrix construction ---

type Grid = Uint8Array[]; // each row is a Uint8Array, values: 0=white, 1=black
type Reserved = Uint8Array[]; // 1 = function pattern (not data)

function makeGrid(n: number): Grid {
  return Array.from({ length: n }, () => new Uint8Array(n));
}

function setModule(grid: Grid, reserved: Reserved, r: number, c: number, val: number) {
  grid[r][c] = val ? 1 : 0;
  reserved[r][c] = 1;
}

function addFinderPattern(grid: Grid, reserved: Reserved, row: number, col: number) {
  for (let dr = -1; dr <= 7; dr++) {
    for (let dc = -1; dc <= 7; dc++) {
      const r = row + dr, c = col + dc;
      if (r < 0 || r >= grid.length || c < 0 || c >= grid.length) continue;
      const inOuter = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6;
      const inInner = dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4;
      const onBorder = dr === 0 || dr === 6 || dc === 0 || dc === 6;
      const val = inInner || (inOuter && onBorder) ? 1 : 0;
      setModule(grid, reserved, r, c, val);
    }
  }
}

function addAlignmentPattern(grid: Grid, reserved: Reserved, row: number, col: number) {
  for (let dr = -2; dr <= 2; dr++) {
    for (let dc = -2; dc <= 2; dc++) {
      const val = Math.abs(dr) === 2 || Math.abs(dc) === 2 || (dr === 0 && dc === 0) ? 1 : 0;
      setModule(grid, reserved, row + dr, col + dc, val);
    }
  }
}

function addTimingPatterns(grid: Grid, reserved: Reserved, n: number) {
  for (let i = 8; i < n - 8; i++) {
    const val = i % 2 === 0 ? 1 : 0;
    if (!reserved[6][i]) setModule(grid, reserved, 6, i, val);
    if (!reserved[i][6]) setModule(grid, reserved, i, 6, val);
  }
}

function reserveFormatArea(grid: Grid, reserved: Reserved, n: number) {
  // Reserve format info bits around finder patterns
  for (let i = 0; i < 8; i++) {
    reserved[8][i] = 1;
    reserved[i][8] = 1;
    reserved[8][n - 1 - i] = 1;
    reserved[n - 1 - i][8] = 1;
  }
  reserved[8][8] = 1;
  // Dark module
  grid[n - 8][8] = 1;
  reserved[n - 8][8] = 1;
}

function placeData(grid: Grid, reserved: Reserved, n: number, data: Uint8Array) {
  let bitIdx = 0;
  const totalBits = data.length * 8;
  let col = n - 1;

  while (col >= 0) {
    if (col === 6) col--; // skip timing column
    for (let row = 0; row < n; row++) {
      for (let c = 0; c < 2; c++) {
        const curCol = col - c;
        if (curCol < 0) continue;
        // Upward or downward?
        const upward = ((n - 1 - col) >> 1) % 2 === 0;
        const curRow = upward ? n - 1 - row : row;
        if (reserved[curRow][curCol]) continue;
        if (bitIdx < totalBits) {
          const byteIdx = bitIdx >> 3;
          const bitPos = 7 - (bitIdx & 7);
          grid[curRow][curCol] = (data[byteIdx] >> bitPos) & 1;
        }
        bitIdx++;
      }
    }
    col -= 2;
  }
}

// --- Masking ---

const MASK_FNS: ((r: number, c: number) => boolean)[] = [
  (r, c) => (r + c) % 2 === 0,
  (r) => r % 2 === 0,
  (_, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
];

function applyMask(grid: Grid, reserved: Reserved, n: number, maskIdx: number): Grid {
  const masked = makeGrid(n);
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      masked[r][c] = grid[r][c];
      if (!reserved[r][c] && MASK_FNS[maskIdx](r, c)) {
        masked[r][c] ^= 1;
      }
    }
  }
  return masked;
}

// --- Format info ---

// Format info for ECC level L (bits 00) with each mask pattern 0-7
// Pre-computed BCH(15,5) encoded with mask applied
const FORMAT_BITS: number[] = [
  0x77c4, 0x72f3, 0x7daa, 0x789d, 0x662f, 0x6318, 0x6c41, 0x6976,
];

function writeFormatInfo(grid: Grid, n: number, maskIdx: number) {
  const bits = FORMAT_BITS[maskIdx];
  // Around top-left finder
  const pos0 = [
    [0, 8], [1, 8], [2, 8], [3, 8], [4, 8], [5, 8],
    [7, 8], [8, 8], [8, 7], [8, 5], [8, 4], [8, 3],
    [8, 2], [8, 1], [8, 0],
  ];
  for (let i = 0; i < 15; i++) {
    const val = (bits >> (14 - i)) & 1;
    grid[pos0[i][0]][pos0[i][1]] = val;
  }
  // Around bottom-left and top-right finders
  const pos1: [number, number][] = [];
  for (let i = 0; i < 7; i++) pos1.push([8, n - 1 - i]);
  for (let i = 7; i < 15; i++) pos1.push([n - 15 + i, 8]);
  for (let i = 0; i < 15; i++) {
    const val = (bits >> (14 - i)) & 1;
    grid[pos1[i][0]][pos1[i][1]] = val;
  }
}

// --- Penalty scoring ---

function penalty(grid: Grid, n: number): number {
  let score = 0;

  // Rule 1: runs of 5+ same-color modules in a row/col
  for (let r = 0; r < n; r++) {
    let run = 1;
    for (let c = 1; c < n; c++) {
      if (grid[r][c] === grid[r][c - 1]) {
        run++;
      } else {
        if (run >= 5) score += run - 2;
        run = 1;
      }
    }
    if (run >= 5) score += run - 2;
  }
  for (let c = 0; c < n; c++) {
    let run = 1;
    for (let r = 1; r < n; r++) {
      if (grid[r][c] === grid[r - 1][c]) {
        run++;
      } else {
        if (run >= 5) score += run - 2;
        run = 1;
      }
    }
    if (run >= 5) score += run - 2;
  }

  // Rule 2: 2x2 blocks
  for (let r = 0; r < n - 1; r++) {
    for (let c = 0; c < n - 1; c++) {
      const v = grid[r][c];
      if (v === grid[r][c + 1] && v === grid[r + 1][c] && v === grid[r + 1][c + 1]) {
        score += 3;
      }
    }
  }

  // Rule 3: finder-like patterns (simplified — check for 1011101 patterns)
  const pat1 = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
  const pat2 = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1];
  for (let r = 0; r < n; r++) {
    for (let c = 0; c <= n - 11; c++) {
      let match1 = true, match2 = true;
      for (let k = 0; k < 11; k++) {
        if (grid[r][c + k] !== pat1[k]) match1 = false;
        if (grid[r][c + k] !== pat2[k]) match2 = false;
      }
      if (match1 || match2) score += 40;
    }
  }
  for (let c = 0; c < n; c++) {
    for (let r = 0; r <= n - 11; r++) {
      let match1 = true, match2 = true;
      for (let k = 0; k < 11; k++) {
        if (grid[r + k][c] !== pat1[k]) match1 = false;
        if (grid[r + k][c] !== pat2[k]) match2 = false;
      }
      if (match1 || match2) score += 40;
    }
  }

  // Rule 4: proportion of dark modules
  let dark = 0;
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      if (grid[r][c]) dark++;
    }
  }
  const pct = (dark * 100) / (n * n);
  const prev5 = Math.floor(pct / 5) * 5;
  const next5 = prev5 + 5;
  score += Math.min(Math.abs(prev5 - 50) / 5, Math.abs(next5 - 50) / 5) * 10;

  return score;
}

// --- Main encode ---

function buildMatrix(text: string): Grid {
  // Pick version
  let ver = 0;
  for (let v = 1; v <= 10; v++) {
    if (text.length <= DATA_CAP[v]) { ver = v; break; }
  }
  if (ver === 0) throw new Error('Text too long for QR versions 1-10');

  const n = moduleCount(ver);

  // Encode data
  const codewords = encodeData(text, ver);

  // Build grid with function patterns
  const grid = makeGrid(n);
  const reserved = makeGrid(n);

  // Finder patterns
  addFinderPattern(grid, reserved, 0, 0);
  addFinderPattern(grid, reserved, 0, n - 7);
  addFinderPattern(grid, reserved, n - 7, 0);

  // Alignment patterns
  if (ver >= 2) {
    const positions = ALIGN_POS[ver];
    for (const r of positions) {
      for (const c of positions) {
        // Skip if overlapping finder patterns
        if (r <= 8 && c <= 8) continue;
        if (r <= 8 && c >= n - 8) continue;
        if (r >= n - 8 && c <= 8) continue;
        addAlignmentPattern(grid, reserved, r, c);
      }
    }
  }

  // Timing patterns
  addTimingPatterns(grid, reserved, n);

  // Reserve format area
  reserveFormatArea(grid, reserved, n);

  // Place data
  placeData(grid, reserved, n, codewords);

  // Try all 8 masks, pick best
  let bestMask = 0;
  let bestScore = Infinity;
  let bestGrid = grid;

  for (let m = 0; m < 8; m++) {
    const masked = applyMask(grid, reserved, n, m);
    writeFormatInfo(masked, n, m);
    const s = penalty(masked, n);
    if (s < bestScore) {
      bestScore = s;
      bestMask = m;
      bestGrid = masked;
    }
  }

  // Apply best mask
  if (bestGrid === grid) {
    bestGrid = applyMask(grid, reserved, n, bestMask);
  }
  writeFormatInfo(bestGrid, n, bestMask);

  return bestGrid;
}

// --- Canvas rendering ---

export function renderQR(canvas: HTMLCanvasElement, text: string, cellSize = 4): void {
  const grid = buildMatrix(text);
  const n = grid.length;
  const quiet = 4; // quiet zone
  const size = (n + quiet * 2) * cellSize;
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext('2d')!;
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, size, size);
  ctx.fillStyle = '#000000';
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      if (grid[r][c]) {
        ctx.fillRect((c + quiet) * cellSize, (r + quiet) * cellSize, cellSize, cellSize);
      }
    }
  }
}

// Export for testing
export { buildMatrix as _buildMatrix };
