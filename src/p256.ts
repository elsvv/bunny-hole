// Minimal P-256 (secp256r1) point multiplication.
// Only computes: publicKey = privateScalar × G
// ~70 lines vs ~32 KB from @noble/curves

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const A = P - 3n; // curve parameter a = -3
const Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
const Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;

type Point = { x: bigint; y: bigint } | null;

function mod(a: bigint, m: bigint): bigint {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n;
  base = mod(base, m);
  while (exp > 0n) {
    if (exp & 1n) result = mod(result * base, m);
    exp >>= 1n;
    base = mod(base * base, m);
  }
  return result;
}

function modInv(a: bigint, m: bigint): bigint {
  return modPow(mod(a, m), m - 2n, m);
}

function pointDouble(p: Point): Point {
  if (!p || p.y === 0n) return null;
  const lam = mod((3n * p.x * p.x + A) * modInv(2n * p.y, P), P);
  const x = mod(lam * lam - 2n * p.x, P);
  return { x, y: mod(lam * (p.x - x) - p.y, P) };
}

function pointAdd(p1: Point, p2: Point): Point {
  if (!p1) return p2;
  if (!p2) return p1;
  if (p1.x === p2.x) return p1.y === p2.y ? pointDouble(p1) : null;
  const lam = mod((p2.y - p1.y) * modInv(p2.x - p1.x, P), P);
  const x = mod(lam * lam - p1.x - p2.x, P);
  return { x, y: mod(lam * (p1.x - x) - p1.y, P) };
}

function scalarMul(k: bigint, p: Point): Point {
  let r: Point = null;
  let c = p;
  while (k > 0n) {
    if (k & 1n) r = pointAdd(r, c);
    c = pointDouble(c);
    k >>= 1n;
  }
  return r;
}

function bigintToBytes(n: bigint, len: number): Uint8Array {
  const b = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--, n >>= 8n) b[i] = Number(n & 0xffn);
  return b;
}

/** Compute uncompressed P-256 public key (65 bytes: 04 || X || Y) from 32-byte private scalar. */
export function getP256PublicKey(privateKey: Uint8Array): Uint8Array {
  let k = 0n;
  for (const b of privateKey) k = (k << 8n) | BigInt(b);
  const pub = scalarMul(k, { x: Gx, y: Gy });
  if (!pub) throw new Error('Invalid private key (zero or order)');
  const out = new Uint8Array(65);
  out[0] = 0x04;
  out.set(bigintToBytes(pub.x, 32), 1);
  out.set(bigintToBytes(pub.y, 32), 33);
  return out;
}
