# Bunny Hole Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a frontend-only encrypted messaging app that encodes encrypted payloads in URL fragments, using passkeys (ECIES) or passwords (PBKDF2) for encryption.

**Architecture:** Single-page app compiled from TypeScript modules into one inlined HTML file. All crypto via Web Crypto API, auth via WebAuthn PRF extension. Zero runtime dependencies. Data stored in localStorage.

**Tech Stack:** TypeScript, esbuild (dev), Web Crypto API, WebAuthn API, Node built-in test runner

---

### Task 1: Project Setup

**Files:**
- Create: `package.json`
- Create: `tsconfig.json`
- Create: `src/main.ts` (empty entry point)
- Create: `index.html` (shell)
- Create: `build.sh`

**Step 1: Initialize project**

```bash
cd /Users/vaceslaveliseev/@dev/bunny-hole
npm init -y
npm install --save-dev esbuild
```

**Step 2: Create tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "noEmit": true,
    "lib": ["ES2022", "DOM", "DOM.Iterable"]
  },
  "include": ["src"]
}
```

**Step 3: Create index.html**

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Bunny Hole</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,sans-serif;max-width:600px;margin:0 auto;padding:1rem}
h1{margin-bottom:.25rem}
p.sub{color:#666;margin-bottom:1rem}
textarea,input[type=text],input[type=password]{width:100%;padding:.5rem;font:inherit;border:1px solid #ccc}
textarea{height:8rem;resize:vertical}
button{padding:.5rem 1rem;font:inherit;cursor:pointer}
hr{margin:1rem 0;border:none;border-top:1px solid #ccc}
pre.msg{white-space:pre-wrap;word-break:break-all;background:#f5f5f5;padding:1rem;border:1px solid #ccc}
.err{color:red}
.warn{color:#856404;background:#fff3cd;padding:.5rem;border:1px solid #ffeeba}
.row{display:flex;gap:.5rem;align-items:center;margin:.25rem 0}
.row input{flex:1}
.hidden{display:none}
label{cursor:pointer}
.contact{display:flex;justify-content:space-between;align-items:center;padding:.25rem 0}
.contact code{font-size:.85em;color:#666}
#result-url{width:100%;font-family:monospace;font-size:.85em}
canvas{margin-top:.5rem}
</style>
</head>
<body>
<h1>Bunny Hole</h1>
<p class="sub">Encrypted messages via URL. No server. No tracking.</p>
<div id="app"></div>
<script src="dist/app.js"></script>
</body>
</html>
```

**Step 4: Create empty entry point**

```typescript
// src/main.ts
console.log('Bunny Hole loaded');
```

**Step 5: Create build script**

```bash
#!/bin/bash
set -e
npx esbuild src/main.ts --bundle --minify --outfile=dist/app.js --target=es2022
echo "Build complete: dist/app.js ($(wc -c < dist/app.js) bytes)"
```

**Step 6: Add npm scripts to package.json**

Add to `scripts`:
```json
{
  "build": "bash build.sh",
  "dev": "npx esbuild src/main.ts --bundle --outfile=dist/app.js --target=es2022 --watch --servedir=.",
  "check": "npx tsc --noEmit",
  "test": "node --test --experimental-strip-types tests/*.test.ts"
}
```

**Step 7: Verify build**

Run: `npm run build`
Expected: `dist/app.js` created, console shows byte count.

Run: `npm run dev` (briefly, Ctrl+C)
Expected: dev server starts, serves index.html.

**Step 8: Commit**

```bash
echo "node_modules" > .gitignore && echo "dist" >> .gitignore
git add package.json tsconfig.json index.html build.sh src/main.ts .gitignore
git commit -m "chore: project setup with esbuild and TypeScript"
```

---

### Task 2: Base64url and Binary Encoding Utilities

**Files:**
- Create: `src/encoding.ts`
- Create: `tests/encoding.test.ts`

**Step 1: Write the failing tests**

```typescript
// tests/encoding.test.ts
import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { toBase64url, fromBase64url, encodePayload, decodePayload } from '../src/encoding.ts';

describe('base64url', () => {
  it('round-trips binary data', () => {
    const data = new Uint8Array([0, 1, 2, 255, 254, 253]);
    assert.deepStrictEqual(fromBase64url(toBase64url(data)), data);
  });

  it('produces URL-safe output (no +/= chars)', () => {
    const data = new Uint8Array(256);
    for (let i = 0; i < 256; i++) data[i] = i;
    const encoded = toBase64url(data);
    assert.ok(!encoded.includes('+'), 'should not contain +');
    assert.ok(!encoded.includes('/'), 'should not contain /');
    assert.ok(!encoded.includes('='), 'should not contain =');
  });

  it('handles empty data', () => {
    const data = new Uint8Array(0);
    assert.deepStrictEqual(fromBase64url(toBase64url(data)), data);
  });
});

describe('payload encoding', () => {
  it('encodes and decodes password mode (0x01)', () => {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array([10, 20, 30]);
    const encoded = encodePayload(0x01, salt, iv, ciphertext);
    const decoded = decodePayload(encoded);
    assert.equal(decoded.mode, 0x01);
    assert.deepStrictEqual(decoded.parts[0], salt);
    assert.deepStrictEqual(decoded.parts[1], iv);
    assert.deepStrictEqual(decoded.parts[2], ciphertext);
  });

  it('encodes and decodes passkey mode (0x02)', () => {
    const ephPubkey = crypto.getRandomValues(new Uint8Array(65));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array([40, 50, 60]);
    const encoded = encodePayload(0x02, ephPubkey, iv, ciphertext);
    const decoded = decodePayload(encoded);
    assert.equal(decoded.mode, 0x02);
    assert.deepStrictEqual(decoded.parts[0], ephPubkey);
    assert.deepStrictEqual(decoded.parts[1], iv);
    assert.deepStrictEqual(decoded.parts[2], ciphertext);
  });

  it('encodes and decodes key share mode (0x03)', () => {
    const pubkey = crypto.getRandomValues(new Uint8Array(65));
    const label = new TextEncoder().encode('Alice');
    const encoded = encodePayload(0x03, pubkey, label);
    const decoded = decodePayload(encoded);
    assert.equal(decoded.mode, 0x03);
    assert.deepStrictEqual(decoded.parts[0], pubkey);
    assert.equal(new TextDecoder().decode(decoded.parts[1]), 'Alice');
  });
});
```

**Step 2: Run tests to verify they fail**

Run: `npm test`
Expected: FAIL — module not found

**Step 3: Implement encoding.ts**

```typescript
// src/encoding.ts

export function toBase64url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64url(str: string): Uint8Array {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Payload layout per mode:
// 0x01: mode(1) | salt(16) | iv(12) | ciphertext(rest)
// 0x02: mode(1) | ephemeral_pubkey(65) | iv(12) | ciphertext(rest)
// 0x03: mode(1) | pubkey(65) | label(rest)

const MODE_LAYOUT: Record<number, number[]> = {
  0x01: [16, 12], // salt, iv — rest is ciphertext
  0x02: [65, 12], // ephemeral_pubkey, iv — rest is ciphertext
  0x03: [65],     // pubkey — rest is label
};

export function encodePayload(mode: number, ...parts: Uint8Array[]): string {
  let totalLen = 1;
  for (const p of parts) totalLen += p.length;
  const buf = new Uint8Array(totalLen);
  buf[0] = mode;
  let offset = 1;
  for (const p of parts) {
    buf.set(p, offset);
    offset += p.length;
  }
  return toBase64url(buf);
}

export function decodePayload(encoded: string): { mode: number; parts: Uint8Array[] } {
  const buf = fromBase64url(encoded);
  const mode = buf[0];
  const layout = MODE_LAYOUT[mode];
  if (!layout) throw new Error(`Unknown mode: 0x${mode.toString(16)}`);

  const parts: Uint8Array[] = [];
  let offset = 1;
  for (const size of layout) {
    parts.push(buf.slice(offset, offset + size));
    offset += size;
  }
  // remaining bytes are the last part
  parts.push(buf.slice(offset));
  return { mode, parts };
}
```

**Step 4: Run tests to verify they pass**

Run: `npm test`
Expected: All tests PASS

**Step 5: Commit**

```bash
git add src/encoding.ts tests/encoding.test.ts
git commit -m "feat: base64url and payload encoding utilities"
```

---

### Task 3: Password-Mode Encryption

**Files:**
- Create: `src/crypto-password.ts`
- Create: `tests/crypto-password.test.ts`

**Step 1: Write the failing tests**

```typescript
// tests/crypto-password.test.ts
import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { encryptPassword, decryptPassword } from '../src/crypto-password.ts';

describe('password mode encryption', () => {
  it('round-trips a simple message', async () => {
    const message = 'Hello, World!';
    const password = 'test-password-123';
    const fragment = await encryptPassword(message, password);
    const decrypted = await decryptPassword(fragment, password);
    assert.equal(decrypted, message);
  });

  it('round-trips unicode text', async () => {
    const message = 'Привет! 你好 🐰';
    const password = 'unicode-pass';
    const fragment = await encryptPassword(message, password);
    const decrypted = await decryptPassword(fragment, password);
    assert.equal(decrypted, message);
  });

  it('round-trips empty message', async () => {
    const fragment = await encryptPassword('', 'pass');
    const decrypted = await decryptPassword(fragment, 'pass');
    assert.equal(decrypted, '');
  });

  it('fails with wrong password', async () => {
    const fragment = await encryptPassword('secret', 'right');
    await assert.rejects(
      () => decryptPassword(fragment, 'wrong'),
      { name: 'OperationError' }
    );
  });

  it('produces different ciphertext each time (random salt/iv)', async () => {
    const a = await encryptPassword('same', 'pass');
    const b = await encryptPassword('same', 'pass');
    assert.notEqual(a, b);
  });
});
```

**Step 2: Run tests to verify they fail**

Run: `npm test`
Expected: FAIL — module not found

**Step 3: Implement crypto-password.ts**

```typescript
// src/crypto-password.ts
import { encodePayload, decodePayload } from './encoding.ts';

const ITERATIONS = 310_000;

async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptPassword(message: string, password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(message))
  );
  return encodePayload(0x01, salt, iv, ciphertext);
}

export async function decryptPassword(fragment: string, password: string): Promise<string> {
  const { mode, parts } = decodePayload(fragment);
  if (mode !== 0x01) throw new Error('Not a password-mode payload');
  const [salt, iv, ciphertext] = parts;
  const key = await deriveKey(password, salt);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new TextDecoder().decode(plaintext);
}
```

**Step 4: Run tests to verify they pass**

Run: `npm test`
Expected: All tests PASS (PBKDF2 with 310k iterations will take ~0.5-1s per call)

**Step 5: Commit**

```bash
git add src/crypto-password.ts tests/crypto-password.test.ts
git commit -m "feat: password-mode encryption (PBKDF2 + AES-GCM)"
```

---

### Task 4: Passkey-Mode Encryption (ECIES Crypto Layer)

This task implements just the ECDH + HKDF + AES-GCM layer, without WebAuthn. The WebAuthn PRF integration comes in Task 5.

**Files:**
- Create: `src/crypto-passkey.ts`
- Create: `tests/crypto-passkey.test.ts`

**Step 1: Write the failing tests**

```typescript
// tests/crypto-passkey.test.ts
import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  deriveKeyPairFromSecret,
  exportPublicKey,
  importPublicKey,
  encryptForRecipient,
  decryptAsRecipient,
} from '../src/crypto-passkey.ts';

describe('ECIES passkey crypto', () => {
  it('derives a consistent key pair from the same secret', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const kp1 = await deriveKeyPairFromSecret(secret);
    const kp2 = await deriveKeyPairFromSecret(secret);
    const pub1 = await exportPublicKey(kp1.publicKey);
    const pub2 = await exportPublicKey(kp2.publicKey);
    assert.deepStrictEqual(pub1, pub2);
  });

  it('different secrets produce different key pairs', async () => {
    const kp1 = await deriveKeyPairFromSecret(new Uint8Array(32)); // all zeros
    const kp2 = await deriveKeyPairFromSecret(new Uint8Array(32).fill(1));
    const pub1 = await exportPublicKey(kp1.publicKey);
    const pub2 = await exportPublicKey(kp2.publicKey);
    assert.notDeepStrictEqual(pub1, pub2);
  });

  it('encrypts and decrypts a message', async () => {
    const recipientSecret = crypto.getRandomValues(new Uint8Array(32));
    const recipientKp = await deriveKeyPairFromSecret(recipientSecret);
    const recipientPubRaw = await exportPublicKey(recipientKp.publicKey);
    const recipientPub = await importPublicKey(recipientPubRaw);

    const message = 'Secret message for recipient';
    const fragment = await encryptForRecipient(message, recipientPub);
    const decrypted = await decryptAsRecipient(fragment, recipientSecret);
    assert.equal(decrypted, message);
  });

  it('round-trips unicode', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const kp = await deriveKeyPairFromSecret(secret);
    const pub = await importPublicKey(await exportPublicKey(kp.publicKey));

    const message = 'Кролик 🐰 тоннель';
    const fragment = await encryptForRecipient(message, pub);
    const decrypted = await decryptAsRecipient(fragment, secret);
    assert.equal(decrypted, message);
  });

  it('fails to decrypt with wrong secret', async () => {
    const secret1 = crypto.getRandomValues(new Uint8Array(32));
    const secret2 = crypto.getRandomValues(new Uint8Array(32));
    const kp1 = await deriveKeyPairFromSecret(secret1);
    const pub1 = await importPublicKey(await exportPublicKey(kp1.publicKey));

    const fragment = await encryptForRecipient('hello', pub1);
    await assert.rejects(() => decryptAsRecipient(fragment, secret2));
  });

  it('public key raw export is 65 bytes (uncompressed P-256)', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const kp = await deriveKeyPairFromSecret(secret);
    const raw = await exportPublicKey(kp.publicKey);
    assert.equal(raw.length, 65);
    assert.equal(raw[0], 0x04); // uncompressed point prefix
  });
});
```

**Step 2: Run tests to verify they fail**

Run: `npm test`
Expected: FAIL — module not found

**Step 3: Implement crypto-passkey.ts**

```typescript
// src/crypto-passkey.ts
import { encodePayload, decodePayload } from './encoding.ts';

const ECDH_PARAMS = { name: 'ECDH', namedCurve: 'P-256' } as const;

// Derive a deterministic ECDH key pair from a 32-byte secret (e.g., from PRF).
// Uses HKDF to derive key material, then imports as ECDH private key via JWK.
export async function deriveKeyPairFromSecret(
  secret: Uint8Array
): Promise<CryptoKeyPair> {
  const hkdfKey = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
  const derived = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('bunny-hole-ecdh-private') },
      hkdfKey,
      256
    )
  );

  // Import as JWK — P-256 private key. The `d` parameter is the private scalar.
  // For P-256, the order n is close to 2^256, so almost any 32-byte value is valid.
  const d = arrayToBase64url(derived);
  // We need to compute the public point. Import as private key first,
  // then export to get the full JWK with x,y coordinates.
  // Trick: generate a throwaway key pair, then import our private scalar with its public coords.
  // Simpler approach: import raw private key via pkcs8... but Web Crypto doesn't support raw ECDH private import.
  // Best approach: use JWK with dummy x,y, then re-derive. Actually, the cleanest way:

  // Generate a key pair, export it, replace d, re-import.
  // This doesn't work — x,y must match d.

  // Correct approach: use the private key to perform a point multiplication with the generator.
  // Web Crypto doesn't expose this directly. Instead, we use a different strategy:
  // Import as a raw key for HKDF, derive an AES key for ECDH shared secret computation.

  // Actually the simplest correct approach: import the derived bytes as a PKCS8 key.
  // PKCS8 for P-256 ECDH has a fixed prefix.
  const pkcs8 = buildP256Pkcs8(derived);
  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, ECDH_PARAMS, true, ['deriveKey', 'deriveBits']);

  // Export as JWK to get x,y, then import public key
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
    ECDH_PARAMS,
    true,
    []
  );

  return { privateKey, publicKey };
}

// Build a PKCS8 DER encoding for a P-256 ECDH private key.
// Structure: SEQUENCE { version, AlgorithmIdentifier { ecPublicKey, P-256 }, OCTET STRING { ECPrivateKey } }
function buildP256Pkcs8(privateKeyBytes: Uint8Array): Uint8Array {
  // Fixed DER prefix for P-256 private key in PKCS8 format (no public key included)
  const prefix = new Uint8Array([
    0x30, 0x41, // SEQUENCE (65 bytes)
    0x02, 0x01, 0x00, // INTEGER version = 0
    0x30, 0x13, // SEQUENCE (19 bytes) — AlgorithmIdentifier
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID ecPublicKey
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID P-256
    0x04, 0x27, // OCTET STRING (39 bytes)
    0x30, 0x25, // SEQUENCE (37 bytes) — ECPrivateKey
    0x02, 0x01, 0x01, // INTEGER version = 1
    0x04, 0x20, // OCTET STRING (32 bytes) — private key
  ]);
  const result = new Uint8Array(prefix.length + 32);
  result.set(prefix);
  result.set(privateKeyBytes, prefix.length);
  return result;
}

function arrayToBase64url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function exportPublicKey(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}

export async function importPublicKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw, ECDH_PARAMS, true, []);
}

async function ecdhDeriveAesKey(privateKey: CryptoKey, publicKey: CryptoKey): Promise<CryptoKey> {
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: publicKey },
    privateKey,
    256
  );
  const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('bunny-hole-msg') },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptForRecipient(message: string, recipientPublicKey: CryptoKey): Promise<string> {
  const ephemeral = await crypto.subtle.generateKey(ECDH_PARAMS, true, ['deriveKey', 'deriveBits']);
  const aesKey = await ecdhDeriveAesKey(ephemeral.privateKey, recipientPublicKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(message))
  );
  const ephPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey));
  return encodePayload(0x02, ephPubRaw, iv, ciphertext);
}

export async function decryptAsRecipient(fragment: string, recipientSecret: Uint8Array): Promise<string> {
  const { mode, parts } = decodePayload(fragment);
  if (mode !== 0x02) throw new Error('Not a passkey-mode payload');
  const [ephPubRaw, iv, ciphertext] = parts;

  const recipientKp = await deriveKeyPairFromSecret(recipientSecret);
  const ephPub = await importPublicKey(ephPubRaw);
  const aesKey = await ecdhDeriveAesKey(recipientKp.privateKey, ephPub);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext);
  return new TextDecoder().decode(plaintext);
}
```

**Step 4: Run tests to verify they pass**

Run: `npm test`
Expected: All tests PASS

**Step 5: Commit**

```bash
git add src/crypto-passkey.ts tests/crypto-passkey.test.ts
git commit -m "feat: ECIES passkey-mode encryption (ECDH P-256 + HKDF + AES-GCM)"
```

---

### Task 5: WebAuthn / PRF Integration

This cannot be unit-tested in Node.js (no WebAuthn API). We implement it and verify manually in the browser.

**Files:**
- Create: `src/webauthn.ts`

**Step 1: Implement webauthn.ts**

```typescript
// src/webauthn.ts

const RP_ID_FALLBACK = 'localhost';

function getRpId(): string {
  if (typeof location !== 'undefined' && location.hostname !== 'localhost') {
    return location.hostname;
  }
  return RP_ID_FALLBACK;
}

// Fixed salt used for PRF evaluation — deterministic key derivation.
const PRF_SALT = new TextEncoder().encode('bunny-hole-prf-salt-v1');

export interface PasskeyRegistration {
  credentialId: string; // base64url
  prfSupported: boolean;
}

export async function registerPasskey(): Promise<PasskeyRegistration> {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(16));

  const credential = await navigator.credentials.create({
    publicKey: {
      rp: { name: 'Bunny Hole', id: getRpId() },
      user: {
        id: userId,
        name: 'bunny-hole-user',
        displayName: 'Bunny Hole User',
      },
      challenge,
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },   // ES256
        { type: 'public-key', alg: -257 },  // RS256
      ],
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
      extensions: { prf: {} } as any,
    },
  }) as PublicKeyCredential;

  const extResults = credential.getClientExtensionResults() as any;
  const prfSupported = !!extResults.prf?.enabled;

  const rawId = new Uint8Array(credential.rawId);
  let credentialId = '';
  for (let i = 0; i < rawId.length; i++) credentialId += String.fromCharCode(rawId[i]);
  credentialId = btoa(credentialId).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  return { credentialId, prfSupported };
}

export async function getPrfSecret(credentialId: string): Promise<Uint8Array> {
  // Decode credential ID from base64url
  const padded = credentialId.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded);
  const rawId = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) rawId[i] = binary.charCodeAt(i);

  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: getRpId(),
      allowCredentials: [{ type: 'public-key', id: rawId.buffer }],
      userVerification: 'preferred',
      extensions: {
        prf: { eval: { first: PRF_SALT } },
      } as any,
    },
  }) as PublicKeyCredential;

  const extResults = assertion.getClientExtensionResults() as any;
  const prfResult = extResults.prf?.results?.first;
  if (!prfResult) {
    throw new Error('PRF extension not available or not supported by this authenticator');
  }
  return new Uint8Array(prfResult);
}
```

**Step 2: Verify TypeScript compiles**

Run: `npm run check`
Expected: No errors (there may be warnings about `as any` for extension types — that's expected since WebAuthn extension types are not fully typed in lib.dom)

**Step 3: Commit**

```bash
git add src/webauthn.ts
git commit -m "feat: WebAuthn PRF integration for passkey key derivation"
```

---

### Task 6: Contacts Management

**Files:**
- Create: `src/contacts.ts`
- Create: `tests/contacts.test.ts`

**Step 1: Write the failing tests**

```typescript
// tests/contacts.test.ts
import { describe, it, beforeEach } from 'node:test';
import { strict as assert } from 'node:assert';

// Mock localStorage for Node.js
const store: Record<string, string> = {};
(globalThis as any).localStorage = {
  getItem: (k: string) => store[k] ?? null,
  setItem: (k: string, v: string) => { store[k] = v; },
  removeItem: (k: string) => { delete store[k]; },
};

import { getContacts, addContact, removeContact, Contact } from '../src/contacts.ts';

describe('contacts', () => {
  beforeEach(() => {
    delete store['bh_contacts'];
  });

  it('returns empty array when no contacts', () => {
    assert.deepStrictEqual(getContacts(), []);
  });

  it('adds a contact', () => {
    addContact('Alice', 'abc123pubkey');
    const contacts = getContacts();
    assert.equal(contacts.length, 1);
    assert.equal(contacts[0].label, 'Alice');
    assert.equal(contacts[0].pubkey, 'abc123pubkey');
    assert.ok(contacts[0].added_at);
  });

  it('adds multiple contacts', () => {
    addContact('Alice', 'key1');
    addContact('Bob', 'key2');
    assert.equal(getContacts().length, 2);
  });

  it('removes a contact by pubkey', () => {
    addContact('Alice', 'key1');
    addContact('Bob', 'key2');
    removeContact('key1');
    const contacts = getContacts();
    assert.equal(contacts.length, 1);
    assert.equal(contacts[0].label, 'Bob');
  });

  it('rejects duplicate pubkey', () => {
    addContact('Alice', 'key1');
    assert.throws(() => addContact('Bob', 'key1'), /already exists/);
  });
});
```

**Step 2: Run tests to verify they fail**

Run: `npm test`
Expected: FAIL — module not found

**Step 3: Implement contacts.ts**

```typescript
// src/contacts.ts

const STORAGE_KEY = 'bh_contacts';

export interface Contact {
  label: string;
  pubkey: string;
  added_at: string; // ISO date
}

export function getContacts(): Contact[] {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return [];
  return JSON.parse(raw);
}

function saveContacts(contacts: Contact[]): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(contacts));
}

export function addContact(label: string, pubkey: string): void {
  const contacts = getContacts();
  if (contacts.some(c => c.pubkey === pubkey)) {
    throw new Error('Contact with this public key already exists');
  }
  contacts.push({ label, pubkey, added_at: new Date().toISOString() });
  saveContacts(contacts);
}

export function removeContact(pubkey: string): void {
  const contacts = getContacts().filter(c => c.pubkey !== pubkey);
  saveContacts(contacts);
}
```

**Step 4: Run tests to verify they pass**

Run: `npm test`
Expected: All tests PASS

**Step 5: Commit**

```bash
git add src/contacts.ts tests/contacts.test.ts
git commit -m "feat: contacts management with localStorage"
```

---

### Task 7: QR Code Generator

Minimal QR code generator for alphanumeric data, rendered to canvas. Since a correct QR encoder is 300+ lines of non-trivial code (Reed-Solomon, masking, format info), we use a pragmatic shortcut: generate a simple "copy link" flow as primary, and add QR as a stretch goal using a tiny vendored library.

**Files:**
- Create: `src/qr.ts`

**Step 1: Implement a minimal QR renderer**

For < 15 KB budget, implement QR generation using the compact algorithm (~200 lines). If this proves too large or complex during implementation, fall back to showing just the copy-link button (QR becomes optional).

```typescript
// src/qr.ts

// Minimal QR Code generator for byte mode.
// Supports versions 1-10 (up to ~271 chars per version 10, ECC level L).
// This is enough for the public key share URLs (~150 chars).

// For full encrypted message URLs (potentially thousands of chars),
// QR is not practical — the URL is too long. QR is only for key sharing links.

export function renderQR(canvas: HTMLCanvasElement, text: string, cellSize = 4): void {
  // Use the minimal QR encoder
  const modules = encode(text);
  const size = modules.length;
  const padding = cellSize * 2;
  canvas.width = size * cellSize + padding * 2;
  canvas.height = size * cellSize + padding * 2;
  const ctx = canvas.getContext('2d')!;
  ctx.fillStyle = '#fff';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#000';
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      if (modules[y][x]) {
        ctx.fillRect(padding + x * cellSize, padding + y * cellSize, cellSize, cellSize);
      }
    }
  }
}

// QR encoding implementation omitted for plan brevity.
// During implementation, either:
// (a) Write a minimal encoder (~200 lines covering versions 1-6, ECC L, byte mode)
// (b) Vendor a tiny library like "qr-creator" (3 KB minified)
// (c) Skip QR and just use copy-to-clipboard
// Decision: make at implementation time based on bundle budget.

function encode(text: string): boolean[][] {
  // Placeholder — will be implemented or vendored
  throw new Error('Not implemented');
}
```

**Step 2: Verify TypeScript compiles**

Run: `npm run check`
Expected: No errors

**Step 3: Commit**

```bash
git add src/qr.ts
git commit -m "feat: QR code renderer scaffold"
```

---

### Task 8: UI — Router and Page Structure

**Files:**
- Create: `src/ui.ts`
- Modify: `src/main.ts`

**Step 1: Implement UI router**

```typescript
// src/ui.ts
import { decodePayload } from './encoding.ts';

export type View =
  | { kind: 'compose' }
  | { kind: 'decrypt-password'; fragment: string }
  | { kind: 'decrypt-passkey'; fragment: string }
  | { kind: 'add-contact'; pubkey: string; label: string };

export function resolveView(): View {
  const hash = location.hash.slice(1);
  if (!hash) return { kind: 'compose' };

  try {
    const { mode, parts } = decodePayload(hash);
    switch (mode) {
      case 0x01:
        return { kind: 'decrypt-password', fragment: hash };
      case 0x02:
        return { kind: 'decrypt-passkey', fragment: hash };
      case 0x03: {
        const pubkeyBytes = parts[0];
        const label = new TextDecoder().decode(parts[1]);
        // Convert pubkey to base64url for display/storage
        let binary = '';
        for (let i = 0; i < pubkeyBytes.length; i++) binary += String.fromCharCode(pubkeyBytes[i]);
        const pubkey = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        return { kind: 'add-contact', pubkey, label };
      }
      default:
        return { kind: 'compose' };
    }
  } catch {
    return { kind: 'compose' };
  }
}
```

**Step 2: Implement main.ts with view rendering**

```typescript
// src/main.ts
import { resolveView, View } from './ui.ts';
import { encryptPassword, decryptPassword } from './crypto-password.ts';
import { encryptForRecipient, decryptAsRecipient, deriveKeyPairFromSecret, exportPublicKey, importPublicKey } from './crypto-passkey.ts';
import { registerPasskey, getPrfSecret } from './webauthn.ts';
import { getContacts, addContact, removeContact } from './contacts.ts';
import { toBase64url, fromBase64url, encodePayload } from './encoding.ts';

const $ = (sel: string) => document.querySelector(sel) as HTMLElement;
const app = () => document.getElementById('app')!;

const MAX_MESSAGE_BYTES = 24_000;
const CREDENTIAL_KEY = 'bh_credential_id';

function getCredentialId(): string | null {
  return localStorage.getItem(CREDENTIAL_KEY);
}

function render(): void {
  const view = resolveView();
  switch (view.kind) {
    case 'compose': return renderCompose();
    case 'decrypt-password': return renderDecryptPassword(view.fragment);
    case 'decrypt-passkey': return renderDecryptPasskey(view.fragment);
    case 'add-contact': return renderAddContact(view.pubkey, view.label);
  }
}

function renderCompose(): void {
  const hasPasskey = !!getCredentialId();
  const contacts = getContacts();

  app().innerHTML = `
    <textarea id="msg" placeholder="Your message" maxlength="${MAX_MESSAGE_BYTES}"></textarea>
    <div class="row"><small id="charcount">0 / ${MAX_MESSAGE_BYTES}</small></div>
    <hr>
    <b>Send via</b>
    <div class="row">
      <label><input type="radio" name="mode" value="password" checked> Password</label>
      <label><input type="radio" name="mode" value="passkey" ${hasPasskey ? '' : 'disabled'}> Passkey${hasPasskey ? '' : ' (register first)'}</label>
    </div>
    <div id="mode-fields"></div>
    <button id="encrypt-btn">Encrypt</button>
    <div id="result" class="hidden"></div>
    <hr>
    <b>My Keys</b>
    <div id="keys-section"></div>
    <hr>
    <b>Contacts</b>
    <div id="contacts-section"></div>
    <div class="row">
      <input type="text" id="new-label" placeholder="Label">
      <input type="text" id="new-pubkey" placeholder="Public key">
      <button id="add-contact-btn">Add</button>
    </div>
  `;

  // Event listeners
  const msgEl = $<HTMLTextAreaElement>('#msg' as any) as unknown as HTMLTextAreaElement;
  msgEl.addEventListener('input', () => {
    const len = new TextEncoder().encode(msgEl.value).length;
    ($('#charcount') as HTMLElement).textContent = `${len} / ${MAX_MESSAGE_BYTES}`;
  });

  document.querySelectorAll('input[name="mode"]').forEach(el =>
    el.addEventListener('change', () => updateModeFields())
  );
  updateModeFields();

  $('#encrypt-btn').addEventListener('click', handleEncrypt);
  renderKeysSection(hasPasskey);
  renderContactsList(contacts);
  $('#add-contact-btn').addEventListener('click', handleAddContact);
}

function updateModeFields(): void {
  const mode = (document.querySelector('input[name="mode"]:checked') as HTMLInputElement)?.value;
  const container = $('#mode-fields');
  if (mode === 'password') {
    container.innerHTML = '<input type="password" id="password" placeholder="Encryption password">';
  } else {
    const contacts = getContacts();
    if (contacts.length === 0) {
      container.innerHTML = '<p class="err">No contacts. Add a recipient\'s public key first.</p>';
    } else {
      container.innerHTML = `<select id="recipient">${contacts.map(c =>
        `<option value="${c.pubkey}">${c.label}</option>`
      ).join('')}</select>`;
    }
  }
}

async function handleEncrypt(): Promise<void> {
  const msg = (document.getElementById('msg') as HTMLTextAreaElement).value;
  if (!msg) return;

  const mode = (document.querySelector('input[name="mode"]:checked') as HTMLInputElement)?.value;
  const resultDiv = $('#result');

  try {
    let fragment: string;
    let isPasswordMode = false;
    if (mode === 'password') {
      const password = (document.getElementById('password') as HTMLInputElement).value;
      if (!password) { resultDiv.innerHTML = '<p class="err">Enter a password.</p>'; resultDiv.classList.remove('hidden'); return; }
      fragment = await encryptPassword(msg, password);
      isPasswordMode = true;
    } else {
      const pubkeyB64 = (document.getElementById('recipient') as HTMLSelectElement).value;
      const pubkeyRaw = fromBase64url(pubkeyB64);
      const pubkey = await importPublicKey(pubkeyRaw);
      fragment = await encryptForRecipient(msg, pubkey);
    }

    const url = `${location.origin}${location.pathname}#${fragment}`;
    resultDiv.innerHTML = `
      <hr>
      <b>Encrypted link</b>
      <div class="row">
        <input type="text" id="result-url" value="${url}" readonly>
        <button id="copy-btn">Copy</button>
      </div>
      ${isPasswordMode ? '<p class="warn">Send this link and the password separately.</p>' : ''}
    `;
    resultDiv.classList.remove('hidden');
    $('#copy-btn').addEventListener('click', () => {
      navigator.clipboard.writeText(url);
      ($('#copy-btn') as HTMLButtonElement).textContent = 'Copied!';
    });
  } catch (e: any) {
    resultDiv.innerHTML = `<p class="err">${e.message}</p>`;
    resultDiv.classList.remove('hidden');
  }
}

function renderKeysSection(hasPasskey: boolean): void {
  const section = $('#keys-section');
  if (!hasPasskey) {
    section.innerHTML = '<button id="register-btn">Register passkey</button>';
    $('#register-btn').addEventListener('click', handleRegister);
  } else {
    section.innerHTML = `
      <p>Passkey registered.</p>
      <button id="show-pubkey-btn">Show my public key</button>
      <div id="pubkey-display" class="hidden"></div>
    `;
    $('#show-pubkey-btn').addEventListener('click', handleShowPubkey);
  }
}

async function handleRegister(): Promise<void> {
  try {
    const reg = await registerPasskey();
    if (!reg.prfSupported) {
      alert('Your browser/device does not support the PRF extension. Passkey mode will not work. Use password mode instead.');
      return;
    }
    localStorage.setItem(CREDENTIAL_KEY, reg.credentialId);
    render();
  } catch (e: any) {
    alert(`Registration failed: ${e.message}`);
  }
}

async function handleShowPubkey(): Promise<void> {
  try {
    const credId = getCredentialId()!;
    const secret = await getPrfSecret(credId);
    const kp = await deriveKeyPairFromSecret(secret);
    const pubRaw = await exportPublicKey(kp.publicKey);
    const pubB64 = toBase64url(pubRaw);

    // Create share URL (mode 0x03)
    const label = prompt('Your name/label for this key:') || 'Anonymous';
    const shareFragment = encodePayload(0x03, pubRaw, new TextEncoder().encode(label));
    const shareUrl = `${location.origin}${location.pathname}#${shareFragment}`;

    const display = $('#pubkey-display');
    display.innerHTML = `
      <code>${pubB64}</code>
      <button id="copy-pubkey">Copy key</button>
      <hr>
      <b>Share link</b>
      <div class="row">
        <input type="text" value="${shareUrl}" readonly style="font-size:.8em">
        <button id="copy-share">Copy</button>
      </div>
    `;
    display.classList.remove('hidden');
    $('#copy-pubkey').addEventListener('click', () => navigator.clipboard.writeText(pubB64));
    $('#copy-share').addEventListener('click', () => navigator.clipboard.writeText(shareUrl));
  } catch (e: any) {
    alert(`Failed to get public key: ${e.message}`);
  }
}

function renderContactsList(contacts: ReturnType<typeof getContacts>): void {
  const section = $('#contacts-section');
  if (contacts.length === 0) {
    section.innerHTML = '<p>No contacts yet.</p>';
    return;
  }
  section.innerHTML = contacts.map(c => `
    <div class="contact">
      <span>${c.label}</span>
      <code>${c.pubkey.slice(0, 8)}...</code>
      <button class="del-contact" data-key="${c.pubkey}">x</button>
    </div>
  `).join('');
  section.querySelectorAll('.del-contact').forEach(btn =>
    btn.addEventListener('click', () => {
      removeContact((btn as HTMLElement).dataset.key!);
      render();
    })
  );
}

function handleAddContact(): void {
  const label = (document.getElementById('new-label') as HTMLInputElement).value.trim();
  const pubkey = (document.getElementById('new-pubkey') as HTMLInputElement).value.trim();
  if (!label || !pubkey) return;
  try {
    addContact(label, pubkey);
    render();
  } catch (e: any) {
    alert(e.message);
  }
}

function renderDecryptPassword(fragment: string): void {
  app().innerHTML = `
    <p>You received an encrypted message.</p>
    <p>Mode: <b>Password</b></p>
    <input type="password" id="dec-password" placeholder="Enter password">
    <button id="dec-btn">Decrypt</button>
    <div id="dec-result" class="hidden"></div>
    <hr>
    <button id="new-msg-btn">New message</button>
  `;

  $('#dec-btn').addEventListener('click', async () => {
    const password = (document.getElementById('dec-password') as HTMLInputElement).value;
    try {
      const message = await decryptPassword(fragment, password);
      const resultDiv = $('#dec-result');
      resultDiv.innerHTML = `<hr><b>Decrypted message</b><pre class="msg">${escapeHtml(message)}</pre>`;
      resultDiv.classList.remove('hidden');
    } catch {
      const resultDiv = $('#dec-result');
      resultDiv.innerHTML = '<p class="err">Decryption failed. Wrong password or corrupted link.</p>';
      resultDiv.classList.remove('hidden');
    }
  });

  $('#new-msg-btn').addEventListener('click', () => { location.hash = ''; render(); });
}

function renderDecryptPasskey(fragment: string): void {
  app().innerHTML = `
    <p>You received an encrypted message.</p>
    <p>Mode: <b>Passkey</b></p>
    <button id="dec-btn">Decrypt with passkey</button>
    <div id="dec-result" class="hidden"></div>
    <hr>
    <button id="new-msg-btn">New message</button>
  `;

  $('#dec-btn').addEventListener('click', async () => {
    const credId = getCredentialId();
    if (!credId) {
      alert('No passkey registered on this device. Register a passkey first.');
      return;
    }
    try {
      const secret = await getPrfSecret(credId);
      const message = await decryptAsRecipient(fragment, secret);
      const resultDiv = $('#dec-result');
      resultDiv.innerHTML = `<hr><b>Decrypted message</b><pre class="msg">${escapeHtml(message)}</pre>`;
      resultDiv.classList.remove('hidden');
    } catch {
      const resultDiv = $('#dec-result');
      resultDiv.innerHTML = '<p class="err">Decryption failed. Wrong passkey or corrupted link.</p>';
      resultDiv.classList.remove('hidden');
    }
  });

  $('#new-msg-btn').addEventListener('click', () => { location.hash = ''; render(); });
}

function renderAddContact(pubkey: string, label: string): void {
  app().innerHTML = `
    <p>Someone shared their public key with you.</p>
    <p><b>Label:</b> ${escapeHtml(label)}</p>
    <p><b>Key:</b> <code>${pubkey.slice(0, 16)}...${pubkey.slice(-8)}</code></p>
    <button id="add-btn">Add to contacts</button>
    <button id="back-btn">Back</button>
    <div id="add-result"></div>
  `;

  $('#add-btn').addEventListener('click', () => {
    try {
      addContact(label, pubkey);
      $('#add-result').innerHTML = '<p>Contact added!</p>';
    } catch (e: any) {
      $('#add-result').innerHTML = `<p class="err">${e.message}</p>`;
    }
  });

  $('#back-btn').addEventListener('click', () => { location.hash = ''; render(); });
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Boot
window.addEventListener('hashchange', render);
render();
```

**Step 2: Build and verify in browser**

Run: `npm run build && npm run dev`
Open in browser, verify compose view renders.

**Step 3: Commit**

```bash
git add src/ui.ts src/main.ts
git commit -m "feat: UI with compose, decrypt, and contact views"
```

---

### Task 9: Build Single-File Output

**Files:**
- Modify: `build.sh`

**Step 1: Update build script to inline JS into HTML**

```bash
#!/bin/bash
set -e

# Build JS bundle
npx esbuild src/main.ts --bundle --minify --outfile=dist/app.js --target=es2022

# Create single-file version with inlined JS
JS=$(cat dist/app.js)
sed "s|<script src=\"dist/app.js\"></script>|<script>${JS}</script>|" index.html > dist/index.html

echo "Build complete:"
echo "  dist/app.js    $(wc -c < dist/app.js | tr -d ' ') bytes"
echo "  dist/index.html $(wc -c < dist/index.html | tr -d ' ') bytes"
```

**Step 2: Build and verify**

Run: `npm run build`
Expected: `dist/index.html` created, size < 15 KB. Open `dist/index.html` in browser — should work standalone.

**Step 3: Commit**

```bash
git add build.sh
git commit -m "feat: single-file build with inlined JS"
```

---

### Task 10: End-to-End Manual Testing

No automated tests — this is browser-only WebAuthn + UI.

**Checklist:**

1. Open `dist/index.html` via local server (`npx serve dist`)
2. **Password mode:**
   - Type message → select Password → enter password → click Encrypt
   - Copy URL → open in new tab → enter password → Decrypt
   - Verify message matches
   - Try wrong password → expect "Decryption failed"
3. **Passkey registration:**
   - Click "Register passkey" → complete WebAuthn prompt
   - Verify "Passkey registered" shown
   - Click "Show my public key" → verify key shown
   - Copy share link
4. **Contact sharing:**
   - Open share link in another browser profile
   - Verify "Add to contacts" screen
   - Click Add → verify contact appears in list
5. **Passkey encryption:**
   - Select Passkey mode → choose contact → Encrypt
   - Open URL in recipient's browser profile → Decrypt with passkey
   - Verify message matches
6. **Edge cases:**
   - Very long message (near 24 KB) → verify char counter
   - Empty message → verify handled
   - Corrupted URL hash → verify graceful error

**Commit after fixing any issues found.**

---

Plan complete and saved to `docs/plans/2026-03-16-bunny-hole-implementation.md`. Two execution options:

**1. Subagent-Driven (this session)** — I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** — Open new session with executing-plans, batch execution with checkpoints

Which approach?