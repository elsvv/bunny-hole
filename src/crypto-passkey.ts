// src/crypto-passkey.ts
import { encodePayload, decodePayload } from './encoding.ts';
import { ECDH_PARAMS, ecdhDeriveAesKey } from './crypto-shared.ts';

export async function deriveKeyPairFromSecret(secret: Uint8Array): Promise<CryptoKeyPair> {
  const hkdfKey = await crypto.subtle.importKey('raw', secret as BufferSource, 'HKDF', false, ['deriveBits']);
  const derived = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('bunny-hole-ecdh-private') },
      hkdfKey,
      256
    )
  );

  // Try PKCS8 import — Chrome/Firefox accept minimal format,
  // Safari requires the curve OID in ECPrivateKey [0] parameters.
  // Try with parameters first (Safari-compatible), fall back to minimal.
  let privateKey: CryptoKey;
  try {
    const pkcs8 = buildP256Pkcs8WithParams(derived);
    privateKey = await crypto.subtle.importKey('pkcs8', pkcs8 as BufferSource, ECDH_PARAMS, true, ['deriveKey', 'deriveBits']);
  } catch {
    const pkcs8 = buildP256Pkcs8Minimal(derived);
    privateKey = await crypto.subtle.importKey('pkcs8', pkcs8 as BufferSource, ECDH_PARAMS, true, ['deriveKey', 'deriveBits']);
  }

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

// PKCS8 with ECPrivateKey [0] parameters — required by Safari
function buildP256Pkcs8WithParams(privateKeyBytes: Uint8Array): Uint8Array {
  // SEQUENCE { version 0, AlgorithmIdentifier { ecPublicKey, P-256 },
  //   OCTET STRING { SEQUENCE { version 1, OCTET STRING(32 bytes),
  //     [0] { OID P-256 } } } }
  const prefix = new Uint8Array([
    0x30, 0x4d,                                           // SEQUENCE (77 bytes)
    0x02, 0x01, 0x00,                                     // INTEGER 0 (version)
    0x30, 0x13,                                           // SEQUENCE (19 bytes)
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID ecPublicKey
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID P-256
    0x04, 0x33,                                           // OCTET STRING (51 bytes)
    0x30, 0x31,                                           // SEQUENCE (49 bytes)
    0x02, 0x01, 0x01,                                     // INTEGER 1 (version)
    0x04, 0x20,                                           // OCTET STRING (32 bytes)
  ]);
  const suffix = new Uint8Array([
    0xa0, 0x0a,                                           // [0] (10 bytes)
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID P-256
  ]);
  const result = new Uint8Array(prefix.length + 32 + suffix.length);
  result.set(prefix);
  result.set(privateKeyBytes, prefix.length);
  result.set(suffix, prefix.length + 32);
  return result;
}

// Minimal PKCS8 without optional fields — works in Chrome/Firefox
function buildP256Pkcs8Minimal(privateKeyBytes: Uint8Array): Uint8Array {
  const prefix = new Uint8Array([
    0x30, 0x41,
    0x02, 0x01, 0x00,
    0x30, 0x13,
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    0x04, 0x27,
    0x30, 0x25,
    0x02, 0x01, 0x01,
    0x04, 0x20,
  ]);
  const result = new Uint8Array(prefix.length + 32);
  result.set(prefix);
  result.set(privateKeyBytes, prefix.length);
  return result;
}

export async function exportPublicKey(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}

export async function importPublicKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw as BufferSource, ECDH_PARAMS, true, []);
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
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, aesKey, ciphertext as BufferSource);
  return new TextDecoder().decode(plaintext);
}
