// src/crypto-passkey.ts
import { encodePayload, decodePayload } from './encoding.ts';

const ECDH_PARAMS = { name: 'ECDH', namedCurve: 'P-256' } as const;

export async function deriveKeyPairFromSecret(secret: Uint8Array): Promise<CryptoKeyPair> {
  const hkdfKey = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
  const derived = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('bunny-hole-ecdh-private') },
      hkdfKey,
      256
    )
  );

  const pkcs8 = buildP256Pkcs8(derived);
  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, ECDH_PARAMS, true, ['deriveKey', 'deriveBits']);

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

function buildP256Pkcs8(privateKeyBytes: Uint8Array): Uint8Array {
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
