// src/crypto-passkey.ts
import { encodePayload, decodePayload } from './encoding.ts';
import { toBase64url } from './encoding.ts';
import { ECDH_PARAMS, ecdhDeriveAesKey } from './crypto-shared.ts';
import { p256 } from '@noble/curves/nist.js';

export async function deriveKeyPairFromSecret(secret: Uint8Array): Promise<CryptoKeyPair> {
  const hkdfKey = await crypto.subtle.importKey('raw', secret as BufferSource, 'HKDF', false, ['deriveBits']);
  const derived = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('bunny-hole-ecdh-private') },
      hkdfKey,
      256
    )
  );

  // Compute public point from private scalar using @noble/curves (works everywhere)
  const publicKeyUncompressed = p256.getPublicKey(derived, false); // 65 bytes: 04 || X || Y
  const x = publicKeyUncompressed.slice(1, 33);
  const y = publicKeyUncompressed.slice(33, 65);

  // Import via JWK — works in ALL browsers including Safari
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    {
      kty: 'EC',
      crv: 'P-256',
      x: toBase64url(x),
      y: toBase64url(y),
      d: toBase64url(derived),
      ext: true,
    },
    ECDH_PARAMS,
    true,
    ['deriveBits']
  );

  const publicKey = await crypto.subtle.importKey(
    'jwk',
    { kty: 'EC', crv: 'P-256', x: toBase64url(x), y: toBase64url(y) },
    ECDH_PARAMS,
    true,
    []
  );

  return { privateKey, publicKey };
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
