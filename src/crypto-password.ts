// src/crypto-password.ts
import { encodePayload, decodePayload } from './encoding.ts';

const ITERATIONS = 310_000;

async function deriveKey(password: string, salt: BufferSource): Promise<CryptoKey> {
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
  const key = await deriveKey(password, salt as BufferSource);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, ciphertext as BufferSource);
  return new TextDecoder().decode(plaintext);
}
