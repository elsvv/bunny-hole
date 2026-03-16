// src/crypto-chunked.ts
import { encodePayload, decodePayload } from './encoding.ts';
import {
  deriveKeyPairFromSecret,
  importPublicKey,
} from './crypto-passkey.ts';

const ITERATIONS = 310_000;
export const CHUNK_DATA_SIZE = 22_000;

const ECDH_PARAMS = { name: 'ECDH', namedCurve: 'P-256' } as const;

export interface ChunkMeta {
  groupId: Uint8Array;   // 16 bytes
  chunkIndex: number;
  totalChunks: number;
  mimeType: string;
  data: Uint8Array;
}

// ---------------------------------------------------------------------------
// Chunk plaintext encoding/decoding
// ---------------------------------------------------------------------------

export function encodeChunkPlaintext(meta: ChunkMeta): Uint8Array {
  const mimeBytes = new TextEncoder().encode(meta.mimeType);
  if (mimeBytes.length > 255) throw new Error('MIME type too long (max 255 bytes)');

  // group_id(16) + chunk_index(2) + total_chunks(2) + mime_len(1) + mime(N) + data
  const totalLen = 16 + 2 + 2 + 1 + mimeBytes.length + meta.data.length;
  const buf = new Uint8Array(totalLen);
  const view = new DataView(buf.buffer);

  let offset = 0;
  buf.set(meta.groupId, offset); offset += 16;
  view.setUint16(offset, meta.chunkIndex); offset += 2;     // big-endian by default
  view.setUint16(offset, meta.totalChunks); offset += 2;
  buf[offset] = mimeBytes.length; offset += 1;
  buf.set(mimeBytes, offset); offset += mimeBytes.length;
  buf.set(meta.data, offset);

  return buf;
}

export function decodeChunkPlaintext(plaintext: Uint8Array): ChunkMeta {
  const view = new DataView(plaintext.buffer, plaintext.byteOffset, plaintext.byteLength);

  let offset = 0;
  const groupId = plaintext.slice(offset, offset + 16); offset += 16;
  const chunkIndex = view.getUint16(offset); offset += 2;
  const totalChunks = view.getUint16(offset); offset += 2;
  const mimeLen = plaintext[offset]; offset += 1;
  const mimeType = new TextDecoder().decode(plaintext.slice(offset, offset + mimeLen)); offset += mimeLen;
  const data = plaintext.slice(offset);

  return { groupId, chunkIndex, totalChunks, mimeType, data };
}

// ---------------------------------------------------------------------------
// Splitting files into chunks
// ---------------------------------------------------------------------------

export function splitIntoChunks(fileData: Uint8Array, mimeType: string): ChunkMeta[] {
  const groupId = crypto.getRandomValues(new Uint8Array(16));
  const totalChunks = Math.max(1, Math.ceil(fileData.length / CHUNK_DATA_SIZE));
  const chunks: ChunkMeta[] = [];

  for (let i = 0; i < totalChunks; i++) {
    const start = i * CHUNK_DATA_SIZE;
    const end = Math.min(start + CHUNK_DATA_SIZE, fileData.length);
    chunks.push({
      groupId,
      chunkIndex: i,
      totalChunks,
      mimeType,
      data: fileData.slice(start, end),
    });
  }

  return chunks;
}

// ---------------------------------------------------------------------------
// Password-mode helpers (shared with crypto-password.ts logic)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Passkey-mode helpers (shared with crypto-passkey.ts logic)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Encrypt / Decrypt — password mode (0x04)
// ---------------------------------------------------------------------------

export async function encryptChunksPassword(
  fileData: Uint8Array,
  mimeType: string,
  password: string,
): Promise<string[]> {
  const chunks = splitIntoChunks(fileData, mimeType);
  const fragments: string[] = [];

  for (const chunk of chunks) {
    const plaintext = encodeChunkPlaintext(chunk);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt);
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext as BufferSource)
    );
    fragments.push(encodePayload(0x04, salt, iv, ciphertext));
  }

  return fragments;
}

export async function decryptChunkPassword(fragment: string, password: string): Promise<ChunkMeta> {
  const { mode, parts } = decodePayload(fragment);
  if (mode !== 0x04) throw new Error('Not a chunked-password payload');
  const [salt, iv, ciphertext] = parts;
  const key = await deriveKey(password, salt as BufferSource);
  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, ciphertext as BufferSource)
  );
  return decodeChunkPlaintext(plaintext);
}

// ---------------------------------------------------------------------------
// Encrypt / Decrypt — passkey mode (0x05)
// ---------------------------------------------------------------------------

export async function encryptChunksPasskey(
  fileData: Uint8Array,
  mimeType: string,
  recipientPublicKey: CryptoKey,
): Promise<string[]> {
  const chunks = splitIntoChunks(fileData, mimeType);
  const fragments: string[] = [];

  for (const chunk of chunks) {
    const plaintext = encodeChunkPlaintext(chunk);
    const ephemeral = await crypto.subtle.generateKey(ECDH_PARAMS, true, ['deriveKey', 'deriveBits']);
    const aesKey = await ecdhDeriveAesKey(ephemeral.privateKey, recipientPublicKey);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintext as BufferSource)
    );
    const ephPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey));
    fragments.push(encodePayload(0x05, ephPubRaw, iv, ciphertext));
  }

  return fragments;
}

export async function decryptChunkPasskey(fragment: string, recipientSecret: Uint8Array): Promise<ChunkMeta> {
  const { mode, parts } = decodePayload(fragment);
  if (mode !== 0x05) throw new Error('Not a chunked-passkey payload');
  const [ephPubRaw, iv, ciphertext] = parts;

  const recipientKp = await deriveKeyPairFromSecret(recipientSecret);
  const ephPub = await importPublicKey(ephPubRaw);
  const aesKey = await ecdhDeriveAesKey(recipientKp.privateKey, ephPub);
  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, aesKey, ciphertext as BufferSource)
  );
  return decodeChunkPlaintext(plaintext);
}
