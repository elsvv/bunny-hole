// src/chunk-store.ts

import { toBase64url } from './encoding.ts';

export interface StoredChunk {
  key: string;           // "{groupId}_{chunkIndex}"
  groupId: string;       // base64url of the 16-byte group_id
  chunkIndex: number;
  totalChunks: number;
  mimeType: string;
  data: Uint8Array;
  storedAt: string;      // ISO date
}

const DB_NAME = 'bunny-hole';
const STORE_NAME = 'chunks';
const DB_VERSION = 1;

let dbPromise: Promise<IDBDatabase> | null = null;

function getDB(): Promise<IDBDatabase> {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const store = db.createObjectStore(STORE_NAME, { keyPath: 'key' });
        store.createIndex('groupId', 'groupId', { unique: false });
        store.createIndex('storedAt', 'storedAt', { unique: false });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => {
      dbPromise = null;
      reject(request.error);
    };
  });
  return dbPromise;
}

export async function saveChunk(chunk: {
  groupId: Uint8Array;
  chunkIndex: number;
  totalChunks: number;
  mimeType: string;
  data: Uint8Array;
}): Promise<void> {
  const groupId = toBase64url(chunk.groupId);
  const key = `${groupId}_${chunk.chunkIndex}`;
  const record: StoredChunk = {
    key,
    groupId,
    chunkIndex: chunk.chunkIndex,
    totalChunks: chunk.totalChunks,
    mimeType: chunk.mimeType,
    data: chunk.data,
    storedAt: new Date().toISOString(),
  };
  const db = await getDB();
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put(record);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function getChunks(groupId: string): Promise<StoredChunk[]> {
  const db = await getDB();
  return new Promise<StoredChunk[]>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const index = tx.objectStore(STORE_NAME).index('groupId');
    const request = index.getAll(groupId);
    request.onsuccess = () => resolve(request.result as StoredChunk[]);
    request.onerror = () => reject(request.error);
  });
}

export async function getProgress(groupId: string): Promise<{ have: number; total: number; missing: number[] }> {
  const chunks = await getChunks(groupId);
  if (chunks.length === 0) {
    return { have: 0, total: 0, missing: [] };
  }
  const total = chunks[0].totalChunks;
  const haveSet = new Set(chunks.map(c => c.chunkIndex));
  const missing: number[] = [];
  for (let i = 0; i < total; i++) {
    if (!haveSet.has(i)) missing.push(i);
  }
  return { have: chunks.length, total, missing };
}

export async function isComplete(groupId: string): Promise<boolean> {
  const { have, total } = await getProgress(groupId);
  return total > 0 && have === total;
}

export async function assembleFile(groupId: string): Promise<{ blob: Blob; mimeType: string } | null> {
  const chunks = await getChunks(groupId);
  if (chunks.length === 0) return null;
  const total = chunks[0].totalChunks;
  if (chunks.length < total) return null;

  const expectedTotal = chunks[0].totalChunks;
  if (chunks.some(c => c.totalChunks !== expectedTotal)) {
    throw new Error('Chunk totalChunks mismatch — possible corruption');
  }

  chunks.sort((a, b) => a.chunkIndex - b.chunkIndex);

  let totalLen = 0;
  for (const c of chunks) totalLen += c.data.length;

  const assembled = new Uint8Array(totalLen);
  let offset = 0;
  for (const c of chunks) {
    assembled.set(c.data, offset);
    offset += c.data.length;
  }

  const mimeType = chunks[0].mimeType;
  return { blob: new Blob([assembled], { type: mimeType }), mimeType };
}

export async function clearGroup(groupId: string): Promise<void> {
  const db = await getDB();
  const chunks = await getChunks(groupId);
  if (chunks.length === 0) return;
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    for (const chunk of chunks) {
      store.delete(chunk.key);
    }
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function cleanOldChunks(): Promise<void> {
  const db = await getDB();
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const index = tx.objectStore(STORE_NAME).index('storedAt');
    const range = IDBKeyRange.upperBound(cutoff);
    const request = index.openCursor(range);
    request.onsuccess = () => {
      const cursor = request.result;
      if (cursor) {
        cursor.delete();
        cursor.continue();
      }
    };
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
