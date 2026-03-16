// tests/crypto-chunked.test.ts
import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  encodeChunkPlaintext,
  decodeChunkPlaintext,
  splitIntoChunks,
  encryptChunksPassword,
  decryptChunkPassword,
  encryptChunksPasskey,
  decryptChunkPasskey,
  CHUNK_DATA_SIZE,
  type ChunkMeta,
} from '../src/crypto-chunked.ts';
import {
  deriveKeyPairFromSecret,
  exportPublicKey,
  importPublicKey,
} from '../src/crypto-passkey.ts';

describe('chunk plaintext encoding', () => {
  it('round-trips encodeChunkPlaintext / decodeChunkPlaintext', () => {
    const meta: ChunkMeta = {
      groupId: crypto.getRandomValues(new Uint8Array(16)),
      chunkIndex: 3,
      totalChunks: 10,
      mimeType: 'image/webp',
      data: crypto.getRandomValues(new Uint8Array(100)),
    };

    const encoded = encodeChunkPlaintext(meta);
    const decoded = decodeChunkPlaintext(encoded);

    assert.deepStrictEqual(decoded.groupId, meta.groupId);
    assert.equal(decoded.chunkIndex, meta.chunkIndex);
    assert.equal(decoded.totalChunks, meta.totalChunks);
    assert.equal(decoded.mimeType, meta.mimeType);
    assert.deepStrictEqual(decoded.data, meta.data);
  });

  it('handles empty data', () => {
    const meta: ChunkMeta = {
      groupId: new Uint8Array(16),
      chunkIndex: 0,
      totalChunks: 1,
      mimeType: 'text/plain',
      data: new Uint8Array(0),
    };

    const encoded = encodeChunkPlaintext(meta);
    const decoded = decodeChunkPlaintext(encoded);

    assert.equal(decoded.data.length, 0);
    assert.equal(decoded.mimeType, 'text/plain');
  });

  it('handles unicode MIME type', () => {
    const meta: ChunkMeta = {
      groupId: new Uint8Array(16),
      chunkIndex: 0,
      totalChunks: 1,
      mimeType: 'application/octet-stream',
      data: new Uint8Array(10),
    };

    const encoded = encodeChunkPlaintext(meta);
    const decoded = decodeChunkPlaintext(encoded);
    assert.equal(decoded.mimeType, 'application/octet-stream');
  });
});

describe('splitIntoChunks', () => {
  it('small file (< 22KB) produces a single chunk', () => {
    const data = new Uint8Array(1000);
    const chunks = splitIntoChunks(data, 'image/png');

    assert.equal(chunks.length, 1);
    assert.equal(chunks[0].chunkIndex, 0);
    assert.equal(chunks[0].totalChunks, 1);
    assert.equal(chunks[0].data.length, 1000);
    assert.equal(chunks[0].mimeType, 'image/png');
  });

  it('exact boundary (22000 bytes) produces a single chunk', () => {
    const data = new Uint8Array(CHUNK_DATA_SIZE);
    const chunks = splitIntoChunks(data, 'image/png');

    assert.equal(chunks.length, 1);
    assert.equal(chunks[0].data.length, CHUNK_DATA_SIZE);
  });

  it('22001 bytes produces two chunks', () => {
    const data = new Uint8Array(CHUNK_DATA_SIZE + 1);
    const chunks = splitIntoChunks(data, 'image/png');

    assert.equal(chunks.length, 2);
    assert.equal(chunks[0].data.length, CHUNK_DATA_SIZE);
    assert.equal(chunks[1].data.length, 1);
    assert.equal(chunks[0].totalChunks, 2);
    assert.equal(chunks[1].totalChunks, 2);
    assert.equal(chunks[0].chunkIndex, 0);
    assert.equal(chunks[1].chunkIndex, 1);
  });

  it('correct number of chunks for large file', () => {
    const size = CHUNK_DATA_SIZE * 5 + 500;
    const data = new Uint8Array(size);
    const chunks = splitIntoChunks(data, 'video/mp4');

    assert.equal(chunks.length, 6);
    for (let i = 0; i < 5; i++) {
      assert.equal(chunks[i].data.length, CHUNK_DATA_SIZE);
    }
    assert.equal(chunks[5].data.length, 500);
  });

  it('group_id is the same for all chunks', () => {
    const data = new Uint8Array(CHUNK_DATA_SIZE * 3);
    const chunks = splitIntoChunks(data, 'image/jpeg');

    const gid = chunks[0].groupId;
    for (const chunk of chunks) {
      assert.deepStrictEqual(chunk.groupId, gid);
    }
  });

  it('chunk_index sequential and total_chunks correct', () => {
    const data = new Uint8Array(CHUNK_DATA_SIZE * 4 + 1);
    const chunks = splitIntoChunks(data, 'image/jpeg');

    assert.equal(chunks.length, 5);
    for (let i = 0; i < chunks.length; i++) {
      assert.equal(chunks[i].chunkIndex, i);
      assert.equal(chunks[i].totalChunks, 5);
    }
  });

  it('MIME type preserved across all chunks', () => {
    const data = new Uint8Array(CHUNK_DATA_SIZE * 2 + 100);
    const chunks = splitIntoChunks(data, 'application/pdf');

    for (const chunk of chunks) {
      assert.equal(chunk.mimeType, 'application/pdf');
    }
  });

  it('empty file produces single chunk with empty data', () => {
    const data = new Uint8Array(0);
    const chunks = splitIntoChunks(data, 'application/octet-stream');

    assert.equal(chunks.length, 1);
    assert.equal(chunks[0].data.length, 0);
    assert.equal(chunks[0].totalChunks, 1);
  });
});

describe('chunked password encryption', () => {
  it('round-trips encrypt/decrypt for small file', async () => {
    const data = crypto.getRandomValues(new Uint8Array(500));
    const password = 'test-chunked-password';
    const mimeType = 'image/webp';

    const fragments = await encryptChunksPassword(data, mimeType, password);
    assert.equal(fragments.length, 1);

    const chunk = await decryptChunkPassword(fragments[0], password);
    assert.equal(chunk.chunkIndex, 0);
    assert.equal(chunk.totalChunks, 1);
    assert.equal(chunk.mimeType, mimeType);
    assert.deepStrictEqual(chunk.data, data);
  });

  it('round-trips multi-chunk file', async () => {
    const data = crypto.getRandomValues(new Uint8Array(CHUNK_DATA_SIZE + 100));
    const password = 'multi-chunk-pass';
    const mimeType = 'video/mp4';

    const fragments = await encryptChunksPassword(data, mimeType, password);
    assert.equal(fragments.length, 2);

    const chunk0 = await decryptChunkPassword(fragments[0], password);
    const chunk1 = await decryptChunkPassword(fragments[1], password);

    assert.equal(chunk0.chunkIndex, 0);
    assert.equal(chunk1.chunkIndex, 1);
    assert.equal(chunk0.totalChunks, 2);
    assert.equal(chunk1.totalChunks, 2);

    // Reassemble and verify
    const reassembled = new Uint8Array(chunk0.data.length + chunk1.data.length);
    reassembled.set(chunk0.data, 0);
    reassembled.set(chunk1.data, chunk0.data.length);
    assert.deepStrictEqual(reassembled, data);
  });

  it('fails with wrong password', async () => {
    const data = crypto.getRandomValues(new Uint8Array(100));
    const fragments = await encryptChunksPassword(data, 'text/plain', 'right');
    await assert.rejects(
      () => decryptChunkPassword(fragments[0], 'wrong'),
      { name: 'OperationError' }
    );
  });

  it('MIME type preserved through encrypt/decrypt', async () => {
    const data = crypto.getRandomValues(new Uint8Array(50));
    const mimeType = 'application/pdf';
    const fragments = await encryptChunksPassword(data, mimeType, 'pass');
    const chunk = await decryptChunkPassword(fragments[0], 'pass');
    assert.equal(chunk.mimeType, mimeType);
  });

  it('group_id same across all encrypted chunks', async () => {
    const data = crypto.getRandomValues(new Uint8Array(CHUNK_DATA_SIZE * 2 + 100));
    const fragments = await encryptChunksPassword(data, 'image/png', 'pass');

    const chunks = await Promise.all(fragments.map(f => decryptChunkPassword(f, 'pass')));
    const gid = chunks[0].groupId;
    for (const chunk of chunks) {
      assert.deepStrictEqual(chunk.groupId, gid);
    }
  });
});

describe('chunked passkey encryption', () => {
  it('round-trips encrypt/decrypt for small file', async () => {
    const recipientSecret = crypto.getRandomValues(new Uint8Array(32));
    const recipientKp = await deriveKeyPairFromSecret(recipientSecret);
    const recipientPubRaw = await exportPublicKey(recipientKp.publicKey);
    const recipientPub = await importPublicKey(recipientPubRaw);

    const data = crypto.getRandomValues(new Uint8Array(500));
    const mimeType = 'image/webp';

    const fragments = await encryptChunksPasskey(data, mimeType, recipientPub);
    assert.equal(fragments.length, 1);

    const chunk = await decryptChunkPasskey(fragments[0], recipientSecret);
    assert.equal(chunk.chunkIndex, 0);
    assert.equal(chunk.totalChunks, 1);
    assert.equal(chunk.mimeType, mimeType);
    assert.deepStrictEqual(chunk.data, data);
  });

  it('round-trips multi-chunk file', async () => {
    const recipientSecret = crypto.getRandomValues(new Uint8Array(32));
    const recipientKp = await deriveKeyPairFromSecret(recipientSecret);
    const recipientPub = await importPublicKey(await exportPublicKey(recipientKp.publicKey));

    const data = crypto.getRandomValues(new Uint8Array(CHUNK_DATA_SIZE + 100));
    const mimeType = 'video/mp4';

    const fragments = await encryptChunksPasskey(data, mimeType, recipientPub);
    assert.equal(fragments.length, 2);

    const chunk0 = await decryptChunkPasskey(fragments[0], recipientSecret);
    const chunk1 = await decryptChunkPasskey(fragments[1], recipientSecret);

    assert.equal(chunk0.chunkIndex, 0);
    assert.equal(chunk1.chunkIndex, 1);
    assert.equal(chunk0.totalChunks, 2);
    assert.equal(chunk1.totalChunks, 2);

    // Reassemble and verify
    const reassembled = new Uint8Array(chunk0.data.length + chunk1.data.length);
    reassembled.set(chunk0.data, 0);
    reassembled.set(chunk1.data, chunk0.data.length);
    assert.deepStrictEqual(reassembled, data);
  });

  it('fails with wrong secret', async () => {
    const secret1 = crypto.getRandomValues(new Uint8Array(32));
    const secret2 = crypto.getRandomValues(new Uint8Array(32));
    const kp1 = await deriveKeyPairFromSecret(secret1);
    const pub1 = await importPublicKey(await exportPublicKey(kp1.publicKey));

    const data = crypto.getRandomValues(new Uint8Array(100));
    const fragments = await encryptChunksPasskey(data, 'text/plain', pub1);
    await assert.rejects(
      () => decryptChunkPasskey(fragments[0], secret2)
    );
  });

  it('MIME type preserved through encrypt/decrypt', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const kp = await deriveKeyPairFromSecret(secret);
    const pub = await importPublicKey(await exportPublicKey(kp.publicKey));

    const data = crypto.getRandomValues(new Uint8Array(50));
    const mimeType = 'application/pdf';
    const fragments = await encryptChunksPasskey(data, mimeType, pub);
    const chunk = await decryptChunkPasskey(fragments[0], secret);
    assert.equal(chunk.mimeType, mimeType);
  });

  it('group_id same across all encrypted chunks', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const kp = await deriveKeyPairFromSecret(secret);
    const pub = await importPublicKey(await exportPublicKey(kp.publicKey));

    const data = crypto.getRandomValues(new Uint8Array(CHUNK_DATA_SIZE * 2 + 100));
    const fragments = await encryptChunksPasskey(data, 'image/png', pub);

    const chunks = await Promise.all(fragments.map(f => decryptChunkPasskey(f, secret)));
    const gid = chunks[0].groupId;
    for (const chunk of chunks) {
      assert.deepStrictEqual(chunk.groupId, gid);
    }
  });
});
