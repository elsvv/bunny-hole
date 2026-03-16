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
