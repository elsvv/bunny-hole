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
