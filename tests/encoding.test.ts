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
