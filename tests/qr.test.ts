import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { QrCode, Ecc } from '../src/qrcodegen.ts';

describe('QR code generator (Nayuki)', () => {
  it('encodes a short text', () => {
    const qr = QrCode.encodeText('Hello', Ecc.LOW);
    assert.ok(qr.size > 0);
    assert.equal(qr.version, 1);
  });

  it('encodes a realistic key-share URL', () => {
    const url = 'https://elsvv.github.io/bunny-hole/#' + 'A'.repeat(100);
    const qr = QrCode.encodeText(url, Ecc.LOW);
    assert.ok(qr.size > 0);
    assert.ok(qr.version >= 3);
  });

  it('produces deterministic output', () => {
    const qr1 = QrCode.encodeText('test', Ecc.LOW);
    const qr2 = QrCode.encodeText('test', Ecc.LOW);
    assert.equal(qr1.size, qr2.size);
    for (let r = 0; r < qr1.size; r++) {
      for (let c = 0; c < qr1.size; c++) {
        assert.equal(qr1.getModule(c, r), qr2.getModule(c, r));
      }
    }
  });

  it('different inputs produce different QR codes', () => {
    const qr1 = QrCode.encodeText('abc', Ecc.LOW);
    const qr2 = QrCode.encodeText('xyz', Ecc.LOW);
    let diff = false;
    const size = Math.min(qr1.size, qr2.size);
    for (let r = 0; r < size && !diff; r++) {
      for (let c = 0; c < size && !diff; c++) {
        if (qr1.getModule(c, r) !== qr2.getModule(c, r)) diff = true;
      }
    }
    assert.ok(diff);
  });
});
