// src/qr.ts — QR code rendering using Nayuki's QR Code generator library (MIT)

import { QrCode, Ecc } from './qrcodegen.ts';

export function renderQR(canvas: HTMLCanvasElement, text: string, cellSize = 6): void {
  const qr = QrCode.encodeText(text, Ecc.LOW);
  const size = qr.size;
  const quiet = 4;
  const totalSize = (size + quiet * 2) * cellSize;
  canvas.width = totalSize;
  canvas.height = totalSize;
  const ctx = canvas.getContext('2d')!;
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, totalSize, totalSize);
  ctx.fillStyle = '#000000';
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (qr.getModule(c, r)) {
        ctx.fillRect((c + quiet) * cellSize, (r + quiet) * cellSize, cellSize, cellSize);
      }
    }
  }
}
