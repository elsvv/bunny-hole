// src/encoding.ts

export function toBase64url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64url(str: string): Uint8Array {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Payload layout per mode:
// 0x01: mode(1) | salt(16) | iv(12) | ciphertext(rest)
// 0x02: mode(1) | ephemeral_pubkey(65) | iv(12) | ciphertext(rest)
// 0x03: mode(1) | pubkey(65) | label(rest)

const MODE_LAYOUT: Record<number, number[]> = {
  0x01: [16, 12], // salt, iv — rest is ciphertext
  0x02: [65, 12], // ephemeral_pubkey, iv — rest is ciphertext
  0x03: [65],     // pubkey — rest is label
  0x04: [16, 12], // salt, iv — rest is ciphertext (chunked password)
  0x05: [65, 12], // ephemeral_pubkey, iv — rest is ciphertext (chunked passkey)
};

export function encodePayload(mode: number, ...parts: Uint8Array[]): string {
  let totalLen = 1;
  for (const p of parts) totalLen += p.length;
  const buf = new Uint8Array(totalLen);
  buf[0] = mode;
  let offset = 1;
  for (const p of parts) {
    buf.set(p, offset);
    offset += p.length;
  }
  return toBase64url(buf);
}

export function decodePayload(encoded: string): { mode: number; parts: Uint8Array[] } {
  const buf = fromBase64url(encoded);
  const mode = buf[0];
  const layout = MODE_LAYOUT[mode];
  if (!layout) throw new Error(`Unknown mode: 0x${mode.toString(16)}`);

  const minLen = 1 + layout.reduce((a, b) => a + b, 0);
  if (buf.length < minLen) throw new Error(`Truncated payload for mode 0x${mode.toString(16)}`);

  const parts: Uint8Array[] = [];
  let offset = 1;
  for (const size of layout) {
    parts.push(buf.slice(offset, offset + size));
    offset += size;
  }
  // remaining bytes are the last part
  parts.push(buf.slice(offset));
  return { mode, parts };
}
