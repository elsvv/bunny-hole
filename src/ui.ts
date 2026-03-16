// src/ui.ts — Router: resolves the current URL hash into a View

import { decodePayload } from './encoding.ts';
import { toBase64url } from './encoding.ts';

export type View =
  | { kind: 'compose' }
  | { kind: 'decrypt-password'; fragment: string }
  | { kind: 'decrypt-passkey'; fragment: string }
  | { kind: 'add-contact'; pubkey: string; label: string };

export function resolveView(): View {
  const hash = location.hash.slice(1);
  if (!hash) return { kind: 'compose' };

  try {
    const { mode, parts } = decodePayload(hash);
    switch (mode) {
      case 0x01:
        return { kind: 'decrypt-password', fragment: hash };
      case 0x02:
        return { kind: 'decrypt-passkey', fragment: hash };
      case 0x03: {
        const pubkeyBytes = parts[0];
        const label = new TextDecoder().decode(parts[1]);
        const pubkey = toBase64url(pubkeyBytes);
        return { kind: 'add-contact', pubkey, label };
      }
      default:
        return { kind: 'compose' };
    }
  } catch {
    return { kind: 'compose' };
  }
}
