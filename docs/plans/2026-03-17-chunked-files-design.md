# Chunked File Encryption — Design Document

Send encrypted files (images, audio, video, any file) via multiple URL chunks.

## Overview

Files are split into chunks, each chunk becomes a self-contained encrypted URL. Recipient opens chunks in any order, stores them locally (IndexedDB). When all chunks collected — file is assembled and available for download/preview.

## Chunk Payload Format

New mode bytes: `0x04` (password), `0x05` (passkey).

**Plaintext structure (before encryption):**
```
group_id (16 bytes)       — random ID, same for all chunks of one file
chunk_index (2 bytes, BE) — 0-based chunk number
total_chunks (2 bytes, BE) — total number of chunks
mime_type_len (1 byte)    — length of MIME type string
mime_type (N bytes)       — e.g. "image/webp"
data (rest)               — chunk data
```

Encrypted and encoded same as existing modes:
- `0x04`: `salt(16) | iv(12) | ciphertext` — password mode
- `0x05`: `ephemeral_pubkey(65) | iv(12) | ciphertext` — passkey mode

**Chunk data size:** 22,000 bytes per chunk.

**Max chunks:** 65,535 (uint16). Warning at >250 KB file size (~12 chunks).

## Image Compression

Before chunking, images (`image/*` except GIF and SVG) are compressed:

1. Load into `Image()`, draw on `<canvas>`
2. If width or height > 1920px — scale proportionally
3. `canvas.toBlob('image/webp', 0.7)` → compressed blob
4. If browser doesn't support WebP — fallback `image/jpeg` at 0.7
5. If compressed blob > original — use original
6. Skip compression for GIF (animation), SVG (already light), files < 50 KB
7. Show "Compressed: 2.3 MB → 180 KB" in UI

## UI — Sender

Text and file are mutually exclusive in compose view.

```
[textarea: Your message]
── or ──
[Button: Attach file]
[file info: photo.jpg → image/webp, 2.3 MB → 180 KB, 9 chunks]

── Send via ──
○ Password    ○ Passkey
[Encrypt]

── Result ──
Generated 9 encrypted links:
[textarea with all links, one per line]  [Copy all]
⚠ Send all links to the recipient. Order doesn't matter.
⚠ Password mode: send password separately.
```

## UI — Recipient

```
You received a file chunk (3 of 9).
[if password: input password]
[Button: Decrypt & save chunk]

── Progress ──
Chunks collected: ███░░░░░░ 3/9
Missing: 4, 5, 6, 7, 8, 9

[When all 9 collected:]
File ready: image/webp (180 KB)
[Button: Download]  [Button: Preview]
```

## Storage

IndexedDB database `bunny-hole`, object store `chunks`:

```
Key: {group_id}_{chunk_index}
Value: {
  group_id: string,
  chunk_index: number,
  total_chunks: number,
  mime_type: string,
  data: Uint8Array,
  stored_at: string (ISO date)
}
```

Assembly: query by group_id, sort by chunk_index, concatenate data arrays, create Blob with mime_type.

Auto-cleanup: chunks older than 24 hours deleted on app open.

## Encoding Module Changes

Add to `MODE_LAYOUT`:
- `0x04: [16, 12]` — same as password mode (salt + iv + ciphertext)
- `0x05: [65, 12]` — same as passkey mode (ephemeral_pubkey + iv + ciphertext)

The chunk metadata (group_id, index, total, mime, data) is inside the encrypted payload, not in the URL-visible part.
