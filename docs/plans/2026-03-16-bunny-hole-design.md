# Bunny Hole - Design Document

Frontend-only encrypted messaging via URL. No server, no tracking.

## Overview

Users encrypt text messages and share them as URLs. The encrypted payload lives entirely in the URL fragment (`#`), which is never sent to any server. Two encryption modes: passkey-based (ECIES) and password-based (PBKDF2), both using AES-256-GCM.

## Architecture

- **Single HTML file** with inline CSS and JS (compiled from TypeScript)
- **Zero dependencies** — Web Crypto API + WebAuthn API only
- **Target bundle size:** < 15 KB (HTML + CSS + JS, before gzip)
- **Deploy:** any static hosting, GitHub Pages, or `file://`

## URL Structure

- `https://bunny-hole.example/` — main page (compose message)
- `https://bunny-hole.example/#<payload>` — encrypted message

### Payload format (base64url-encoded)

```
mode (1 byte) | data...
```

| Mode | Description | Data |
|------|-------------|------|
| 0x01 | Password-based | salt(16) \| iv(12) \| ciphertext |
| 0x02 | Passkey-based | ephemeral_pubkey(65) \| iv(12) \| ciphertext |
| 0x03 | Public key share | pubkey(65) \| label(utf8) |

## Encryption

### Password mode (PBKDF2 + AES-GCM)

```
encrypt(message, password):
  salt = random(16 bytes)
  iv = random(12 bytes)
  key = PBKDF2(password, salt, 310000 iterations, SHA-256) -> AES-256
  ciphertext = AES-GCM(key, iv, encode_utf8(message))
  fragment = base64url(0x01 | salt | iv | ciphertext)

decrypt(fragment, password):
  decode -> mode, salt, iv, ciphertext
  key = PBKDF2(password, salt, 310000, SHA-256)
  message = decode_utf8(AES-GCM.decrypt(key, iv, ciphertext))
```

### Passkey mode (ECIES: ECDH P-256 + HKDF + AES-GCM)

```
register_passkey():
  credential = navigator.credentials.create({ extensions: { prf: {} } })
  save credential.id to localStorage
  prf_secret = authenticate_with_prf(fixed_salt)
  private_key = HKDF(prf_secret, "bunny-hole-ecdh-private") -> ECDH P-256
  public_key = derive public from private
  show public_key to user

encrypt(message, recipient_pubkey):
  ephemeral = ECDH.generateKey(P-256)
  shared = ECDH(ephemeral.private, recipient_pubkey)
  aes_key = HKDF(shared, "bunny-hole-msg") -> AES-256
  iv = random(12 bytes)
  ciphertext = AES-GCM(aes_key, iv, encode_utf8(message))
  fragment = base64url(0x02 | ephemeral.public_raw | iv | ciphertext)

decrypt(fragment):
  decode -> mode, ephemeral_pubkey, iv, ciphertext
  prf_secret = authenticate_with_prf(fixed_salt)
  private_key = HKDF(prf_secret, "bunny-hole-ecdh-private")
  shared = ECDH(private_key, ephemeral_pubkey)
  aes_key = HKDF(shared, "bunny-hole-msg")
  message = decode_utf8(AES-GCM.decrypt(aes_key, iv, ciphertext))
```

## localStorage

| Key | Value |
|-----|-------|
| `bh_contacts` | `[{label, pubkey, added_at}]` |
| `bh_credential_id` | WebAuthn credential ID for PRF |

## UI

Single page, three states based on URL fragment presence and mode.

### State 1: Compose (no fragment)

```
Bunny Hole
Encrypted messages via URL. No server. No tracking.

[textarea: Your message]                    [char counter]

-- Send via --
( ) Password    ( ) Passkey
[if password: input "Encryption password"]
[if passkey:  select "Recipient" from contacts]
[Button: Encrypt]

-- My Keys --
[Button: Register passkey]          (if no passkey)
Your public key: [ab3F...xQ=]  [Copy] [QR]   (if passkey registered)

-- Contacts --
Alice    [ab3f...] [x]
Bob      [f82a...] [x]
[input: label] [input: public key] [Add]
```

### State 2: Decrypt (fragment with mode 0x01 or 0x02)

```
Bunny Hole
You received an encrypted message.

[if password mode:]
  [input: Password]
  [Button: Decrypt]

[if passkey mode:]
  [Button: Decrypt with passkey]

-- Decrypted message --
[plaintext in <pre>]
[Button: New message]
```

### State 3: Add contact (fragment with mode 0x03)

```
Bunny Hole
Someone shared their public key with you.

Label: Alice
Key:   ab3F...xQ=

[Button: Add to contacts]
[Button: Back]
```

### After encryption

```
-- Encrypted link --
[readonly input with full URL] [Copy]
[QR code on <canvas>]

! Send this link and the password separately.   (password mode only)
```

## Edge Cases

- **Message size limit:** ~24 KB plaintext (cross-browser URL limit). Show counter, block if exceeded.
- **Passkey loss:** different passkey = different private key. Warn user at registration. Support multiple passkey registrations.
- **PRF not supported:** detect at registration, show fallback message pointing to password mode.
- **Decryption failure:** catch AES-GCM error, show "Decryption failed."
- **QR code:** render on `<canvas>`, no library.

## Visual Style

Web 1.0 minimal. System font, `<hr>` dividers, no icons, no colors beyond defaults. Must load instantly.
