// src/webauthn.ts

const RP_ID_FALLBACK = 'localhost';

function getRpId(): string {
  if (typeof location !== 'undefined' && location.hostname !== 'localhost') {
    return location.hostname;
  }
  return RP_ID_FALLBACK;
}

// Fixed salt used for PRF evaluation — deterministic key derivation.
const PRF_SALT = new TextEncoder().encode('bunny-hole-prf-salt-v1');

export interface PasskeyRegistration {
  credentialId: string; // base64url
  prfSupported: boolean;
}

export async function registerPasskey(): Promise<PasskeyRegistration> {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(16));

  const credential = await navigator.credentials.create({
    publicKey: {
      rp: { name: 'Bunny Hole', id: getRpId() },
      user: {
        id: userId,
        name: 'bunny-hole-user',
        displayName: 'Bunny Hole User',
      },
      challenge,
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },   // ES256
        { type: 'public-key', alg: -257 },  // RS256
      ],
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
      extensions: { prf: {} } as any,
    },
  }) as PublicKeyCredential;

  const extResults = credential.getClientExtensionResults() as any;
  const prfSupported = !!extResults.prf?.enabled;

  const rawId = new Uint8Array(credential.rawId);
  let credentialId = '';
  for (let i = 0; i < rawId.length; i++) credentialId += String.fromCharCode(rawId[i]);
  credentialId = btoa(credentialId).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  return { credentialId, prfSupported };
}

export async function getPrfSecret(credentialId: string): Promise<Uint8Array> {
  // Decode credential ID from base64url
  const padded = credentialId.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded);
  const rawId = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) rawId[i] = binary.charCodeAt(i);

  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: getRpId(),
      allowCredentials: [{ type: 'public-key', id: rawId.buffer }],
      userVerification: 'preferred',
      extensions: {
        prf: { eval: { first: PRF_SALT } },
      } as any,
    },
  }) as PublicKeyCredential;

  const extResults = assertion.getClientExtensionResults() as any;
  const prfResult = extResults.prf?.results?.first;
  if (!prfResult) {
    throw new Error('PRF extension not available or not supported by this authenticator');
  }
  return new Uint8Array(prfResult);
}
