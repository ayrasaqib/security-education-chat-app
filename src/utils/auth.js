// ECDSA (P-256) digital signatures, used to authenticate the DH public values in Level 4.

const SIGN_ALGO = { name: 'ECDSA', namedCurve: 'P-256' }
const SIGN_PARAMS = { name: 'ECDSA', hash: 'SHA-256' }

/**
 * Generate a long-term ECDSA identity keypair. This simulates a pre-established identity
 * (e.g. a certificate or a key pinned on first contact) — it is NOT regenerated every
 * time the DH exchange re-runs, the same way a real identity key outlives any single session.
 */
export function generateIdentityKeyPair() {
  return crypto.subtle.generateKey(SIGN_ALGO, true, ['sign', 'verify'])
}

/** Export a public identity key to raw bytes, hex-encoded, purely for display as a "fingerprint". */
export async function exportPublicKeyHex(publicKey) {
  const raw = await crypto.subtle.exportKey('raw', publicKey)
  return bufferToHex(raw)
}

/** Sign a byte payload (here: a DH public value's bytes) with a private identity key. */
export function signBytes(privateKey, bytes) {
  return crypto.subtle.sign(SIGN_PARAMS, privateKey, bytes)
}

/** Verify a signature over a byte payload using the claimed signer's public identity key. */
export function verifyBytes(publicKey, signature, bytes) {
  return crypto.subtle.verify(SIGN_PARAMS, publicKey, signature, bytes)
}

export function bufferToHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('')
}

export function shortHex(hex, chars = 20) {
  return hex.length > chars ? `${hex.slice(0, chars)}…` : hex
}