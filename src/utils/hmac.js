// HMAC-SHA256 helpers, used to protect message *integrity* in Level 5.

import { bigIntToBytes } from './dh'

const HMAC_ALGO = { name: 'HMAC', hash: 'SHA-256' }

// Domain-separation label appended before hashing, so the HMAC key derived here is never
// numerically equal to the AES key Level 3/4 derive from the same raw shared secret.
const HMAC_LABEL_BYTE = 0x01

/**
 * Derive a dedicated HMAC-SHA256 key from the raw DH shared secret.
 * Using a distinct, labelled derivation (rather than reusing the AES key) means compromising
 * one key doesn't hand over the other for free — a small but real defence-in-depth choice.
 */
export async function deriveHmacKeyFromSharedSecret(sharedSecret) {
  const raw = bigIntToBytes(sharedSecret)
  const labelled = new Uint8Array(raw.length + 1)
  labelled.set(raw)
  labelled[raw.length] = HMAC_LABEL_BYTE
  const hash = await crypto.subtle.digest('SHA-256', labelled)
  return crypto.subtle.importKey('raw', hash, HMAC_ALGO, true, ['sign', 'verify'])
}

/** Compute an HMAC-SHA256 tag over arbitrary bytes, returned as hex for display/transmission. */
export async function computeHmacHex(key, bytes) {
  const sig = await crypto.subtle.sign('HMAC', key, bytes)
  return bufferToHex(sig)
}

/** Verify a hex-encoded HMAC tag against the same bytes. False on any mismatch — no partial credit. */
export async function verifyHmacHex(key, tagHex, bytes) {
  return crypto.subtle.verify('HMAC', key, hexToBuffer(tagHex), bytes)
}

/** Encode the fields an HMAC should cover (IV + ciphertext) into one byte array to sign/verify. */
export function encodeForMac(ivHex, ciphertextB64) {
  return new TextEncoder().encode(ivHex + ciphertextB64)
}

export function bufferToHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('')
}

function hexToBuffer(hex) {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16)
  return bytes
}

export function shortHex(hex, chars = 20) {
  return hex.length > chars ? `${hex.slice(0, chars)}…` : hex
}