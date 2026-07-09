// AES-256-CTR helpers built on the browser's native Web Crypto API (SubtleCrypto).
//
// CTR is a stream-cipher mode: it XORs the plaintext with a keystream generated from the
// key + counter block, block by block, with no chaining between blocks and no built-in
// authentication tag (unlike AES-GCM). That's a deliberate choice for this level range —
// confidentiality is provided, but nothing here detects tampering, which is what makes the
// tampering attack demo possible before Level 5 introduces HMAC as the fix.

const ALGO = 'AES-CTR'
const COUNTER_LENGTH_BYTES = 16 // AES-CTR requires a full 16-byte initial counter block
const COUNTER_BITS = 64 // how many of those 128 bits are treated as the counter portion

/** Generate a fresh random AES-256-CTR key. */
export async function generateAesKey() {
  return crypto.subtle.generateKey({ name: ALGO, length: 256 }, true, ['encrypt', 'decrypt'])
}

/** Export a CryptoKey to a hex string, purely for display in the UI. */
export async function exportKeyHex(key) {
  const raw = await crypto.subtle.exportKey('raw', key)
  return bufferToHex(raw)
}

/**
 * Encrypt plaintext with AES-CTR.
 * Returns { ivHex, ciphertextB64 } — both safe to display/transmit as "network traffic".
 * ivHex here is the random initial counter block (still labelled "IV" in the UI, since that's
 * the familiar term, but it's 16 bytes rather than GCM's 12-byte IV).
 */
export async function encryptMessage(key, plaintext) {
  const counter = crypto.getRandomValues(new Uint8Array(COUNTER_LENGTH_BYTES))
  const encoded = new TextEncoder().encode(plaintext)

  const ciphertextBuf = await crypto.subtle.encrypt({ name: ALGO, counter, length: COUNTER_BITS }, key, encoded)

  return {
    ivHex: bufferToHex(counter),
    ciphertextB64: bufferToBase64(ciphertextBuf),
    ciphertextBytes: ciphertextBuf.byteLength,
  }
}

/**
 * Decrypt a { ivHex, ciphertextB64 } pair back to plaintext.
 * Unlike GCM, CTR mode has no authentication tag: decryption never throws on tampered
 * ciphertext. Flipping a ciphertext bit flips the exact corresponding plaintext bit and
 * decryption "succeeds" with silently altered content — that gap is intentional here, and
 * is exactly what Level 5's HMAC tag is introduced to close.
 */
export async function decryptMessage(key, ivHex, ciphertextB64) {
  const counter = hexToBuffer(ivHex)
  const ciphertext = base64ToBuffer(ciphertextB64)

  const plainBuf = await crypto.subtle.decrypt({ name: ALGO, counter, length: COUNTER_BITS }, key, ciphertext)
  return new TextDecoder().decode(plainBuf)
}

// ── encoding helpers ──

function bufferToHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('')
}

function hexToBuffer(hex) {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16)
  }
  return bytes.buffer
}

function bufferToBase64(buf) {
  const bytes = new Uint8Array(buf)
  let binary = ''
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
  return btoa(binary)
}

function base64ToBuffer(b64) {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes.buffer
}