// AES-256-GCM helpers built on the browser's native Web Crypto API (SubtleCrypto).
// Eve intercepts encrypted text (ciphertext) in the UI

const ALGO = 'AES-GCM'
const IV_LENGTH_BYTES = 12 // 96-bit IV, recommended size for AES-GCM

/** Generate a fresh random AES-256-GCM key. */
export async function generateAesKey() {
  return crypto.subtle.generateKey({ name: ALGO, length: 256 }, true, ['encrypt', 'decrypt'])
}

/** Export a CryptoKey to a hex string, purely for display in the UI. */
export async function exportKeyHex(key) {
  const raw = await crypto.subtle.exportKey('raw', key)
  return bufferToHex(raw)
}

/**
 * Encrypt plaintext with AES-GCM.
 * Returns { ivHex, ciphertextB64 } — both safe to display/transmit as "network traffic".
 */
export async function encryptMessage(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES))
  const encoded = new TextEncoder().encode(plaintext)

  const ciphertextBuf = await crypto.subtle.encrypt({ name: ALGO, iv }, key, encoded)

  return {
    ivHex: bufferToHex(iv),
    ciphertextB64: bufferToBase64(ciphertextBuf),
    ciphertextBytes: ciphertextBuf.byteLength,
  }
}

/**
 * Decrypt a { ivHex, ciphertextB64 } pair back to plaintext.
 * Throws if the key is wrong or the ciphertext has been tampered with
 * (GCM's built-in authentication tag will fail to verify).
 */
export async function decryptMessage(key, ivHex, ciphertextB64) {
  const iv = hexToBuffer(ivHex)
  const ciphertext = base64ToBuffer(ciphertextB64)

  const plainBuf = await crypto.subtle.decrypt({ name: ALGO, iv }, key, ciphertext)
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
