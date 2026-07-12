// Shared "Eve tampers with an intercepted message" logic, reused by every level's
// "Tamper & resend" button. Eve never needs the key for any of this — that's the point:
// she's blindly corrupting bytes she can't read, not forging a message from scratch.

/**
 * Flip one byte in a base64-encoded ciphertext, roughly in the middle of the message.
 * Under AES-CTR (Levels 2-4), this flips the exact corresponding plaintext byte with no
 * error raised. Under HMAC-protected levels (5-6), it invalidates the tag instead, since
 * the tag was computed over the original bytes.
 * Returns a NEW base64 string — the original captured message is left untouched, so it can
 * still be tampered again or compared against.
 */
export function tamperCiphertextB64(ciphertextB64) {
  const binary = atob(ciphertextB64)
  if (binary.length === 0) return ciphertextB64

  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)

  const offset = Math.floor(bytes.length / 2)
  bytes[offset] ^= 0xff // flip every bit in that one byte

  let out = ''
  for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i])
  return btoa(out)
}

/**
 * Level 1 has no ciphertext to flip — plaintext travels as-is, so "tampering" there is just
 * editing the text directly. Kept in this module so every level's tamper action is driven by
 * the same file, even though this case needs no cryptography at all.
 */
export function tamperPlaintext(text) {
  const chars = [...text]
  if (chars.length === 0) return text

  const offset = Math.floor(chars.length / 2)
  chars[offset] = chars[offset] === '$' ? '€' : '$' // deterministic, visibly different substitution
  return chars.join('')
}