// Diffie–Hellman key exchange over a standard 2048-bit MODP group (RFC 3526, Group 14).
// This is a real safe prime used in production protocols (IKE/IPsec, SSH, TLS)
// Level 3 removes Level 2's "pre-shared key" assumption: Alice and Bob now derive their
// shared AES key live, over a channel Eve can watch, using only public values.

const PRIME_HEX = (
  'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' +
  '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' +
  '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
  'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05' +
  '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB' +
  '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
  'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' +
  '3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF'
)

export const PRIME = BigInt('0x' + PRIME_HEX)
export const GENERATOR = 2n

// Size of the random private exponent. Doesn't need to match the 2048-bit modulus —
// 256 bits already gives a keyspace far bigger than brute force can touch — but it does
// need to come from a CSPRNG, which is why this uses crypto.getRandomValues rather than Math.random.
const PRIVATE_KEY_BITS = 256

/** Modular exponentiation by repeated squaring: base^exp mod m, without ever materializing base^exp. */
function modPow(base, exp, mod) {
  base %= mod
  let result = 1n
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod
    exp >>= 1n
    base = (base * base) % mod
  }
  return result
}

/** Cryptographically random BigInt with an exact bit length. */
function randomBigInt(bits) {
  const byteLen = Math.ceil(bits / 8)
  const bytes = new Uint8Array(byteLen)
  crypto.getRandomValues(bytes)
  let big = BigInt('0x' + [...bytes].map(b => b.toString(16).padStart(2, '0')).join(''))
  const excess = BigInt(byteLen * 8 - bits)
  if (excess > 0n) big >>= excess
  return big
}

/** Generate a fresh DH keypair: a random private exponent and its public value g^x mod p. */
export function generateDHKeyPair() {
  const privateKey = randomBigInt(PRIVATE_KEY_BITS)
  const publicKey = modPow(GENERATOR, privateKey, PRIME)
  return { privateKey, publicKey }
}

/** Combine your private exponent with the other party's public value into the shared secret. */
export function computeSharedSecret(myPrivateKey, theirPublicKey) {
  return modPow(theirPublicKey, myPrivateKey, PRIME)
}

/**
 * Big-endian byte encoding of a BigInt. Used for hashing into an AES key (never sent over
 * the wire), and, as of Level 4, as the exact bytes that get signed/verified — the signature
 * authenticates "this specific DH public value", not just "some message from Alice".
 */
export function bigIntToBytes(big) {
  let hex = big.toString(16)
  if (hex.length % 2) hex = '0' + hex
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16)
  return bytes
}

/**
 * Derive a usable AES-256-GCM key from the raw DH shared secret.
 * The raw secret is never used as key material directly — it's hashed first, the same
 * basic idea real protocols use (HKDF) to turn a DH output into a symmetric key.
 */
export async function deriveAesKeyFromSharedSecret(sharedSecret) {
  const raw = bigIntToBytes(sharedSecret)
  const hash = await crypto.subtle.digest('SHA-256', raw)
  return crypto.subtle.importKey('raw', hash, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt'])
}

/** Truncated hex for display — these are 2048-bit / 256-bit numbers, far too long to show in full. */
export function shortHex(big, chars = 20) {
  const hex = big.toString(16)
  return hex.length > chars ? `${hex.slice(0, chars)}…` : hex
}