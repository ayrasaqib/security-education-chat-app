// Shared "Eve as active man-in-the-middle" logic, reused across every level that runs a DH
// exchange (3 onward)

import { generateDHKeyPair, bigIntToBytes, computeSharedSecret, deriveAesKeyFromSharedSecret } from './dh'
import { verifyBytes } from './auth'

/**
 * Eve's core move: instead of relaying Alice's and Bob's real DH public values to each other,
 * she generates two independent DH keypairs of her own and substitutes one for each side.
 */
export function forgeSubstituteKeys() {
  return {
    forAlice: generateDHKeyPair(), // the forged "B" Eve hands to Alice
    forBob: generateDHKeyPair(),   // the forged "A" Eve hands to Bob
  }
}

/**
 * Derive the keys that result once Alice and Bob unknowingly complete DH with Eve's forged
 * values instead of each other's real ones. Only relevant where nothing catches the
 * substitution before this point (Level 3 — no authentication layer yet). Returns three
 * independent AES keys plus the raw shared secrets (for display/narration).
 */
export async function deriveMitmKeys({ alice, bob, forged }) {
  const sharedAliceSide = computeSharedSecret(alice.privateKey, forged.forAlice.publicKey)
  const sharedBobSide = computeSharedSecret(bob.privateKey, forged.forBob.publicKey)
  const eveSharedWithAlice = computeSharedSecret(forged.forAlice.privateKey, alice.publicKey)
  const eveSharedWithBob = computeSharedSecret(forged.forBob.privateKey, bob.publicKey)

  const [aliceKey, bobKey, eveKeyWithAlice, eveKeyWithBob] = await Promise.all([
    deriveAesKeyFromSharedSecret(sharedAliceSide),
    deriveAesKeyFromSharedSecret(sharedBobSide),
    deriveAesKeyFromSharedSecret(eveSharedWithAlice),
    deriveAesKeyFromSharedSecret(eveSharedWithBob),
  ])

  return { aliceKey, bobKey, eveKeyWithAlice, eveKeyWithBob, eveSharedWithAlice, eveSharedWithBob }
}

/**
 * Check whether Eve's substituted public values would survive signature verification —
 * relevant everywhere the DH exchange is authenticated (Levels 4, 5, 6). Eve only ever holds
 * the REAL signatures she intercepted (computed over the real public values); she has neither
 * identity's private key, so she cannot produce a new signature that verifies over her forged
 * values. This calls the real Web Crypto verify — the failure is genuine, not scripted.
 */
export async function verifyForgedValues({ forged, sigA, sigB, aliceIdentityPublicKey, bobIdentityPublicKey }) {
  const forgedBBytesForAlice = bigIntToBytes(forged.forAlice.publicKey) // what Alice receives as "B"
  const forgedABytesForBob = bigIntToBytes(forged.forBob.publicKey)     // what Bob receives as "A"

  const [aliceVerifiedBob, bobVerifiedAlice] = await Promise.all([
    verifyBytes(bobIdentityPublicKey, sigB, forgedBBytesForAlice),
    verifyBytes(aliceIdentityPublicKey, sigA, forgedABytesForBob),
  ])

  return { aliceVerifiedBob, bobVerifiedAlice }
}