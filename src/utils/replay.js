// HMAC (Level 5) proves a message wasn't altered in transit, but says nothing about whether it's
// being seen for the first time — a byte-for-byte replay of an untampered message produces a tag
// that verifies perfectly. Binding a strictly-increasing sequence number into the same MAC-covered
// payload closes that gap: the number can't be stripped or edited without invalidating the tag
// (Level 5's control still catches that), and the receiver independently refuses to accept anything
// at or below the highest sequence number already seen from that sender.

/** Encode (sequence number, IV, ciphertext) into the bytes an HMAC tag should cover. */
export function encodeForMacWithSeq(seq, ivHex, ciphertextB64) {
  return new TextEncoder().encode(`${seq}:${ivHex}${ciphertextB64}`)
}

/**
 * True if `seq` is NOT acceptable as the next message from this sender — i.e. it's at or below
 * the highest sequence number already accepted. This simulator uses a strict, non-windowed check:
 * equal-or-lower is always treated as a replay, the same way a minimal sequence-number scheme would
 * (real protocols sometimes use a small sliding window to tolerate reordering).
 */
export function isReplay(seq, lastSeen) {
  return seq <= lastSeen
}