import { useState, useRef, useEffect } from 'react'
import { encryptMessage, decryptMessage } from '../../utils/crypto'
import {
  generateDHKeyPair,
  computeSharedSecret,
  deriveAesKeyFromSharedSecret,
  bigIntToBytes,
  shortHex,
  GENERATOR,
} from '../../utils/dh'
import {
  generateIdentityKeyPair,
  exportPublicKeyHex,
  signBytes,
  verifyBytes,
  bufferToHex,
  shortHex as sigShortHex,
} from '../../utils/auth'
import {
  deriveHmacKeyFromSharedSecret,
  computeHmacHex,
  verifyHmacHex,
  shortHex as macShortHex,
} from '../../utils/hmac'
import { encodeForMacWithSeq, isReplay } from '../../utils/replay'
import './Level6.css'

const STEP_DELAY_MS = 550

function Level6() {
  const [aliceMsgs, setAliceMsgs] = useState([])
  const [bobMsgs, setBobMsgs] = useState([])
  const [eveMsgs, setEveMsgs] = useState([])
  const [input, setInput] = useState('')
  const [sender, setSender] = useState('alice')
  const [status, setStatus] = useState('identities') // 'identities' | 'exchanging' | 'ready' | 'failed'
  const [aliceFingerprint, setAliceFingerprint] = useState('')
  const [bobFingerprint, setBobFingerprint] = useState('')

  // Reactive mirrors of the two "last seen" counters below, purely so the UI can visibly show them
  // ticking up. The refs remain the source of truth the async delivery logic checks against —
  // state alone would risk a stale value being read mid-await.
  const [lastSeenFromAlice, setLastSeenFromAlice] = useState(0) // Bob's counter for Alice's messages
  const [lastSeenFromBob, setLastSeenFromBob] = useState(0)     // Alice's counter for Bob's messages

  const aliceIdentityRef = useRef(null) // long-term ECDSA keypair, generated once
  const bobIdentityRef = useRef(null)
  const aesKeyRef = useRef(null)  // derived per exchange — confidentiality
  const hmacKeyRef = useRef(null) // derived per exchange — integrity, kept separate from aesKeyRef

  // Per-sender outgoing counters and per-recipient "highest accepted" trackers — this is the one
  // control new to Level 6. Everything else on this page is Levels 2–5 carried forward unchanged.
  const aliceSeqRef = useRef(0)
  const bobSeqRef = useRef(0)
  const lastSeenFromAliceRef = useRef(0) // Bob's view: highest sequence number accepted from Alice
  const lastSeenFromBobRef = useRef(0)   // Alice's view: highest sequence number accepted from Bob

  const msgId = useRef(1)
  const runIdRef = useRef(0) // guards against a stale run still writing state after "New exchange" or unmount
  const aliceScrollRef = useRef(null)
  const bobScrollRef = useRef(null)
  const eveScrollRef = useRef(null)

  function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms))
  }

  function addAlice(text, type = 'step') {
    setAliceMsgs(prev => [...prev, { id: msgId.current++, type, text }])
  }
  function addBob(text, type = 'step') {
    setBobMsgs(prev => [...prev, { id: msgId.current++, type, text }])
  }
  function addEve(text, type = 'capture') {
    setEveMsgs(prev => [...prev, { id: msgId.current++, type, text }])
  }

  async function runHandshake() {
    const myRun = ++runIdRef.current
    const stale = () => runIdRef.current !== myRun

    setStatus('exchanging')
    setAliceMsgs([])
    setBobMsgs([])
    setEveMsgs([])

    // Fresh session — sequence counters and "last seen" trackers reset along with the keys below.
    aliceSeqRef.current = 0
    bobSeqRef.current = 0
    lastSeenFromAliceRef.current = 0
    lastSeenFromBobRef.current = 0
    setLastSeenFromAlice(0)
    setLastSeenFromBob(0)

    const aliceIdentity = aliceIdentityRef.current
    const bobIdentity = bobIdentityRef.current

    // 1. Agree on public DH parameters
    addAlice(`Agreed public parameters — p (2048-bit prime), g = ${GENERATOR}`)
    addBob(`Agreed public parameters — p (2048-bit prime), g = ${GENERATOR}`)
    addEve(`Intercepted: p (2048-bit), g = ${GENERATOR} — public by design, nothing secret yet`)
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    // 2. Each side generates a fresh temporary DH keypair for this session
    addAlice('Generating ephemeral private value a…')
    addBob('Generating ephemeral private value b…')
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    const alice = generateDHKeyPair()
    const bob = generateDHKeyPair()
    addAlice(`Computing A = g^a mod p = ${shortHex(alice.publicKey)}`)
    addBob(`Computing B = g^b mod p = ${shortHex(bob.publicKey)}`)
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    // 3. Each side signs its own DH public value with its long-term identity key (Level 4's control)
    addAlice('Signing A with my identity key…')
    addBob('Signing B with my identity key…')
    const aBytes = bigIntToBytes(alice.publicKey)
    const bBytes = bigIntToBytes(bob.publicKey)
    const sigA = await signBytes(aliceIdentity.privateKey, aBytes)
    const sigB = await signBytes(bobIdentity.privateKey, bBytes)
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    // 4. Exchange (public value, signature) pairs over the untrusted network
    addAlice('Sending (A, signature) to Bob →')
    addBob('Sending (B, signature) to Alice →')
    addEve(`Intercepted A = ${shortHex(alice.publicKey, 16)} + sig ${sigShortHex(bufferToHex(sigA), 16)}`)
    addEve(`Intercepted B = ${shortHex(bob.publicKey, 16)} + sig ${sigShortHex(bufferToHex(sigB), 16)}`)
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    // 5. Each side verifies the signature against the sender's known identity public key
    const aliceVerifiedBob = await verifyBytes(bobIdentity.publicKey, sigB, bBytes)
    const bobVerifiedAlice = await verifyBytes(aliceIdentity.publicKey, sigA, aBytes)

    addAlice(
      aliceVerifiedBob
        ? "✓ Verified B's signature against Bob's known identity key"
        : "✕ Signature verification FAILED — rejecting this key"
    )
    addBob(
      bobVerifiedAlice
        ? "✓ Verified A's signature against Alice's known identity key"
        : "✕ Signature verification FAILED — rejecting this key"
    )
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    if (!aliceVerifiedBob || !bobVerifiedAlice) {
      setStatus('failed')
      return
    }

    // 6. After authenticating the source of each public value, compute the shared secret
    const sharedAlice = computeSharedSecret(alice.privateKey, bob.publicKey)
    const sharedBob = computeSharedSecret(bob.privateKey, alice.publicKey)

    addAlice(`Computing s = B^a mod p = ${shortHex(sharedAlice)}`)
    addBob(`Computing s = A^b mod p = ${shortHex(sharedBob)}`)
    addEve('Has p, g, A, B, and both signatures — still cannot derive s without solving the discrete log problem')
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    // 7. Derive TWO independent keys from the same shared secret — confidentiality and integrity
    //    stay separate controls, same reasoning as Level 5.
    addAlice('Deriving AES-256 key = SHA-256(s)…')
    addBob('Deriving AES-256 key = SHA-256(s)…')
    const aesKey = await deriveAesKeyFromSharedSecret(sharedAlice)
    if (stale()) return
    aesKeyRef.current = aesKey
    await sleep(400)
    if (stale()) return

    addAlice('Deriving HMAC-SHA256 key = SHA-256(s ‖ label)…')
    addBob('Deriving HMAC-SHA256 key = SHA-256(s ‖ label)…')
    const hmacKey = await deriveHmacKeyFromSharedSecret(sharedAlice)
    if (stale()) return
    hmacKeyRef.current = hmacKey
    await sleep(400)
    if (stale()) return

    // 8. Level 6's own addition — no new key material, just a per-sender counter both sides now track.
    addAlice('Resetting per-session sequence number to 0')
    addBob('Resetting per-session sequence number to 0')
    addEve('Can see ciphertext, MAC tags, and sequence numbers on every message, but has no key and cannot rewind either counter')
    await sleep(400)
    if (stale()) return

    addAlice('Secure, authenticated, integrity-protected, replay-resistant channel ready — you can chat now.', 'ready-note')
    addBob('Secure, authenticated, integrity-protected, replay-resistant channel ready — you can chat now.', 'ready-note')
    setStatus('ready')
  }

  // Long-term identity keys: generated once on mount, NOT regenerated by "New exchange" —
  // they represent identities both parties already trust, independent of any one session.
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      const alice = await generateIdentityKeyPair()
      const bob = await generateIdentityKeyPair()
      if (cancelled) return
      aliceIdentityRef.current = alice
      bobIdentityRef.current = bob
      setAliceFingerprint(sigShortHex(await exportPublicKeyHex(alice.publicKey)))
      setBobFingerprint(sigShortHex(await exportPublicKeyHex(bob.publicKey)))
      runHandshake()
    })()
    return () => { cancelled = true; runIdRef.current++ } // invalidate any in-flight run on unmount
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  useEffect(() => {
    if (aliceScrollRef.current) aliceScrollRef.current.scrollTop = aliceScrollRef.current.scrollHeight
  }, [aliceMsgs])

  useEffect(() => {
    if (bobScrollRef.current) bobScrollRef.current.scrollTop = bobScrollRef.current.scrollHeight
  }, [bobMsgs])

  useEffect(() => {
    if (eveScrollRef.current) eveScrollRef.current.scrollTop = eveScrollRef.current.scrollHeight
  }, [eveMsgs])

  /**
   * Shared receiver-side pipeline: HMAC verify (Level 5) → sequence freshness check (Level 6) →
   * decrypt. Used both for normal delivery and for Eve's "Replay" button, so the exact same checks
   * run whether the message is arriving for the first time or being re-sent from capture.
   */
  async function deliverMessage({ seq, ivHex, ciphertextB64, tagHex, fromAlice }) {
    const hmacKey = hmacKeyRef.current
    const aesKey = aesKeyRef.current
    const setCounter = fromAlice ? setLastSeenFromAlice : setLastSeenFromBob

    const macBytes = encodeForMacWithSeq(seq, ivHex, ciphertextB64)
    const integrityOk = await verifyHmacHex(hmacKey, tagHex, macBytes)
    if (!integrityOk) {
      const lastSeenRef = fromAlice ? lastSeenFromAliceRef : lastSeenFromBobRef
      return { ok: false, reason: '✕ HMAC verification failed — message discarded', counterAfter: lastSeenRef.current }
    }

    const lastSeenRef = fromAlice ? lastSeenFromAliceRef : lastSeenFromBobRef
    if (isReplay(seq, lastSeenRef.current)) {
      return {
        ok: false,
        reason: `✕ Replay detected — seqNum ${seq} already seen, discarding`,
        counterAfter: lastSeenRef.current, // rejected — counter does NOT advance
      }
    }

    lastSeenRef.current = seq
    setCounter(seq) // reactive mirror, so the counter visibly ticks up next to the message
    const text = await decryptMessage(aesKey, ivHex, ciphertextB64)
    return { ok: true, text, counterAfter: seq }
  }

  async function sendMsg() {
    const text = input.trim()
    if (!text || status !== 'ready') return

    const ts = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    const id = msgId.current++
    const isAlice = sender === 'alice'
    const aesKey = aesKeyRef.current
    const hmacKey = hmacKeyRef.current

    const seqRef = isAlice ? aliceSeqRef : bobSeqRef
    seqRef.current += 1
    const seq = seqRef.current

    // Encrypt, then compute the MAC over (seq, IV, ciphertext) — the sequence number rides inside
    // the MAC-covered payload, so Eve can't strip or alter it without invalidating the tag.
    const { ivHex, ciphertextB64, ciphertextBytes } = await encryptMessage(aesKey, text)
    const macBytes = encodeForMacWithSeq(seq, ivHex, ciphertextB64)
    const tagHex = await computeHmacHex(hmacKey, macBytes)

    const delivered = await deliverMessage({ seq, ivHex, ciphertextB64, tagHex, fromAlice: isAlice })

    const sentMsg = { id, type: 'sent', text }
    const deliveredMsg = delivered.ok
      ? { id: id + 0.1, type: 'received', text: delivered.text, verified: true, seq, ok: true, counterAfter: delivered.counterAfter }
      : { id: id + 0.1, type: 'rejected', text: delivered.reason, verified: false, seq, ok: false, counterAfter: delivered.counterAfter }
    const eveMsg = {
      id: id + 0.2,
      type: 'attacker',
      sender,
      ts,
      seq,
      ciphertextB64,
      ivHex,
      tagHex,
      bytes: ciphertextBytes,
      fromAlice: isAlice,
    }

    if (isAlice) {
      setAliceMsgs(prev => [...prev, sentMsg])
      setBobMsgs(prev => [...prev, deliveredMsg])
    } else {
      setBobMsgs(prev => [...prev, sentMsg])
      setAliceMsgs(prev => [...prev, deliveredMsg])
    }

    setEveMsgs(prev => [...prev, eveMsg])
    setInput('')
  }

  // The attack this level demonstrates: Eve re-sends a captured, completely untampered message.
  // Its HMAC tag verifies fine — nothing was altered — but the sequence check now rejects it anyway.
  async function replayCaptured(m) {
    const result = await deliverMessage({
      seq: m.seq,
      ivHex: m.ivHex,
      ciphertextB64: m.ciphertextB64,
      tagHex: m.tagHex,
      fromAlice: m.fromAlice,
    })

    const id = msgId.current++
    const replayedMsg = result.ok
      ? { id, type: 'received', text: result.text, verified: true, seq: m.seq, ok: true, counterAfter: result.counterAfter }
      : { id, type: 'rejected', text: result.reason, verified: false, seq: m.seq, ok: false, counterAfter: result.counterAfter }

    if (m.fromAlice) {
      setBobMsgs(prev => [...prev, replayedMsg])
    } else {
      setAliceMsgs(prev => [...prev, replayedMsg])
    }

    addEve(
      `↻ Replayed FROM: ${m.sender.toUpperCase()} seqNum ${m.seq} — ` +
      (result.ok ? 'accepted (!)' : 'rejected by sequence check'),
      'capture'
    )
  }

  function handleKey(e) {
    if (e.key === 'Enter') sendMsg()
  }

  const busy = status === 'exchanging' || status === 'identities'

  return (
    <div className="level6">

      <div className="identity-panel">
        <div className="identity-item">
          <i className="ti ti-shield-check" aria-hidden="true" />
          <span className="identity-label">Alice's identity key</span>
          <code className="identity-value">{aliceFingerprint || 'generating…'}</code>
        </div>
        <div className="identity-item">
          <i className="ti ti-shield-check" aria-hidden="true" />
          <span className="identity-label">Bob's identity key</span>
          <code className="identity-value">{bobFingerprint || 'generating…'}</code>
        </div>
        <span className="identity-caveat">
          Long-term identity private keys known to both parties in advance — Eve never has a copy of either.
        </span>
      </div>

      <div className="handshake-bar">
        <div className="handshake-label">
          <i className="ti ti-stack-2" aria-hidden="true" />
          Defence in depth — all five layers {
            status === 'ready' ? 'active' :
            status === 'failed' ? '— FAILED (signature invalid)' :
            '— setting up…'
          }
        </div>
        <button className="handshake-redo" onClick={runHandshake} disabled={busy}>
          New exchange
        </button>
      </div>

      <div className="chat-area">

        <div className="chat-col">
          <div className="col-heading-row">
            <h3 className="col-heading">Alice</h3>
            <span className="counter-chip">Bob's Last Seen: <strong>{lastSeenFromBob}</strong></span>
          </div>
          <div className="messages" ref={aliceScrollRef}>
            {aliceMsgs.map(m => (
              <div key={m.id} className={`msg ${m.type}`}>
                {m.text}
                {m.type === 'received' && <span className="mac-badge">✓ verified &amp; fresh</span>}
                {typeof m.seq === 'number' && (
                  <span className={`seq-badge ${m.ok ? 'match' : 'mismatch'}`}>
                    seqNum {m.seq} {m.ok ? '=' : '✕'} counter {m.counterAfter}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>

        <div className="attacker-col">
          <div className="sniff-indicator">
            <div className="dot" /> Eve (eavesdropping)
          </div>
          <h3 className="col-heading eve">Intercepted</h3>
          <div className="messages" ref={eveScrollRef}>
            {eveMsgs.map(m => {
              if (m.type === 'attacker') {
                return (
                  <div key={m.id} className="msg attacker">
                    [{m.ts}] FROM: {m.sender.toUpperCase()} · SEQNUM{m.seq} · {m.bytes}B<br />
                    <span className="cipher-label">IV</span> {m.ivHex}<br />
                    <span className="cipher-label">CT</span> {m.ciphertextB64}<br />
                    <span className="cipher-label">TAG</span> {macShortHex(m.tagHex, 24)}
                    <div className="cannot-read">✕ cannot read plaintext, cannot forge a valid tag</div>
                    <button className="replay-btn" onClick={() => replayCaptured(m)} disabled={status !== 'ready'}>
                      <i className="ti ti-repeat" aria-hidden="true" /> Replay this message
                    </button>
                  </div>
                )
              }
              return <div key={m.id} className="msg capture">{m.text}</div>
            })}
          </div>
        </div>

        <div className="chat-col">
          <div className="col-heading-row">
            <h3 className="col-heading">Bob</h3>
            <span className="counter-chip">Alice's Last Seen: <strong>{lastSeenFromAlice}</strong></span>
          </div>
          <div className="messages" ref={bobScrollRef}>
            {bobMsgs.map(m => (
              <div key={m.id} className={`msg ${m.type}`}>
                {m.text}
                {m.type === 'received' && <span className="mac-badge">✓ verified &amp; fresh</span>}
                {typeof m.seq === 'number' && (
                  <span className={`seq-badge ${m.ok ? 'match' : 'mismatch'}`}>
                    seqNum {m.seq} {m.ok ? '=' : '✕'} counter {m.counterAfter}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>

      </div>

      <div className="input-row">
        <select value={sender} onChange={e => setSender(e.target.value)}>
          <option value="alice">Alice</option>
          <option value="bob">Bob</option>
        </select>
        <input
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKey}
          placeholder={status === 'ready' ? 'Type a message — encrypted, tagged, and sequenced…' : 'Setting up all five layers…'}
          disabled={status !== 'ready'}
        />
        <button onClick={sendMsg} disabled={status !== 'ready'}>Send</button>
      </div>

      <div className="info-panel">
        <h4>What's happening</h4>
        <p>
          Every layer from Levels 2–5 is active here: Diffie-Hellman gives Alice and Bob a shared
          secret Eve can't derive; ECDSA signatures on the DH values stop her from impersonating
          either side; AES-256-CTR hides message content; HMAC-SHA256 (keyed independently of the
          AES key) catches any altered ciphertext that CTR mode alone would silently accept.
        </p>
      </div>
    </div>
  )
}

export default Level6