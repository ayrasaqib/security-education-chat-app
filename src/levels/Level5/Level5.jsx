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
  encodeForMac,
  shortHex as macShortHex,
} from '../../utils/hmac'
import { forgeSubstituteKeys, verifyForgedValues } from '../../utils/mitm'
import { tamperCiphertextB64 } from '../../utils/tamper'
import { useAttackPanel } from '../../hooks/useAttackPanel'
import AttackPanel from '../../components/AttackPanel'
import './Level5.css'

const STEP_DELAY_MS = 550

const ATTACKS = [
  { id: 'mitm', label: 'MITM / Impersonation', available: true },
  { id: 'tampering', label: 'Tampering', available: true },
  { id: 'replay', label: 'Replay', available: true },
]

function Level5() {
  const [aliceMsgs, setAliceMsgs] = useState([])
  const [bobMsgs, setBobMsgs] = useState([])
  const [eveMsgs, setEveMsgs] = useState([])
  const [input, setInput] = useState('')
  const [sender, setSender] = useState('alice')
  const [status, setStatus] = useState('identities') // 'identities' | 'exchanging' | 'ready' | 'failed'
  const [aliceFingerprint, setAliceFingerprint] = useState('')
  const [bobFingerprint, setBobFingerprint] = useState('')
  const [tamperingEnabled, setTamperingEnabled] = useState(false)
  const [replayEnabled, setReplayEnabled] = useState(false)
  const [pendingTamperMsgs, setPendingTamperMsgs] = useState([]) // messages Eve is holding, awaiting forward decision

  const {
    selectedAttackId, setSelectedAttackId, attackRunning, attackResult, setAttackResult, runAttack,
  } = useAttackPanel()

  const aliceIdentityRef = useRef(null) // long-term ECDSA keypair, generated once
  const bobIdentityRef = useRef(null)
  const aesKeyRef = useRef(null)  // derived per exchange — confidentiality
  const hmacKeyRef = useRef(null) // derived per exchange — integrity, kept separate from aesKeyRef

  const msgId = useRef(1)
  const runIdRef = useRef(0) // guards against a stale run still writing state after "New exchange" or unmount
  const aliceScrollRef = useRef(null)
  const bobScrollRef = useRef(null)
  const eveScrollRef = useRef(null)

  useEffect(() => {
    if (aliceScrollRef.current) aliceScrollRef.current.scrollTop = aliceScrollRef.current.scrollHeight
  }, [aliceMsgs])

  useEffect(() => {
    if (bobScrollRef.current) bobScrollRef.current.scrollTop = bobScrollRef.current.scrollHeight
  }, [bobMsgs])

  useEffect(() => {
    if (eveScrollRef.current) eveScrollRef.current.scrollTop = eveScrollRef.current.scrollHeight
  }, [eveMsgs, pendingTamperMsgs])

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

  async function runHandshake(underAttack) {
    const myRun = ++runIdRef.current
    const stale = () => runIdRef.current !== myRun

    setStatus('exchanging')
    setAliceMsgs([])
    setBobMsgs([])
    setEveMsgs([])
    setAttackResult(null)
    setTamperingEnabled(false)
    setReplayEnabled(false)
    setPendingTamperMsgs([])

    const aliceIdentity = aliceIdentityRef.current
    const bobIdentity = bobIdentityRef.current

    // 1. Agree on public DH parameters
    addAlice(`Agreed public parameters — p (2048-bit prime), g = ${GENERATOR}`)
    addBob(`Agreed public parameters — p (2048-bit prime), g = ${GENERATOR}`)
    addEve(`Intercepted: p (2048-bit), g = ${GENERATOR}`)
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    // 2. Each side generates a fresh temporary DH keypair for this session
    addAlice('Generating private value a…')
    addBob('Generating private value b…')
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    const alice = generateDHKeyPair()
    const bob = generateDHKeyPair()
    addAlice(`Computing A = g^a mod p = ${shortHex(alice.publicKey)}`)
    addBob(`Computing B = g^b mod p = ${shortHex(bob.publicKey)}`)
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    // 3. Each side signs its own DH public value with its long-term identity private key
    addAlice('Signing A with my identity private key…')
    addBob('Signing B with my identity private key…')
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

    let forged = null

    if (underAttack) {
      // Same move as Level 4: substitute forged DH values, but the only signatures Eve has
      // were computed over the real ones — she has neither identity's private key.
      forged = forgeSubstituteKeys()

      addEve('Substituting forged public values before forwarding — reusing the only signatures available (over the real values)')
      await sleep(STEP_DELAY_MS)
      if (stale()) return

      addBob(`Received "A" from Alice = ${shortHex(forged.forBob.publicKey, 16)}  (this is actually Eve's)`)
      addAlice(`Received "B" from Bob = ${shortHex(forged.forAlice.publicKey, 16)}  (this is actually Eve's)`)
      await sleep(STEP_DELAY_MS)
      if (stale()) return
    }

    // 5. Each side verifies the signature against the sender's known identity public key
    const { aliceVerifiedBob, bobVerifiedAlice } = underAttack
      ? await verifyForgedValues({
          forged,
          sigA,
          sigB,
          aliceIdentityPublicKey: aliceIdentity.publicKey,
          bobIdentityPublicKey: bobIdentity.publicKey,
        })
      : {
          aliceVerifiedBob: await verifyBytes(bobIdentity.publicKey, sigB, bBytes),
          bobVerifiedAlice: await verifyBytes(aliceIdentity.publicKey, sigA, aBytes),
        }

    addAlice(
      aliceVerifiedBob
        ? "✓ Verified B's signature against Bob's known identity key"
        : "✕ Signature verification FAILED — public value received doesn't match what was signed — rejecting"
    )
    addBob(
      bobVerifiedAlice
        ? "✓ Verified A's signature against Alice's known identity key"
        : "✕ Signature verification FAILED — public value received doesn't match what was signed — rejecting"
    )
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    if (!aliceVerifiedBob || !bobVerifiedAlice) {
      if (underAttack) {
        setAttackResult({ type: 'blocked', text: 'Attack blocked: cannot forge valid signature for substituted value' })
      }
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

    // 7. Derive TWO independent keys from the same shared secret — one per control.
    //    Confidentiality (AES) and integrity (HMAC) are kept separate on purpose: a mechanism
    //    that only encrypts says nothing about whether ciphertext was altered in transit.
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
    addEve('Can see ciphertext and MAC tags on every message, but has neither key — cannot forge a tag that will verify')
    await sleep(400)
    if (stale()) return

    addAlice('Secure, authenticated, integrity-protected channel ready — you can chat now.', 'ready-note')
    addBob('Secure, authenticated, integrity-protected channel ready — you can chat now.', 'ready-note')
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
      runHandshake(false)
    })()
    return () => { cancelled = true; runIdRef.current++ } // invalidate any in-flight run on unmount
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  function runMitmAttack() {
    if (selectedAttackId !== 'mitm') return
    runAttack(() => runHandshake(true))
  }

  function runTamperingAttack() {
    if (selectedAttackId !== 'tampering') return
    runAttack(async () => {
      await runHandshake(false)
      setTamperingEnabled(true)
    })
  }

  function runReplayAttack() {
    if (selectedAttackId !== 'replay') return
    runAttack(async () => {
      await runHandshake(false)
      setReplayEnabled(true)
    })
  }

  function runSelectedAttack() {
    if (selectedAttackId === 'mitm') runMitmAttack()
    else if (selectedAttackId === 'tampering') runTamperingAttack()
    else if (selectedAttackId === 'replay') runReplayAttack()
  }

  // This is the gap Level 6 closes: HMAC proves the bytes weren't altered, but says nothing
  // about whether they've been seen before. Replaying a captured message untouched reproduces
  // the exact same tag, so it verifies and decrypts exactly like the first time. The outcome is
  // logged in Eve's panel — there's no badge on Bob's bubble either way, since a valid HMAC on a
  // replay looks identical to a valid HMAC on an original message from where he's sitting.
  async function replayCaptured(m) {
    const hmacKey = hmacKeyRef.current
    const aesKey = aesKeyRef.current
    const macBytes = encodeForMac(m.ivHex, m.ciphertextB64)
    const integrityOk = await verifyHmacHex(hmacKey, m.tagHex, macBytes)

    const id = msgId.current++
    if (!integrityOk) {
      const rejectedMsg = { id, type: 'rejected', text: '✕ HMAC verification failed due to tag mismatch — message discarded', verified: false }
      if (m.sender === 'alice') setBobMsgs(prev => [...prev, rejectedMsg])
      else setAliceMsgs(prev => [...prev, rejectedMsg])
      addEve(`↻ Replayed FROM: ${m.sender.toUpperCase()} — rejected, HMAC verification failed`)
      setAttackResult({ type: 'blocked', text: 'Attack blocked: HMAC verification failed' })
      return
    }

    const text = await decryptMessage(aesKey, m.ivHex, m.ciphertextB64)
    const replayedMsg = { id, type: 'received', text, verified: true }
    if (m.sender === 'alice') setBobMsgs(prev => [...prev, replayedMsg])
    else setAliceMsgs(prev => [...prev, replayedMsg])

    addEve(`↻ Replayed FROM: ${m.sender.toUpperCase()} — accepted, HMAC has nothing to say about freshness`)

    setAttackResult({ type: 'success', text: 'Attack succeeded: replayed message accepted despite valid HMAC' })
  }

  // This is the level's whole point: Eve still can't read the message, but now she can't
  // silently corrupt it either. She has no HMAC key, so she can't produce a new tag over her
  // tampered ciphertext — the receiver recomputes the tag over what actually arrived, it
  // won't match the original tag she's stuck reusing, and the message is discarded outright.
  async function forwardPendingTamper(item, corrupt) {
    const hmacKey = hmacKeyRef.current
    const aesKey = aesKeyRef.current
    const finalCiphertext = corrupt ? tamperCiphertextB64(item.ciphertextB64) : item.ciphertextB64

    const macBytes = encodeForMac(item.ivHex, finalCiphertext)
    const computedTag = await computeHmacHex(hmacKey, macBytes)
    const integrityOk = await verifyHmacHex(hmacKey, item.tagHex, macBytes)

    const deliveredMsg = integrityOk
      ? { id: item.id + 0.1, type: 'received', text: await decryptMessage(aesKey, item.ivHex, finalCiphertext), verified: true }
      : {
          id: item.id + 0.1,
          type: 'rejected',
          text: '✕ HMAC verification failed due to tag mismatch — message discarded',
          verified: false,
          sentTag: item.tagHex,
          computedTag,
        }

    if (item.fromAlice) setBobMsgs(prev => [...prev, deliveredMsg])
    else setAliceMsgs(prev => [...prev, deliveredMsg])

    setEveMsgs(prev => [...prev, {
      id: item.id + 0.2,
      type: 'attacker',
      sender: item.fromAlice ? 'alice' : 'bob',
      ts: item.ts,
      ivHex: item.ivHex,
      ciphertextB64: finalCiphertext,
      originalCiphertextB64: item.ciphertextB64,
      tagHex: item.tagHex,
      bytes: item.bytes,
      note: corrupt ? 'CORRUPTED before relay' : 'unmodified',
    }])

    setPendingTamperMsgs(prev => prev.filter(p => p.id !== item.id))

    if (corrupt) {
      setAttackResult(
        integrityOk
          ? { type: 'success', text: 'Attack succeeded: altered message accepted' }
          : { type: 'blocked', text: 'Attack blocked: HMAC verification failed' }
      )
    }
  }

  async function sendMsg() {
    const text = input.trim()
    if (!text || status !== 'ready') return

    const ts = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    const id = msgId.current++
    const aesKey = aesKeyRef.current
    const hmacKey = hmacKeyRef.current
    const isAlice = sender === 'alice'

    // Encrypt first, then compute the MAC over the ciphertext — the tag protects exactly what
    // goes over the wire, so it can be checked before any decryption is attempted.
    const { ivHex, ciphertextB64, ciphertextBytes } = await encryptMessage(aesKey, text)
    const macBytes = encodeForMac(ivHex, ciphertextB64)
    const tagHex = await computeHmacHex(hmacKey, macBytes)

    const sentMsg = { id, type: 'sent', text }
    if (isAlice) setAliceMsgs(prev => [...prev, sentMsg])
    else setBobMsgs(prev => [...prev, sentMsg])

    if (tamperingEnabled) {
      setPendingTamperMsgs(prev => [...prev, {
        id: id + 0.05, fromAlice: isAlice, ts, ivHex, ciphertextB64, tagHex, bytes: ciphertextBytes,
      }])
      setInput('')
      return
    }

    // Receiver's side of the integrity check: recompute the tag over what actually arrived and
    // compare, before calling decrypt.
    const integrityOk = await verifyHmacHex(hmacKey, tagHex, macBytes)
    const decrypted = integrityOk
      ? await decryptMessage(aesKey, ivHex, ciphertextB64)
      : null

    const deliveredMsg = integrityOk
      ? { id: id + 0.1, type: 'received', text: decrypted, verified: true }
      : { id: id + 0.1, type: 'rejected', text: '✕ HMAC verification failed due to tag mismatch — message discarded', verified: false }
    const eveMsg = {
      id: id + 0.2,
      type: 'attacker',
      sender,
      ts,
      ciphertextB64,
      ivHex,
      tagHex,
      bytes: ciphertextBytes,
    }

    if (isAlice) {
      setBobMsgs(prev => [...prev, deliveredMsg])
    } else {
      setAliceMsgs(prev => [...prev, deliveredMsg])
    }

    setEveMsgs(prev => [...prev, eveMsg])
    setInput('')
  }

  function handleKey(e) {
    if (e.key === 'Enter') sendMsg()
  }

  const busy = status === 'exchanging' || status === 'identities'

  return (
    <div className="level5">

      <div className="handshake-bar">
        <div className="handshake-label">
          <i className="ti ti-arrows-exchange" aria-hidden="true" />
          Authenticated DH + integrity key setup {
            status === 'ready' ? '— complete' :
            status === 'failed' ? '— FAILED (signature invalid)' :
            '— in progress…'
          }
        </div>
        <button className="handshake-redo" onClick={() => runHandshake(false)} disabled={busy}>
          New exchange
        </button>
      </div>

      <AttackPanel
        attacks={ATTACKS}
        selectedAttackId={selectedAttackId}
        onSelect={setSelectedAttackId}
        onRun={runSelectedAttack}
        running={attackRunning}
        disabled={attackRunning || busy}
        result={attackResult}
      />

      <div className="chat-area">

        <div className="chat-col">
          <div className="col-heading-row">
            <h3 className="col-heading">Alice</h3>
            <span className="identity-chip">
              <i className="ti ti-shield-check" aria-hidden="true" /> {aliceFingerprint || 'generating…'}
            </span>
          </div>
          <div className="messages" ref={aliceScrollRef}>
            {aliceMsgs.map(m => (
              <div key={m.id} className={`msg ${m.type}`}>
                {m.text}
                {m.type === 'received' && <span className="mac-badge">✓ HMAC verified</span>}
                {m.type === 'rejected' && m.sentTag && (
                  <div className="tag-mismatch">
                    <span className="cipher-label">SENT TAG</span> {macShortHex(m.sentTag, 24)}<br />
                    <span className="cipher-label">COMPUTED</span> {macShortHex(m.computedTag, 24)}
                  </div>
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
                // Blind tampering flips a bit in place — it never re-encrypts, so the IV never changes
                // and ciphertext equality reliably means "unmodified".
                const showCtDiff = m.note !== undefined && m.note !== 'unmodified'
                return (
                  <div key={m.id} className="msg attacker">
                    [{m.ts}] FROM: {m.sender.toUpperCase()} · {m.bytes}B{m.note ? ` · ${m.note}` : ''}<br />
                    <span className="cipher-label">IV</span> {m.ivHex}<br />
                    {showCtDiff ? (
                      <>
                        <span className="text-diff-label">CT (captured)</span> {m.originalCiphertextB64}<br />
                        <span className="text-diff-label">CT (sent)</span> {m.ciphertextB64}<br />
                      </>
                    ) : (
                      <>
                        <span className="cipher-label">CT</span> {m.ciphertextB64}<br />
                      </>
                    )}
                    <span className="cipher-label">TAG</span> {macShortHex(m.tagHex, 24)}
                    {replayEnabled && (
                      <button className="replay-btn" onClick={() => replayCaptured(m)}>
                        <i className="ti ti-repeat" aria-hidden="true" /> Replay this message
                      </button>
                    )}
                  </div>
                )
              }
              return <div key={m.id} className="msg capture">{m.text}</div>
            })}

            {pendingTamperMsgs.map(item => (
              <div key={item.id} className="intercept-card">
                <div className="intercept-meta">
                  [{item.ts}] FROM: {(item.fromAlice ? 'alice' : 'bob').toUpperCase()} · {item.bytes}B — held, awaiting forward decision
                </div>
                <div className="intercept-ciphertext">
                  <span className="cipher-label">IV</span> {item.ivHex}<br />
                  <span className="cipher-label">CT</span> {item.ciphertextB64}<br />
                  <span className="cipher-label">TAG</span> {macShortHex(item.tagHex, 24)}
                </div>
                <div className="intercept-actions">
                  <button className="forward-btn" onClick={() => forwardPendingTamper(item, false)}>
                    <i className="ti ti-send" aria-hidden="true" /> Forward unmodified
                  </button>
                  <button className="tamper-btn" onClick={() => forwardPendingTamper(item, true)}>
                    <i className="ti ti-edit" aria-hidden="true" /> Corrupt &amp; forward
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="chat-col">
          <div className="col-heading-row">
            <h3 className="col-heading">Bob</h3>
            <span className="identity-chip">
              <i className="ti ti-shield-check" aria-hidden="true" /> {bobFingerprint || 'generating…'}
            </span>
          </div>
          <div className="messages" ref={bobScrollRef}>
            {bobMsgs.map(m => (
              <div key={m.id} className={`msg ${m.type}`}>
                {m.text}
                {m.type === 'received' && <span className="mac-badge">✓ HMAC verified</span>}
                {m.type === 'rejected' && m.sentTag && (
                  <div className="tag-mismatch">
                    <span className="cipher-label">SENT TAG</span> {macShortHex(m.sentTag, 24)}<br />
                    <span className="cipher-label">COMPUTED</span> {macShortHex(m.computedTag, 24)}
                  </div>
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
          placeholder={status === 'ready' ? 'Type a message — encrypted, then HMAC-tagged…' : 'Setting up encryption + integrity keys…'}
          disabled={status !== 'ready'}
        />
        <button onClick={sendMsg} disabled={status !== 'ready'}>Send</button>
      </div>

      <div className="info-panel">
        <h4>What's happening</h4>
        <p>
          Every message is encrypted, then a separate HMAC-SHA256 tag is computed over the IV and
          ciphertext using a key derived independently from the same DH secret. The receiver
          recomputes that tag over whatever actually arrived and compares it before attempting to
          decrypt — a message whose ciphertext was altered in transit would produce a different tag
          and be rejected outright, rather than silently decrypting to garbage. Confidentiality
          (AES) and integrity (HMAC) are deliberately separate controls here: encryption alone only
          hides content, it doesn't guarantee that content wasn't changed after the fact. Select
          Tampering above and run it, then send a message: it pauses at Eve first, and choosing
          "Corrupt &amp; forward" shows exactly why it's rejected — the tag Bob computes over what
          actually arrived doesn't match the tag that came with the message, unlike Levels 2-4
          where Eve's edit reaches decryption unnoticed. HMAC has nothing to say about freshness,
          though — select Replay instead and every captured message gets a "Replay this message"
          button. Resending the exact same IV, ciphertext, and tag reproduces a tag that verifies
          perfectly, so it's accepted all over again. Level 6 closes exactly this gap with sequence
          numbers.
        </p>
      </div>
    </div>
  )
}

export default Level5