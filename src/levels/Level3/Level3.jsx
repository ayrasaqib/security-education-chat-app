import { useState, useRef, useEffect } from 'react'
import { encryptMessage, decryptMessage } from '../../utils/crypto'
import { generateDHKeyPair, computeSharedSecret, deriveAesKeyFromSharedSecret, shortHex, PRIME, GENERATOR } from '../../utils/dh'
import { forgeSubstituteKeys, deriveMitmKeys } from '../../utils/mitm'
import { tamperCiphertextB64 } from '../../utils/tamper'
import { useAttackPanel } from '../../hooks/useAttackPanel'
import AttackPanel from '../../components/AttackPanel'
import './Level3.css'

const STEP_DELAY_MS = 550

const ATTACKS = [
  { id: 'mitm', label: 'MITM / Impersonation', available: true },
  { id: 'tampering', label: 'Tampering', available: true },
  { id: 'replay', label: 'Replay', available: true },
]

function Level3() {
  const [aliceMsgs, setAliceMsgs] = useState([])
  const [bobMsgs, setBobMsgs] = useState([])
  const [eveMsgs, setEveMsgs] = useState([])
  const [input, setInput] = useState('')
  const [sender, setSender] = useState('alice')
  const [status, setStatus] = useState('exchanging') // 'exchanging' | 'ready'
  const [compromised, setCompromised] = useState(false) // true once Eve has separately keyed sessions with both sides
  const [pendingIntercepts, setPendingIntercepts] = useState([]) // messages Eve is holding, awaiting forward/edit (MITM)
  const [pendingTamperMsgs, setPendingTamperMsgs] = useState([]) // messages Eve is holding, awaiting forward decision (tampering)
  const [tamperingEnabled, setTamperingEnabled] = useState(false)
  const [replayEnabled, setReplayEnabled] = useState(false)

  const {
    selectedAttackId, setSelectedAttackId, attackRunning, attackResult, setAttackResult, runAttack,
  } = useAttackPanel()

  // Baseline (no attack): one key shared directly between Alice and Bob.
  const keyRef = useRef(null)
  // Under attack: three keys instead of one — Alice⇄Eve, Bob⇄Eve, and Eve holds both.
  const aliceKeyRef = useRef(null) // Alice's key — she believes this is shared with Bob
  const bobKeyRef = useRef(null)   // Bob's key — he believes this is shared with Alice
  const eveKeyWithAliceRef = useRef(null) // Eve's matching key for the Alice-facing session
  const eveKeyWithBobRef = useRef(null)   // Eve's matching key for the Bob-facing session

  const msgId = useRef(1)
  const runIdRef = useRef(0) // guards against a stale run still writing state after a re-run or unmount
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
  }, [eveMsgs, pendingIntercepts, pendingTamperMsgs])

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
    setPendingIntercepts([])
    setPendingTamperMsgs([])
    setCompromised(false)
    setAttackResult(null)
    setTamperingEnabled(false)
    setReplayEnabled(false)
    keyRef.current = null
    aliceKeyRef.current = null
    bobKeyRef.current = null
    eveKeyWithAliceRef.current = null
    eveKeyWithBobRef.current = null

    // 1. Agree on public parameters
    addAlice(`Agreed public parameters — p (2048-bit prime), g = ${GENERATOR}`)
    addBob(`Agreed public parameters — p (2048-bit prime), g = ${GENERATOR}`)
    addEve(`Intercepted: p = ${shortHex(PRIME, 16)}, g = ${GENERATOR}`)
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    // 2. Each side generates a private exponent, locally, never transmitted
    addAlice('Generating private value a…')
    addBob('Generating private value b…')
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    const alice = generateDHKeyPair()
    const bob = generateDHKeyPair()
    addAlice(`a = ${shortHex(alice.privateKey)}  (kept secret)`)
    addBob(`b = ${shortHex(bob.privateKey)}  (kept secret)`)
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    // 3. Each side computes its public value
    addAlice(`Computing A = g^a mod p = ${shortHex(alice.publicKey)}`)
    addBob(`Computing B = g^b mod p = ${shortHex(bob.publicKey)}`)
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    if (!underAttack) {
      // ── Baseline: Eve only ever sees the real public values, passively ──
      addAlice('Sending A to Bob →')
      addBob('Sending B to Alice →')
      addEve(`Intercepted A = ${shortHex(alice.publicKey, 16)}`)
      addEve(`Intercepted B = ${shortHex(bob.publicKey, 16)}`)
      await sleep(STEP_DELAY_MS)
      if (stale()) return

      addAlice(`Received B from Bob = ${shortHex(bob.publicKey)}`)
      addBob(`Received A from Alice = ${shortHex(alice.publicKey)}`)
      await sleep(STEP_DELAY_MS)
      if (stale()) return

      const sharedAlice = computeSharedSecret(alice.privateKey, bob.publicKey)
      const sharedBob = computeSharedSecret(bob.privateKey, alice.publicKey)
      const matches = sharedAlice === sharedBob

      addAlice(`Computing s = B^a mod p = ${shortHex(sharedAlice)}`)
      addBob(`Computing s = A^b mod p = ${shortHex(sharedBob)}`)
      await sleep(STEP_DELAY_MS)
      if (stale()) return

      addAlice(matches ? '✓ Shared secret matches Bob\u2019s' : '✕ shared secret mismatch')
      addBob(matches ? '✓ Shared secret matches Alice\u2019s' : '✕ shared secret mismatch')
      addEve('Has p, g, A, B — cannot derive s without solving the discrete log problem')
      await sleep(STEP_DELAY_MS)
      if (stale()) return

      addAlice('Deriving AES-256 key = SHA-256(s)…')
      addBob('Deriving AES-256 key = SHA-256(s)…')
      const aesKey = await deriveAesKeyFromSharedSecret(sharedAlice)
      if (stale()) return
      keyRef.current = aesKey
      await sleep(400)
      if (stale()) return

      addAlice('Secure channel ready — you can chat now.', 'ready-note')
      addBob('Secure channel ready — you can chat now.', 'ready-note')
      setStatus('ready')
      return
    }

    // ── Under attack: Eve intercepts both public values and substitutes her own ──
    // She never lets Alice and Bob's real public values reach each other. Instead she
    // maintains two independent DH keypairs — one to fool Alice, one to fool Bob.
    const forged = forgeSubstituteKeys()

    addAlice('Sending A to Bob →')
    addBob('Sending B to Alice →')
    addEve(`Intercepted A = ${shortHex(alice.publicKey, 16)} — substituting a forged value before forwarding to Bob`)
    addEve(`Intercepted B = ${shortHex(bob.publicKey, 16)} — substituting a forged value before forwarding to Alice`)
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    addBob(`Received "A" from Alice (Eve) = ${shortHex(forged.forBob.publicKey)}`)
    addAlice(`Received "B" from Bob (Eve) = ${shortHex(forged.forAlice.publicKey)}`)
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    // Alice and Bob each compute a shared secret — but with Eve, not each other.
    const {
      aliceKey, bobKey, eveKeyWithAlice, eveKeyWithBob, eveSharedWithAlice, eveSharedWithBob,
    } = await deriveMitmKeys({ alice, bob, forged })
    if (stale()) return

    addAlice(`Computing s = B^a mod p = ${shortHex(eveSharedWithAlice)}`)
    addBob(`Computing s = A^b mod p = ${shortHex(eveSharedWithBob)}`)
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    addAlice('✓ Shared secret established — believes this is with Bob')
    addBob('✓ Shared secret established — believes this is with Alice')
    addEve(
      `Derived TWO separate shared secrets. One with Alice (${shortHex(eveSharedWithAlice, 12)}). ` +
      `One with Bob (${shortHex(eveSharedWithBob, 12)}). Neither matches the other.`
    )
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    addAlice('Deriving AES-256 key = SHA-256(s)…')
    addBob('Deriving AES-256 key = SHA-256(s)…')
    aliceKeyRef.current = aliceKey
    bobKeyRef.current = bobKey
    eveKeyWithAliceRef.current = eveKeyWithAlice
    eveKeyWithBobRef.current = eveKeyWithBob
    setCompromised(true)
    setAttackResult({ type: 'success', text: 'Attack succeeded: messages pass through Eve' })

    await sleep(400)
    if (stale()) return

    addAlice('Channel "ready"', 'ready-note')
    addBob('Channel "ready"', 'ready-note')
    setStatus('ready')
  }

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    runHandshake(false)
    // eslint-disable-next-line react-hooks/exhaustive-deps
    return () => { runIdRef.current++ } // invalidate any in-flight run on unmount
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

  // Runs the baseline (non-MITM) handshake, same as tampering — the Eve-in-the-middle keys
  // from a MITM run aren't what replay is demonstrating here.
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

  // DH gives confidentiality but nothing here checks freshness — decrypting the same captured
  // IV/ciphertext a second time with the same shared key just produces the same plaintext again.
  // The outcome is logged in Eve's panel, not on the message itself — Bob's client has no way
  // to know it's a repeat.
  async function replayCaptured(m) {
    const key = keyRef.current
    const text = await decryptMessage(key, m.ivHex, m.ciphertextB64)
    const id = msgId.current++
    const replayedMsg = { id, type: 'received', text }
    if (m.sender === 'alice') setBobMsgs(prev => [...prev, replayedMsg])
    else setAliceMsgs(prev => [...prev, replayedMsg])

    addEve(`↻ Replayed FROM: ${m.sender.toUpperCase()} — accepted, nothing here tracks what's already been delivered`)

    setAttackResult({ type: 'success', text: 'Attack succeeded: replayed message accepted' })
  }

  async function sendMsg() {
    const text = input.trim()
    if (!text || status !== 'ready') return

    const ts = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    const id = msgId.current++
    const isAlice = sender === 'alice'

    if (compromised) {
      // Encrypt with the sender's own (Eve-facing) key, then hand it straight to Eve
      // for review rather than delivering it — she decides what, if anything, arrives.
      const myKey = isAlice ? aliceKeyRef.current : bobKeyRef.current
      const eveDecryptKey = isAlice ? eveKeyWithAliceRef.current : eveKeyWithBobRef.current
      const { ivHex, ciphertextB64, ciphertextBytes } = await encryptMessage(myKey, text)
      const plaintext = await decryptMessage(eveDecryptKey, ivHex, ciphertextB64)

      const sentMsg = { id, type: 'sent', text }
      if (isAlice) setAliceMsgs(prev => [...prev, sentMsg])
      else setBobMsgs(prev => [...prev, sentMsg])

      setPendingIntercepts(prev => [...prev, {
        id: id + 0.05,
        fromAlice: isAlice,
        ts,
        originalText: plaintext,
        editedText: plaintext,
        bytes: ciphertextBytes,
        ivHex,
        ciphertextB64,
      }])
      setInput('')
      return
    }

    // Baseline (no attack): single shared key.
    const key = keyRef.current
    const { ivHex, ciphertextB64, ciphertextBytes } = await encryptMessage(key, text)

    const sentMsg = { id, type: 'sent', text }
    if (isAlice) setAliceMsgs(prev => [...prev, sentMsg])
    else setBobMsgs(prev => [...prev, sentMsg])

    if (tamperingEnabled) {
      setPendingTamperMsgs(prev => [...prev, {
        id: id + 0.05, fromAlice: isAlice, ts, ivHex, ciphertextB64, bytes: ciphertextBytes,
      }])
      setInput('')
      return
    }

    const decrypted = await decryptMessage(key, ivHex, ciphertextB64)
    const deliveredMsg = { id: id + 0.1, type: 'received', text: decrypted }
    const eveMsg = {
      id: id + 0.2,
      type: 'attacker',
      sender,
      ts,
      ciphertextB64,
      ivHex,
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

  function updateIntercept(id, newText) {
    setPendingIntercepts(prev => prev.map(p => (p.id === id ? { ...p, editedText: newText } : p)))
  }

  // Eve holds both sides' keys, so she isn't blindly flipping bits — she can retype the message
  // itself before re-encrypting for the recipient. The outcome (and both ciphertexts, since a
  // fresh encryption always produces a new one) goes in Eve's panel, not as a badge on Bob's or
  // Alice's bubble — neither of them has any way to see this happened.
  async function forwardIntercept(item) {
    const outgoingKey = item.fromAlice ? eveKeyWithBobRef.current : eveKeyWithAliceRef.current
    const recipientKey = item.fromAlice ? bobKeyRef.current : aliceKeyRef.current

    const { ivHex, ciphertextB64 } = await encryptMessage(outgoingKey, item.editedText)
    const delivered = await decryptMessage(recipientKey, ivHex, ciphertextB64)

    const wasEdited = item.editedText !== item.originalText
    const deliveredMsg = { id: item.id + 0.1, type: 'received', text: delivered }

    if (item.fromAlice) setBobMsgs(prev => [...prev, deliveredMsg])
    else setAliceMsgs(prev => [...prev, deliveredMsg])

    setEveMsgs(prev => [...prev, {
      id: item.id + 0.2,
      type: 'attacker',
      sender: item.fromAlice ? 'alice' : 'bob',
      ts: item.ts,
      bytes: item.bytes,
      ivHex,
      ciphertextB64,
      originalIvHex: item.ivHex,
      originalCiphertextB64: item.ciphertextB64,
      originalText: item.originalText,
      decrypted: item.editedText,
      note: wasEdited ? 'EDITED before relay' : 'unmodified',
    }])

    setPendingIntercepts(prev => prev.filter(p => p.id !== item.id))
  }

  function handleKey(e) {
    if (e.key === 'Enter') sendMsg()
  }

  // Applies to the baseline shared-key session (not the MITM-compromised one — that already
  // lets Eve edit messages directly). DH gives confidentiality here but nothing checks
  // integrity, so a blind ciphertext flip still decrypts "successfully" to altered content.
  async function forwardPendingTamper(item, corrupt) {
    const key = keyRef.current
    const finalCiphertext = corrupt ? tamperCiphertextB64(item.ciphertextB64) : item.ciphertextB64
    const delivered = await decryptMessage(key, item.ivHex, finalCiphertext)

    const deliveredMsg = { id: item.id + 0.1, type: 'received', text: delivered }
    if (item.fromAlice) setBobMsgs(prev => [...prev, deliveredMsg])
    else setAliceMsgs(prev => [...prev, deliveredMsg])

    setEveMsgs(prev => [...prev, {
      id: item.id + 0.2,
      type: 'attacker',
      sender: item.fromAlice ? 'alice' : 'bob',
      ts: item.ts,
      ivHex: item.ivHex,
      ciphertextB64: finalCiphertext,
      originalIvHex: item.ivHex, // blind tampering only flips ciphertext bytes — the IV itself never changes
      originalCiphertextB64: item.ciphertextB64,
      bytes: item.bytes,
      note: corrupt ? 'CORRUPTED before relay' : 'unmodified',
    }])

    setPendingTamperMsgs(prev => prev.filter(p => p.id !== item.id))

    if (corrupt) {
      setAttackResult({ type: 'success', text: 'Attack succeeded: altered message accepted' })
    }
  }

  const busy = status === 'exchanging'

  return (
    <div className="level3">

      <div className="handshake-bar">
        <div className="handshake-label">
          <i className="ti ti-arrows-exchange" aria-hidden="true" />
          Diffie–Hellman key exchange {
            status === 'exchanging' ? '— in progress…' :
            compromised ? '— complete (compromised)' :
            '— complete'
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
          <h3 className="col-heading">Alice</h3>
          <div className="messages" ref={aliceScrollRef}>
            {aliceMsgs.map(m => (
              <div key={m.id} className={`msg ${m.type}`}>
                {m.text}
              </div>
            ))}
          </div>
        </div>

        <div className="attacker-col">
          <div className="sniff-indicator">
            <div className="dot" /> Eve (eavesdropping{compromised ? ' + MITM active' : ''})
          </div>
          <h3 className="col-heading eve">Intercepted</h3>
          <div className="messages" ref={eveScrollRef}>
            {eveMsgs.map(m => {
              if (m.type === 'attacker') {
                // Blind tampering never touches the IV or re-encrypts, so ciphertext equality is a
                // reliable "was this changed" signal there — but MITM forwards always re-encrypt with
                // a fresh IV (AES-CTR requires it), so raw ciphertext bytes differ even when the
                // plaintext wasn't edited. The plaintext-derived `note` covers both cases correctly.
                const showCtDiff = m.note !== undefined && m.note !== 'unmodified'
                // Blind tampering reuses the same IV in both rows (it never re-encrypts) — repeating
                // it as "captured" vs "sent" would wrongly imply it changed too. MITM forwards do
                // re-encrypt with a fresh IV, so there it's a genuine, worth-showing difference.
                const ivChanged = m.originalIvHex !== undefined && m.originalIvHex !== m.ivHex
                const showTextDiff = m.originalText !== undefined && m.originalText !== m.decrypted
                return (
                  <div key={m.id} className="msg attacker">
                    [{m.ts}] FROM: {m.sender.toUpperCase()} · {m.bytes}B{m.note ? ` · ${m.note}` : ''}<br />
                    {showCtDiff ? (
                      ivChanged ? (
                        <>
                          <span className="text-diff-label">IV/CT (captured)</span> {m.originalIvHex} / {m.originalCiphertextB64}<br />
                          <span className="text-diff-label">IV/CT (sent)</span> {m.ivHex} / {m.ciphertextB64}
                        </>
                      ) : (
                        <>
                          <span className="cipher-label">IV</span> {m.ivHex}<br />
                          <span className="text-diff-label">CT (captured)</span> {m.originalCiphertextB64}<br />
                          <span className="text-diff-label">CT (sent)</span> {m.ciphertextB64}
                        </>
                      )
                    ) : (
                      <>
                        <span className="cipher-label">IV</span> {m.ivHex}<br />
                        <span className="cipher-label">CT</span> {m.ciphertextB64}
                      </>
                    )}
                    {m.decrypted !== undefined && (
                      <div className="decrypted-plaintext">
                        {showTextDiff ? (
                          <>
                            <span className="decrypted-label">Before:</span> {m.originalText}<br />
                            <span className="decrypted-label">After:</span> {m.decrypted}
                          </>
                        ) : (
                          <><span className="decrypted-label">Sent to recipient:</span> {m.decrypted}</>
                        )}
                      </div>
                    )}
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
                  <span className="cipher-label">CT</span> {item.ciphertextB64}
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

            {pendingIntercepts.map(item => (
              <div key={item.id} className="intercept-card">
                <div className="intercept-meta">
                  [{item.ts}] FROM: {(item.fromAlice ? 'alice' : 'bob').toUpperCase()} · {item.bytes}B — decrypted with Eve's key
                </div>
                <textarea
                  className="intercept-textarea"
                  value={item.editedText}
                  onChange={e => updateIntercept(item.id, e.target.value)}
                  rows={2}
                />
                <button className="intercept-forward-btn" onClick={() => forwardIntercept(item)}>
                  <i className="ti ti-send" aria-hidden="true" /> Forward
                  {item.editedText !== item.originalText ? ' (edited)' : ' (unmodified)'}
                </button>
              </div>
            ))}
          </div>
        </div>

        <div className="chat-col">
          <h3 className="col-heading">Bob</h3>
          <div className="messages" ref={bobScrollRef}>
            {bobMsgs.map(m => (
              <div key={m.id} className={`msg ${m.type}`}>
                {m.text}
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
          placeholder={status === 'ready' ? 'Type a message — encrypted with the DH-derived key…' : 'Running key exchange…'}
          disabled={status !== 'ready'}
        />
        <button onClick={sendMsg} disabled={status !== 'ready'}>Send</button>
      </div>

      <div className="info-panel">
        <h4>What's happening</h4>
        <p>
          Alice and Bob each generate a private exponent locally and exchange only public values
          (g^a mod p and g^b mod p) over the network. Nothing here proves *who* sent a given public
          value, though — that's exactly what an attacker can exploit. Select MITM above and run it
          to see Eve intercept both public values and substitute her own, ending up with two separate
          shared secrets — one with Alice, one with Bob — while both of them believe they're talking
          directly to each other. Separately, select Tampering: DH gives confidentiality here, but
          nothing checks integrity. Once enabled, new messages pause at Eve first — try sending one
          and choosing "Corrupt &amp; forward": a blind ciphertext edit still decrypts without error.
          Select Replay and every captured message gets a "Replay this message" button instead —
          nothing here tracks what's already been delivered, so decrypting the same captured
          ciphertext again succeeds just as well the second time.
          Level 4
          fixes the impersonation problem by having each side sign its public value with
          a long-term identity key Eve doesn't have.
        </p>
      </div>
    </div>
  )
}

export default Level3