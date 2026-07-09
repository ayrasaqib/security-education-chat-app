import { useState, useRef, useEffect } from 'react'
import { encryptMessage, decryptMessage } from '../../utils/crypto'
import { generateDHKeyPair, computeSharedSecret, deriveAesKeyFromSharedSecret, shortHex, PRIME, GENERATOR } from '../../utils/dh'
import { forgeSubstituteKeys, deriveMitmKeys } from '../../utils/mitm'
import { useAttackPanel } from '../../hooks/useAttackPanel'
import AttackPanel from '../../components/AttackPanel'
import './Level3.css'

const STEP_DELAY_MS = 550

const ATTACKS = [
  { id: 'mitm', label: 'MITM / Impersonation', available: true },
]

function Level3() {
  const [aliceMsgs, setAliceMsgs] = useState([])
  const [bobMsgs, setBobMsgs] = useState([])
  const [eveMsgs, setEveMsgs] = useState([])
  const [input, setInput] = useState('')
  const [sender, setSender] = useState('alice')
  const [status, setStatus] = useState('exchanging') // 'exchanging' | 'ready'
  const [compromised, setCompromised] = useState(false) // true once Eve has separately keyed sessions with both sides
  const [pendingIntercepts, setPendingIntercepts] = useState([]) // messages Eve is holding, awaiting forward/edit

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
    runHandshake(false)
    // eslint-disable-next-line react-hooks/exhaustive-deps
    return () => { runIdRef.current++ } // invalidate any in-flight run on unmount
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
  }, [eveMsgs, pendingIntercepts])

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
    setCompromised(false)
    setAttackResult(null)
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
      `Derived TWO separate shared secrets — one with Alice (${shortHex(eveSharedWithAlice, 12)}), ` +
      `one with Bob (${shortHex(eveSharedWithBob, 12)}) — neither matches the other`
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
    setAttackResult({ type: 'success', text: 'MITM succeeded' })

    addEve('Man-in-the-middle complete — every message will pass through here')
    await sleep(400)
    if (stale()) return

    addAlice('Channel "ready"', 'ready-note')
    addBob('Channel "ready"', 'ready-note')
    setStatus('ready')
  }

  function runMitmAttack() {
    if (selectedAttackId !== 'mitm') return
    runAttack(() => runHandshake(true))
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
      }])
      setInput('')
      return
    }

    // Baseline (no attack): single shared key, delivered immediately as before.
    const key = keyRef.current
    const { ivHex, ciphertextB64, ciphertextBytes } = await encryptMessage(key, text)
    const decrypted = await decryptMessage(key, ivHex, ciphertextB64)

    const sentMsg = { id, type: 'sent', text }
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
      setAliceMsgs(prev => [...prev, sentMsg])
      setBobMsgs(prev => [...prev, deliveredMsg])
    } else {
      setBobMsgs(prev => [...prev, sentMsg])
      setAliceMsgs(prev => [...prev, deliveredMsg])
    }

    setEveMsgs(prev => [...prev, eveMsg])
    setInput('')
  }

  function updateIntercept(id, newText) {
    setPendingIntercepts(prev => prev.map(p => (p.id === id ? { ...p, editedText: newText } : p)))
  }

  async function forwardIntercept(item) {
    const outgoingKey = item.fromAlice ? eveKeyWithBobRef.current : eveKeyWithAliceRef.current
    const recipientKey = item.fromAlice ? bobKeyRef.current : aliceKeyRef.current

    // Eve re-encrypts (possibly edited) plaintext with the key she shares with the recipient.
    const { ivHex, ciphertextB64 } = await encryptMessage(outgoingKey, item.editedText)
    const delivered = await decryptMessage(recipientKey, ivHex, ciphertextB64)

    const wasEdited = item.editedText !== item.originalText
    const deliveredMsg = {
      id: item.id + 0.1,
      type: 'received',
      text: delivered,
      tampered: wasEdited,
    }

    if (item.fromAlice) setBobMsgs(prev => [...prev, deliveredMsg])
    else setAliceMsgs(prev => [...prev, deliveredMsg])

    addEve(
      `Forwarded ${item.fromAlice ? 'Alice → Bob' : 'Bob → Alice'}` +
      (wasEdited ? ' — EDITED before relay' : ' — unmodified'),
      'capture'
    )
    setPendingIntercepts(prev => prev.filter(p => p.id !== item.id))
  }

  function handleKey(e) {
    if (e.key === 'Enter') sendMsg()
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
        onRun={runMitmAttack}
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
                {m.type === 'received' && m.tampered && <span className="tampered-badge">⚠ altered in transit</span>}
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
                return (
                  <div key={m.id} className="msg attacker">
                    [{m.ts}] FROM: {m.sender.toUpperCase()} · {m.bytes}B<br />
                    <span className="cipher-label">IV</span> {m.ivHex}<br />
                    <span className="cipher-label">CT</span> {m.ciphertextB64}
                    <div className="cannot-read">✕ cannot read plaintext</div>
                  </div>
                )
              }
              return <div key={m.id} className="msg capture">{m.text}</div>
            })}

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
                {m.type === 'received' && m.tampered && <span className="tampered-badge">⚠ altered in transit</span>}
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
          value, though — that's exactly what an attacker can exploit. Run the MITM attack above to
          see Eve intercept both public values and substitute her own, ending up with two separate
          shared secrets — one with Alice, one with Bob — while both of them believe they're talking
          directly to each other. Level 4 fixes this by having each side sign its public value with
          a long-term identity key Eve doesn't have.
        </p>
      </div>
    </div>
  )
}

export default Level3