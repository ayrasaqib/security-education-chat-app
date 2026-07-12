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
import { forgeSubstituteKeys, verifyForgedValues } from '../../utils/mitm'
import { tamperCiphertextB64 } from '../../utils/tamper'
import { useAttackPanel } from '../../hooks/useAttackPanel'
import AttackPanel from '../../components/AttackPanel'
import './Level4.css'

const STEP_DELAY_MS = 550

const ATTACKS = [
  { id: 'mitm', label: 'MITM / Impersonation', available: true },
  { id: 'tampering', label: 'Tampering', available: true },
]

function Level4() {
  const [aliceMsgs, setAliceMsgs] = useState([])
  const [bobMsgs, setBobMsgs] = useState([])
  const [eveMsgs, setEveMsgs] = useState([])
  const [input, setInput] = useState('')
  const [sender, setSender] = useState('alice')
  const [status, setStatus] = useState('identities') // 'identities' | 'exchanging' | 'ready' | 'failed'
  const [aliceFingerprint, setAliceFingerprint] = useState('')
  const [bobFingerprint, setBobFingerprint] = useState('')
  const [tamperingEnabled, setTamperingEnabled] = useState(false)
  const [pendingTamperMsgs, setPendingTamperMsgs] = useState([]) // messages Eve is holding, awaiting forward decision

  const {
    selectedAttackId, setSelectedAttackId, attackRunning, attackResult, setAttackResult, runAttack,
  } = useAttackPanel()

  const aliceIdentityRef = useRef(null) // long-term ECDSA keypair, generated once
  const bobIdentityRef = useRef(null)
  const keyRef = useRef(null) // derived AES key, per exchange

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
      // Eve substitutes her own forged DH values in place of the real ones, but she has
      // no way to sign them with Alice's or Bob's identity private key — the only signatures
      // she has (sigA, sigB) were computed over the REAL public values, not her forged ones.
      forged = forgeSubstituteKeys()

      addEve('Substituting forged public values before forwarding — reusing the only signatures available (over the real values)')
      await sleep(STEP_DELAY_MS)
      if (stale()) return

      addBob(`Received "A" from Alice (Eve) = ${shortHex(forged.forBob.publicKey, 16)}`)
      addAlice(`Received "B" from Bob (Eve) = ${shortHex(forged.forAlice.publicKey, 16)}`)
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

    // 7. Derive the symmetric key from the shared secret
    addAlice('Deriving AES-256 key = SHA-256(s)…')
    addBob('Deriving AES-256 key = SHA-256(s)…')
    const aesKey = await deriveAesKeyFromSharedSecret(sharedAlice)
    if (stale()) return
    keyRef.current = aesKey
    await sleep(400)
    if (stale()) return

    addAlice('Secure, authenticated channel ready — you can chat now.', 'ready-note')
    addBob('Secure, authenticated channel ready — you can chat now.', 'ready-note')
    setStatus('ready')
  }

  // Long-term identity keys: generated once on mount, NOT regenerated by "New exchange" —
  // they represent identities both parties already trust, independent of any one session.
  // Eve never gets a copy of either private key — she only ever sees what crosses the wire.
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

  function runSelectedAttack() {
    if (selectedAttackId === 'mitm') runMitmAttack()
    else if (selectedAttackId === 'tampering') runTamperingAttack()
  }

  // Authentication protects the HANDSHAKE — it says nothing about individual messages after
  // that. AES-CTR still has no per-message integrity check, so a blind ciphertext flip still
  // decrypts "successfully" to altered content, exactly like Levels 2 and 3.
  async function forwardPendingTamper(item, corrupt) {
    const key = keyRef.current
    const finalCiphertext = corrupt ? tamperCiphertextB64(item.ciphertextB64) : item.ciphertextB64
    const delivered = await decryptMessage(key, item.ivHex, finalCiphertext)

    const deliveredMsg = { id: item.id + 0.1, type: 'received', text: delivered, tampered: corrupt }
    if (item.fromAlice) setBobMsgs(prev => [...prev, deliveredMsg])
    else setAliceMsgs(prev => [...prev, deliveredMsg])

    setEveMsgs(prev => [...prev, {
      id: item.id + 0.2,
      type: 'attacker',
      sender: item.fromAlice ? 'alice' : 'bob',
      ts: item.ts,
      ivHex: item.ivHex,
      ciphertextB64: item.ciphertextB64,
      bytes: item.bytes,
    }])

    setPendingTamperMsgs(prev => prev.filter(p => p.id !== item.id))

    if (corrupt) {
      setAttackResult({ type: 'success', text: 'Attack succeeded: altered message accepted' })
    }
  }

  async function sendMsg() {
    const text = input.trim()
    if (!text || status !== 'ready') return

    const ts = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    const id = msgId.current++
    const key = keyRef.current
    const isAlice = sender === 'alice'

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

  function handleKey(e) {
    if (e.key === 'Enter') sendMsg()
  }

  const busy = status === 'exchanging' || status === 'identities'

  return (
    <div className="level4">

      <div className="handshake-bar">
        <div className="handshake-label">
          <i className="ti ti-arrows-exchange" aria-hidden="true" />
          Authenticated DH key exchange {
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
              <i className="ti ti-shield-check" aria-hidden="true" /> Identity public key: {aliceFingerprint || 'generating…'}
            </span>
          </div>
          <div className="messages" ref={aliceScrollRef}>
            {aliceMsgs.map(m => (
              <div key={m.id} className={`msg ${m.type}`}>
                {m.text}
                {m.type === 'received' && m.tampered && <span className="tampered-badge">⚠ altered by Eve — accepted anyway</span>}
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
                    [{m.ts}] FROM: {m.sender.toUpperCase()} · {m.bytes}B<br />
                    <span className="cipher-label">IV</span> {m.ivHex}<br />
                    <span className="cipher-label">CT</span> {m.ciphertextB64}
                    <div className="cannot-read">✕ cannot read plaintext</div>
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
          </div>
        </div>

        <div className="chat-col">
          <div className="col-heading-row">
            <h3 className="col-heading">Bob</h3>
            <span className="identity-chip">
              <i className="ti ti-shield-check" aria-hidden="true" /> Identity public key: {bobFingerprint || 'generating…'}
            </span>
          </div>
          <div className="messages" ref={bobScrollRef}>
            {bobMsgs.map(m => (
              <div key={m.id} className={`msg ${m.type}`}>
                {m.text}
                {m.type === 'received' && m.tampered && <span className="tampered-badge">⚠ altered by Eve — accepted anyway</span>}
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
          placeholder={status === 'ready' ? 'Type a message — encrypted with the authenticated key…' : 'Running authenticated key exchange…'}
          disabled={status !== 'ready'}
        />
        <button onClick={sendMsg} disabled={status !== 'ready'}>Send</button>
      </div>

      <div className="info-panel">
        <h4>What's happening</h4>
        <p>
          Alice and Bob each have identity public keys known to both parties in advance while their private 
          keys never leave their own side. Before Alice and Bob trust each other's DH public value, each one is signed
          with the sender's identity private key and verified against the identity public key the other side
          already holds. Eve can watch every bit of this handshake — the DH public values, both signatures,
          later the ciphertext — but she holds neither identity private key, so she can't produce a
          signature Alice or Bob would accept, and she can't derive the shared secret from public values alone.
          That signature only ever protects the handshake, though — select Tampering above and run it.
          Once enabled, new messages pause at Eve first: choose "Corrupt &amp; forward" and see that
          AES-CTR still has no per-message integrity check, so a blind ciphertext edit decrypts
          without error, same as Levels 2 and 3.
        </p>
      </div>
    </div>
  )
}

export default Level4