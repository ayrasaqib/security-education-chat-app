import { useState, useRef, useEffect } from 'react'
import { encryptMessage, decryptMessage } from '../../utils/crypto'
import { generateDHKeyPair, computeSharedSecret, deriveAesKeyFromSharedSecret, shortHex, PRIME, GENERATOR } from '../../utils/dh'
import './Level3.css'

const STEP_DELAY_MS = 550

function Level3() {
  const [aliceMsgs, setAliceMsgs] = useState([])
  const [bobMsgs, setBobMsgs] = useState([])
  const [eveMsgs, setEveMsgs] = useState([])
  const [input, setInput] = useState('')
  const [sender, setSender] = useState('alice')
  const [status, setStatus] = useState('exchanging') // 'exchanging' | 'ready'

  const keyRef = useRef(null)
  const msgId = useRef(1)
  const runIdRef = useRef(0) // guards against a stale run still writing state after "New exchange" or unmount
  const aliceScrollRef = useRef(null)
  const bobScrollRef = useRef(null)
  const eveScrollRef = useRef(null)

  useEffect(() => {
    runHandshake()
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
  }, [eveMsgs])

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

    // 4. Exchange public values over the (untrusted) network
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

    // 5. Each side computes the shared secret from the other's public value
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

    // 6. Derive the symmetric key from the shared secret
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
  }

  async function sendMsg() {
    const text = input.trim()
    if (!text || status !== 'ready') return

    const ts = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    const id = msgId.current++
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

    if (sender === 'alice') {
      setAliceMsgs(prev => [...prev, sentMsg])
      setBobMsgs(prev => [...prev, deliveredMsg])
    } else {
      setBobMsgs(prev => [...prev, sentMsg])
      setAliceMsgs(prev => [...prev, deliveredMsg])
    }

    setEveMsgs(prev => [...prev, eveMsg])
    setInput('')
  }

  function handleKey(e) {
    if (e.key === 'Enter') sendMsg()
  }

  return (
    <div className="level3">

      <div className="handshake-bar">
        <div className="handshake-label">
          <i className="ti ti-arrows-exchange" aria-hidden="true" />
          Diffie–Hellman key exchange {status === 'exchanging' ? '— in progress…' : '— complete'}
        </div>
        <button className="handshake-redo" onClick={runHandshake} disabled={status === 'exchanging'}>
          New exchange
        </button>
      </div>

      <div className="chat-area">

        <div className="chat-col">
          <h3 className="col-heading">Alice</h3>
          <div className="messages" ref={aliceScrollRef}>
            {aliceMsgs.map(m => (
              <div key={m.id} className={`msg ${m.type}`}>{m.text}</div>
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
          </div>
        </div>

        <div className="chat-col">
          <h3 className="col-heading">Bob</h3>
          <div className="messages" ref={bobScrollRef}>
            {bobMsgs.map(m => (
              <div key={m.id} className={`msg ${m.type}`}>{m.text}</div>
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
          (g^a mod p and g^b mod p) over the network. From those, each independently computes the
          same shared secret — Eve, watching the whole exchange, has the same public values but
          can't reconstruct the secret without solving a discrete logarithm over a 2048-bit prime.
          The AES key used for chat is derived from that shared secret, so Level 2's "how did the
          key get there" gap is closed. What's still missing: neither party has verified the other's
          identity, so an active attacker positioned on the wire during the exchange itself is a
          different problem — that's what Level 4 (authentication) and a later MITM demo address.
        </p>
      </div>
    </div>
  )
}

export default Level3