import { useState, useRef, useEffect } from 'react'
import { generateAesKey, exportKeyHex, encryptMessage, decryptMessage } from '../../utils/crypto'
import './Level2.css'

const STEP_DELAY_MS = 550

function Level2() {
  const [aliceMsgs, setAliceMsgs] = useState([])
  const [bobMsgs, setBobMsgs] = useState([])
  const [eveMsgs, setEveMsgs] = useState([])
  const [input, setInput] = useState('')
  const [sender, setSender] = useState('alice')
  const [status, setStatus] = useState('exchanging') // 'exchanging' | 'ready'
  const [capturedKeyHex, setCapturedKeyHex] = useState('') // the key Eve stole, shown in her column header

  const keyRef = useRef(null)
  const msgId = useRef(1)
  const runIdRef = useRef(0) // guards against a stale run still writing state after "New exchange" or unmount
  const aliceScrollRef = useRef(null)
  const bobScrollRef = useRef(null)
  const eveScrollRef = useRef(null)

  useEffect(() => {
    runKeyExchange()
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

  /**
   * Naive key exchange: Alice generates a real AES-256 session key and sends
   * it to Bob AS-IS over the same insecure channel Eve is sniffing. Unlike
   * Level 3's Diffie–Hellman exchange (where Eve only ever sees public values
   * and still can't derive the secret), here the literal key crosses the wire
   * — so Eve's capture below is not a partial leak, it's the whole key.
   */
  async function runKeyExchange() {
    const myRun = ++runIdRef.current
    const stale = () => runIdRef.current !== myRun

    setStatus('exchanging')
    setAliceMsgs([])
    setBobMsgs([])
    setEveMsgs([])
    setCapturedKeyHex('')

    addAlice('Generating AES-256 session key locally…')
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    const key = await generateAesKey()
    const keyHex = await exportKeyHex(key)
    if (stale()) return
    keyRef.current = key
    addAlice(`Key generated: ${keyHex.slice(0, 16)}…`)
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    addAlice('Sending session key to Bob →')
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    // The key is transmitted in full, in the clear — Eve captures all of it.
    addEve(`Intercepted session key (full): ${keyHex}`, 'capture-key')
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    addBob(`Received session key from Alice: ${keyHex.slice(0, 16)}…`)
    await sleep(STEP_DELAY_MS)
    if (stale()) return

    setCapturedKeyHex(keyHex)
    addAlice('Channel ready — you can chat now.', 'ready-note')
    addBob('Channel ready — you can chat now.', 'ready-note')
    setStatus('ready')
  }

  async function sendMsg() {
    const text = input.trim()
    if (!text || status !== 'ready') return

    const ts = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    const id = msgId.current++
    const key = keyRef.current

    // Encrypt on the sender's side before it ever "touches the network".
    const { ivHex, ciphertextB64, ciphertextBytes } = await encryptMessage(key, text)

    // The receiver only ever gets ciphertext + IV, then decrypts locally.
    const decrypted = await decryptMessage(key, ivHex, ciphertextB64)

    const sentMsg      = { id, type: 'sent', text }
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
    <div className="level2">

      <div className="handshake-bar">
        <div className="handshake-label">
          <i className="ti ti-key" aria-hidden="true" />
          Naive key exchange (AES-256-GCM) {status === 'exchanging' ? '— in progress…' : '— complete'}
        </div>
        <button className="handshake-redo" onClick={runKeyExchange} disabled={status === 'exchanging'}>
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
          <h3 className="col-heading eve">
            Intercepted
          </h3>
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
              return <div key={m.id} className={`msg ${m.type}`}>{m.text}</div>
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
          placeholder={status === 'ready' ? 'Type a message — encrypted with the exposed key…' : 'Exchanging key…'}
          disabled={status !== 'ready'}
        />
        <button onClick={sendMsg} disabled={status !== 'ready'}>Send</button>
      </div>

      <div className="info-panel">
        <h4>What's happening</h4>
        <p>
          Alice generates a AES-256 session key locally, then sends it to Bob over a channel she believes is secure.
          Eve is monitoring the same channel and captures the entire key, giving her the ability to decrypt the
          conversation. There is no mechanism to establish a key securely, so the channel is vulnerable.
        </p>
      </div>
    </div>
  )
}

export default Level2