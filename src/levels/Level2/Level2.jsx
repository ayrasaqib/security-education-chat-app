import { useState, useRef, useEffect } from 'react'
import { generateAesKey, exportKeyHex, encryptMessage, decryptMessage } from '../../utils/crypto'
import './Level2.css'

function Level2() {
  const [aliceMsgs, setAliceMsgs] = useState([])
  const [bobMsgs, setBobMsgs] = useState([])
  const [eveMsgs, setEveMsgs] = useState([])
  const [input, setInput] = useState('')
  const [sender, setSender] = useState('alice')
  const [keyHex, setKeyHex] = useState('')
  const [ready, setReady] = useState(false)
  const keyRef = useRef(null)
  const msgId = useRef(1)

  // Simulate a pre-shared key already sitting on both Alice's and Bob's
  // machines. Level 3 replaces this assumption with a real key exchange.
  useEffect(() => {
    let cancelled = false
    generateAesKey().then(async key => {
      if (cancelled) return
      keyRef.current = key
      setKeyHex(await exportKeyHex(key))
      setReady(true)
    })
    return () => { cancelled = true }
  }, [])

  async function regenerateKey() {
    setReady(false)
    const key = await generateAesKey()
    keyRef.current = key
    setKeyHex(await exportKeyHex(key))
    setAliceMsgs([])
    setBobMsgs([])
    setEveMsgs([])
    setReady(true)
  }

  async function sendMsg() {
    const text = input.trim()
    if (!text || !ready) return

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

      <div className="key-panel">
        <div className="key-panel-label">
          <i className="ti ti-key" aria-hidden="true" />
          Pre-shared symmetric key (AES-256-GCM)
        </div>
        <code className="key-value">{keyHex ? `${keyHex.slice(0, 32)}…` : 'generating…'}</code>
        <button className="key-regen" onClick={regenerateKey}>Rotate key</button>
        <span className="key-caveat">
          Held by Alice &amp; Bob before the conversation starts — not exchanged over this channel.
          Level 3 removes this assumption with Diffie–Hellman key exchange.
        </span>
      </div>

      <div className="chat-area">

        <div className="chat-col">
          <h3 className="col-heading">Alice</h3>
          <div className="messages">
            {aliceMsgs.length === 0 && (
              <div className="empty-alice">Waiting for messages…</div>
            )}
            {aliceMsgs.map(m => (
              <div key={m.id} className={`msg ${m.type}`}>{m.text}</div>
            ))}
          </div>
        </div>

        <div className="attacker-col">
          <div className="sniff-indicator">
            <div className="dot" /> Eve (eavesdropping)
          </div>
          <h3 className="col-heading eve">Intercepted (ciphertext)</h3>
          <div className="messages">
            {eveMsgs.length === 0 && (
              <div className="empty-eve">Waiting for traffic…</div>
            )}
            {eveMsgs.map(m => (
              <div key={m.id} className="msg attacker">
                [{m.ts}] FROM: {m.sender.toUpperCase()} · {m.bytes}B<br />
                <span className="cipher-label">IV</span> {m.ivHex}<br />
                <span className="cipher-label">CT</span> {m.ciphertextB64}
                <div className="cannot-read">✕ cannot read plaintext</div>
              </div>
            ))}
          </div>
        </div>

        <div className="chat-col">
          <h3 className="col-heading">Bob</h3>
          <div className="messages">
            {bobMsgs.length === 0 && (
              <div className="empty-bob">Waiting for messages…</div>
            )}
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
          placeholder={ready ? 'Type a message — encrypted before it leaves the sender…' : 'Generating key…'}
          disabled={!ready}
        />
        <button onClick={sendMsg} disabled={!ready}>Send</button>
      </div>

      <div className="info-panel">
        <h4>What's happening</h4>
        <p>
          Each message is encrypted with AES-256-GCM using a key both parties already hold, and
          decrypted only on arrival. Eve intercepts real ciphertext and cannot recover the content —
          but she can still see <em>who</em> is talking, <em>when</em>, and roughly <em>how much</em>
          data was sent. Confidentiality is solved; sender authentication and integrity are not yet
          (see later levels), and the key itself still had to reach both parties somehow.
        </p>
      </div>
    </div>
  )
}

export default Level2
