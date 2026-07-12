import { useState, useRef, useEffect } from 'react'
import { generateAesKey, exportKeyHex, encryptMessage, decryptMessage } from '../../utils/crypto'
import { useAttackPanel } from '../../hooks/useAttackPanel'
import AttackPanel from '../../components/AttackPanel'
import './Level2.css'

const STEP_DELAY_MS = 550

const ATTACKS = [
  { id: 'tampering', label: 'Tampering', available: true },
]

function Level2() {
  const [aliceMsgs, setAliceMsgs] = useState([])
  const [bobMsgs, setBobMsgs] = useState([])
  const [eveMsgs, setEveMsgs] = useState([])
  const [pendingMsgs, setPendingMsgs] = useState([]) // messages held at Eve, awaiting forward decision
  const [input, setInput] = useState('')
  const [sender, setSender] = useState('alice')
  const [status, setStatus] = useState('exchanging') // 'exchanging' | 'ready'
  const [tamperingEnabled, setTamperingEnabled] = useState(false)

  const {
    selectedAttackId, setSelectedAttackId, attackRunning, attackResult, setAttackResult, runAttack,
  } = useAttackPanel('tampering')

  const keyRef = useRef(null)
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
  }, [eveMsgs, pendingMsgs])

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
    setPendingMsgs([])
    setTamperingEnabled(false)
    setAttackResult(null)

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

    addAlice('Channel ready — you can chat now.', 'ready-note')
    addBob('Channel ready — you can chat now.', 'ready-note')
    setStatus('ready')
  }

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    runKeyExchange()
    // eslint-disable-next-line react-hooks/exhaustive-deps
    return () => { runIdRef.current++ } // invalidate any in-flight run on unmount
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Once tampering is enabled, new messages stop delivering instantly — they sit at Eve first,
  // and she decides whether to forward them unchanged or corrupted. Messages already delivered
  // before enabling are untouched; only sends from this point on go through the pause.
  async function sendMsg() {
    const text = input.trim()
    if (!text || status !== 'ready') return

    const ts = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    const id = msgId.current++
    const key = keyRef.current
    const isAlice = sender === 'alice'

    // Encrypt on the sender's side before it ever "touches the network".
    const { ivHex, ciphertextB64, ciphertextBytes } = await encryptMessage(key, text)

    const sentMsg = { id, type: 'sent', text }
    if (isAlice) setAliceMsgs(prev => [...prev, sentMsg])
    else setBobMsgs(prev => [...prev, sentMsg])

    if (tamperingEnabled) {
      const plaintext = await decryptMessage(key, ivHex, ciphertextB64)
      setPendingMsgs(prev => [...prev, {
        id: id + 0.05, fromAlice: isAlice, ts, ivHex, ciphertextB64, bytes: ciphertextBytes,
        originalText: plaintext, editedText: plaintext,
      }])
    } else {
      // The receiver only ever gets ciphertext + IV, then decrypts locally.
      const decrypted = await decryptMessage(key, ivHex, ciphertextB64)
      const deliveredMsg = { id: id + 0.1, type: 'received', text: decrypted }
      if (isAlice) setBobMsgs(prev => [...prev, deliveredMsg])
      else setAliceMsgs(prev => [...prev, deliveredMsg])

      setEveMsgs(prev => [...prev, {
        id: id + 0.2, type: 'attacker', sender, ts, ivHex, ciphertextB64, bytes: ciphertextBytes,
      }])
    }

    setInput('')
  }

  function handleKey(e) {
    if (e.key === 'Enter') sendMsg()
  }

  function updatePending(id, newText) {
    setPendingMsgs(prev => prev.map(p => (p.id === id ? { ...p, editedText: newText } : p)))
  }

  // Eve already has the key, so she's not blindly flipping bits here — she can see the exact
  // plaintext and retype it before re-encrypting and forwarding whatever she decides on.
  async function forwardPending(item) {
    const key = keyRef.current
    const { ivHex, ciphertextB64, ciphertextBytes } = await encryptMessage(key, item.editedText)
    const delivered = await decryptMessage(key, ivHex, ciphertextB64)

    const wasEdited = item.editedText !== item.originalText
    const deliveredMsg = { id: item.id + 0.1, type: 'received', text: delivered, tampered: wasEdited }
    if (item.fromAlice) setBobMsgs(prev => [...prev, deliveredMsg])
    else setAliceMsgs(prev => [...prev, deliveredMsg])

    setEveMsgs(prev => [...prev, {
      id: item.id + 0.2,
      type: 'attacker',
      sender: item.fromAlice ? 'alice' : 'bob',
      ts: item.ts,
      ivHex,
      ciphertextB64,
      bytes: ciphertextBytes,
    }])

    setPendingMsgs(prev => prev.filter(p => p.id !== item.id))

    if (wasEdited) {
      
      ({ type: 'success', text: 'Attack succeeded: altered message accepted' })
    }
  }

  // Resetting happens when the attack actually runs, not just when it's selected — clicking
  // "Run attack" re-runs the key exchange first so tampering starts from a clean slate.
  function runTamperingAttack() {
    if (selectedAttackId !== 'tampering') return
    runAttack(async () => {
      await runKeyExchange()
      setTamperingEnabled(true)
    })
  }

  // Eve holds the literal session key (captured during the naive exchange), so she can decrypt
  // any historical captured ciphertext at any point. Messages currently held pending don't need
  // this — they're already shown decrypted and editable directly.
  async function revealDecryption(id, ivHex, ciphertextB64) {
    const key = keyRef.current
    const text = await decryptMessage(key, ivHex, ciphertextB64)
    setEveMsgs(prev => prev.map(m => (m.id === id ? { ...m, decrypted: text } : m)))
  }

  return (
    <div className="level2">

      <div className="handshake-bar">
        <div className="handshake-label">
          <i className="ti ti-key" aria-hidden="true" />
          Naive key exchange (AES-256-CTR) {status === 'exchanging' ? '— in progress…' : '— complete'}
        </div>
        <button className="handshake-redo" onClick={() => runKeyExchange()} disabled={status === 'exchanging'}>
          New exchange
        </button>
      </div>

      <AttackPanel
        attacks={ATTACKS}
        selectedAttackId={selectedAttackId}
        onSelect={setSelectedAttackId}
        onRun={runTamperingAttack}
        running={attackRunning}
        disabled={attackRunning || tamperingEnabled || status === 'exchanging'}
        result={attackResult}
      />

      <div className="chat-area">

        <div className="chat-col">
          <h3 className="col-heading">Alice</h3>
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
                    {m.decrypted === undefined ? (
                      <>
                        <div className="cannot-read">✕ cannot read plaintext — without the key</div>
                        <button className="decrypt-btn" onClick={() => revealDecryption(m.id, m.ivHex, m.ciphertextB64)}>
                          <i className="ti ti-lock-open" aria-hidden="true" /> Decrypt with captured key
                        </button>
                      </>
                    ) : (
                      <div className="decrypted-plaintext">
                        <span className="decrypted-label">Decrypted with captured key:</span> {m.decrypted}
                      </div>
                    )}
                  </div>
                )
              }
              return <div key={m.id} className={`msg ${m.type}`}>{m.text}</div>
            })}

            {pendingMsgs.map(item => (
              <div key={item.id} className="intercept-card">
                <div className="intercept-meta">
                  [{item.ts}] FROM: {(item.fromAlice ? 'alice' : 'bob').toUpperCase()} · {item.bytes}B — held, awaiting forward decision
                </div>
                <div className="intercept-ciphertext">
                  <span className="cipher-label">IV</span> {item.ivHex}<br />
                  <span className="cipher-label">CT</span> {item.ciphertextB64}
                </div>
                <textarea
                  className="intercept-textarea"
                  value={item.editedText}
                  onChange={e => updatePending(item.id, e.target.value)}
                  rows={2}
                />
                <button className="intercept-forward-btn" onClick={() => forwardPending(item)}>
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
          placeholder={status === 'ready' ? 'Type a message — encrypted with the exposed key…' : 'Exchanging key…'}
          disabled={status !== 'ready'}
        />
        <button onClick={sendMsg} disabled={status !== 'ready'}>Send</button>
      </div>

      <div className="info-panel">
        <h4>What's happening</h4>
        <p>
          Alice generates a AES-256 session key locally, then sends it to Bob over a channel she believes is secure.
          Eve is monitoring the same channel and can capture the entire key, giving her the ability to decrypt the
          conversation. There is no mechanism to establish a key securely, so the channel is vulnerable.
          Each message is encrypted with AES-256-CTR using a key both parties already hold, and
          decrypted only on arrival. Eve intercepts real ciphertext — try "Decrypt with captured key" on any
          intercepted message to see her actually recover the plaintext using the exact key she captured
          earlier. Confidentiality is not solved here at all. On top of that, AES-256-CTR has no integrity
          check — select Tampering above and run it, then send a message: it pauses at Eve first, already
          decrypted with her captured key, and she can retype it directly before forwarding — no blind
          guessing required, and no error on arrival either way.
        </p>
      </div>
    </div>
  )
}

export default Level2
