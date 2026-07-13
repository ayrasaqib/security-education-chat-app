import { useState, useRef, useEffect } from 'react'
import { generateAesKey, exportKeyHex, encryptMessage, decryptMessage } from '../../utils/crypto'
import { useAttackPanel } from '../../hooks/useAttackPanel'
import AttackPanel from '../../components/AttackPanel'
import './Level2.css'

const STEP_DELAY_MS = 550

const ATTACKS = [
  { id: 'tampering', label: 'Tampering', available: true },
  { id: 'replay', label: 'Replay', available: true },
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
  const [replayEnabled, setReplayEnabled] = useState(false)

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
    setReplayEnabled(false)
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
      // The receiver only ever gets ciphertext + IV, then decrypts locally. Eve holds the same
      // captured key, so she decrypts it too, the moment it's intercepted — no reason to hide
      // that behind an extra click.
      const decrypted = await decryptMessage(key, ivHex, ciphertextB64)
      const deliveredMsg = { id: id + 0.1, type: 'received', text: decrypted }
      if (isAlice) setBobMsgs(prev => [...prev, deliveredMsg])
      else setAliceMsgs(prev => [...prev, deliveredMsg])

      setEveMsgs(prev => [...prev, {
        id: id + 0.2, type: 'attacker', sender, ts, ivHex, ciphertextB64, bytes: ciphertextBytes, decrypted,
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
  // plaintext and retype it before deciding what to send on. If she's leaving it alone, there's
  // no reason to re-encrypt — she just relays the exact bytes she intercepted, and Bob decrypts
  // them with the same shared key Alice used. Only an actual edit forces her to build fresh
  // ciphertext, which needs a new IV under CTR regardless of what changed. The outcome goes in
  // her own panel rather than a warning badge on Bob's bubble — Bob's UI never sees any of this.
  async function forwardPending(item) {
    const key = keyRef.current
    const wasEdited = item.editedText !== item.originalText

    const { ivHex, ciphertextB64, ciphertextBytes } = wasEdited
      ? await encryptMessage(key, item.editedText)
      : { ivHex: item.ivHex, ciphertextB64: item.ciphertextB64, ciphertextBytes: item.bytes }
    const delivered = await decryptMessage(key, ivHex, ciphertextB64)

    const deliveredMsg = { id: item.id + 0.1, type: 'received', text: delivered }
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
      decrypted: delivered,
      originalText: item.originalText,
      originalIvHex: item.ivHex,
      originalCiphertextB64: item.ciphertextB64,
      note: wasEdited ? 'EDITED before relay' : 'unmodified',
    }])

    setPendingMsgs(prev => prev.filter(p => p.id !== item.id))

    if (wasEdited) {
      setAttackResult({ type: 'success', text: 'Attack succeeded: altered message accepted' })
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

  // Same reset-then-arm pattern, but messages keep delivering instantly — replay doesn't need
  // to intercept anything in flight, it just needs a message that's already been captured.
  function runReplayAttack() {
    if (selectedAttackId !== 'replay') return
    runAttack(async () => {
      await runKeyExchange()
      setReplayEnabled(true)
    })
  }

  function runSelectedAttack() {
    if (selectedAttackId === 'tampering') runTamperingAttack()
    else if (selectedAttackId === 'replay') runReplayAttack()
  }

  // AES-CTR alone has no integrity or freshness check — decrypting the exact same IV/ciphertext
  // a second time produces the exact same plaintext, and nothing on the receiving end knows this
  // isn't the first time it's seen this message, so the outcome is only visible in Eve's panel.
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
        onRun={runSelectedAttack}
        running={attackRunning}
        disabled={attackRunning || tamperingEnabled || replayEnabled || status === 'exchanging'}
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
            <div className="dot" /> Eve (eavesdropping)
          </div>
          <h3 className="col-heading eve">
            Intercepted
          </h3>
          <div className="messages" ref={eveScrollRef}>
            {eveMsgs.map(m => {
              if (m.type === 'attacker') {
                // AES-CTR needs a fresh IV on every encryption, so Level 2's re-encrypted ciphertext
                // never byte-for-byte matches the original capture — even when the plaintext wasn't
                // edited. Basing the diff on the plaintext-derived `note` (not raw ciphertext equality)
                // keeps "unmodified" forwards showing as a single row, the way they actually are.
                const showCtDiff = m.note !== undefined && m.note !== 'unmodified'
                const showTextDiff = m.originalText !== undefined && m.originalText !== m.decrypted
                return (
                  <div key={m.id} className="msg attacker">
                    [{m.ts}] FROM: {m.sender.toUpperCase()} · {m.bytes}B{m.note ? ` · ${m.note}` : ''}<br />
                    {showCtDiff ? (
                      <>
                        <span className="text-diff-label">IV/CT (captured)</span> {m.originalIvHex} / {m.originalCiphertextB64}<br />
                        <span className="text-diff-label">IV/CT (sent)</span> {m.ivHex} / {m.ciphertextB64}
                      </>
                    ) : (
                      <>
                        <span className="cipher-label">IV</span> {m.ivHex}<br />
                        <span className="cipher-label">CT</span> {m.ciphertextB64}
                      </>
                    )}
                    <div className="decrypted-plaintext">
                      {showTextDiff ? (
                        <>
                          <span className="decrypted-label">Before:</span> {m.originalText}<br />
                          <span className="decrypted-label">After:</span> {m.decrypted}
                        </>
                      ) : (
                        <><span className="decrypted-label">Decrypted with captured key:</span> {m.decrypted}</>
                      )}
                    </div>
                    {replayEnabled && (
                      <button className="replay-btn" onClick={() => replayCaptured(m)}>
                        <i className="ti ti-repeat" aria-hidden="true" /> Replay this message
                      </button>
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
                <span className="decrypted-label">Decrypted with captured key:</span>
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
          decrypted only on arrival. Eve intercepts real ciphertext, but since she captured the same
          key, every intercepted message is shown already decrypted right next to it — no separate
          step needed. Confidentiality is not solved here at all. On top of that, AES-256-CTR has no integrity
          check — select Tampering above and run it, then send a message: it pauses at Eve first, already
          decrypted with her captured key, and she can retype it directly before forwarding — no blind
          guessing required, and no error on arrival either way. Select Replay instead and every
          intercepted message gets a "Replay this message" button — re-decrypting and re-delivering the
          exact same IV and ciphertext succeeds again, because nothing here tracks what's already arrived.
        </p>
      </div>
    </div>
  )
}

export default Level2
