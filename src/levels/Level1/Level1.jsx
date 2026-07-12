import { useState, useRef, useEffect } from 'react'
import { useAttackPanel } from '../../hooks/useAttackPanel'
import AttackPanel from '../../components/AttackPanel'
import './Level1.css'

const ATTACKS = [
  { id: 'tampering', label: 'Tampering', available: true },
]

function Level1() {
  const [aliceMsgs, setAliceMsgs] = useState([])
  const [bobMsgs, setBobMsgs] = useState([])
  const [eveMsgs, setEveMsgs] = useState([])
  const [pendingMsgs, setPendingMsgs] = useState([]) // messages held at Eve, awaiting forward decision
  const [input, setInput] = useState('')
  const [sender, setSender] = useState('alice')
  const [tamperingEnabled, setTamperingEnabled] = useState(false)
  const msgId = useRef(1)
  const aliceScrollRef = useRef(null)
  const bobScrollRef = useRef(null)
  const eveScrollRef = useRef(null)

  const {
    selectedAttackId, setSelectedAttackId, attackRunning, attackResult, setAttackResult, runAttack,
  } = useAttackPanel('tampering')

  useEffect(() => {
    if (aliceScrollRef.current) aliceScrollRef.current.scrollTop = aliceScrollRef.current.scrollHeight
  }, [aliceMsgs])

  useEffect(() => {
    if (bobScrollRef.current) bobScrollRef.current.scrollTop = bobScrollRef.current.scrollHeight
  }, [bobMsgs])

  useEffect(() => {
    if (eveScrollRef.current) eveScrollRef.current.scrollTop = eveScrollRef.current.scrollHeight
  }, [eveMsgs, pendingMsgs])

  // Once tampering is enabled, new messages stop delivering instantly — they sit at Eve first,
  // and she decides whether to forward them unchanged or edited. Messages already delivered
  // before enabling are untouched; only sends from this point on go through the pause.
  function sendMsg() {
    const text = input.trim()
    if (!text) return

    const ts = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    const id = msgId.current++
    const isAlice = sender === 'alice'

    const sentMsg = { id, type: 'sent', text }
    if (isAlice) setAliceMsgs(prev => [...prev, sentMsg])
    else setBobMsgs(prev => [...prev, sentMsg])

    if (tamperingEnabled) {
      setPendingMsgs(prev => [...prev, { id: id + 0.05, fromAlice: isAlice, ts, originalText: text, editedText: text }])
    } else {
      const deliveredMsg = { id: id + 0.1, type: 'received', text }
      if (isAlice) setBobMsgs(prev => [...prev, deliveredMsg])
      else setAliceMsgs(prev => [...prev, deliveredMsg])

      setEveMsgs(prev => [...prev, { id: id + 0.2, type: 'attacker', text, sender, ts }])
    }

    setInput('')
  }

  function handleKey(e) {
    if (e.key === 'Enter') sendMsg()
  }

  function updatePending(id, newText) {
    setPendingMsgs(prev => prev.map(p => (p.id === id ? { ...p, editedText: newText } : p)))
  }

  // Nothing protects this channel at all — Eve can see the plaintext directly, so she can just
  // retype it before releasing it. There's no check on the other end to catch the difference.
  function forwardPending(item) {
    const wasEdited = item.editedText !== item.originalText
    const deliveredMsg = { id: item.id + 0.1, type: 'received', text: item.editedText, tampered: wasEdited }

    if (item.fromAlice) setBobMsgs(prev => [...prev, deliveredMsg])
    else setAliceMsgs(prev => [...prev, deliveredMsg])

    setEveMsgs(prev => [...prev, {
      id: item.id + 0.2,
      type: 'attacker',
      text: item.originalText,
      sender: item.fromAlice ? 'alice' : 'bob',
      ts: item.ts,
    }])

    setPendingMsgs(prev => prev.filter(p => p.id !== item.id))

    if (wasEdited) {
      setAttackResult({ type: 'success', text: 'Attack succeeded: altered message accepted' })
    }
  }

  // Resetting happens when the attack actually runs, not just when it's selected — clicking
  // "Run attack" clears the session first so tampering starts from a clean slate.
  function runTamperingAttack() {
    if (selectedAttackId !== 'tampering') return
    runAttack(async () => {
      setAliceMsgs([])
      setBobMsgs([])
      setEveMsgs([])
      setPendingMsgs([])
      setTamperingEnabled(true)
    })
  }

  return (
    <div className="level1">

      <AttackPanel
        attacks={ATTACKS}
        selectedAttackId={selectedAttackId}
        onSelect={setSelectedAttackId}
        onRun={runTamperingAttack}
        running={attackRunning}
        disabled={attackRunning || tamperingEnabled}
        result={attackResult}
      />

      <div className="chat-area">

        <div className="chat-col">
          <h3 className="col-heading">Alice</h3>
          <div className="messages" ref={aliceScrollRef}>
            {aliceMsgs.length === 0 && (
              <div className="empty-alice">Waiting for messages…</div>
            )}

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
            {eveMsgs.length === 0 && pendingMsgs.length === 0 && (
              <div className="empty-eve">Waiting for traffic…</div>
            )}
            {eveMsgs.map(m => (
              <div key={m.id} className="msg attacker">
                [{m.ts}] FROM: {m.sender.toUpperCase()}<br />{m.text}
              </div>
            ))}

            {pendingMsgs.map(item => (
              <div key={item.id} className="intercept-card">
                <div className="intercept-meta">
                  [{item.ts}] FROM: {(item.fromAlice ? 'alice' : 'bob').toUpperCase()} — held, awaiting forward decision
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
            {bobMsgs.length === 0 && (
              <div className="empty-bob">Waiting for messages…</div>
            )}
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
          placeholder="Type a message — sent as plaintext…"
        />
        <button onClick={sendMsg}>Send</button>
      </div>

      <div className="info-panel">
        <h4>What's happening</h4>
        <p>
          Every message travels over the network as unencrypted plaintext.
          Eve intercepts and accesses all data, including sender, content, and timestamp — and since
          nothing checks the message's integrity either, she can hold a message, edit the text she can
          already see in plain sight, and release whichever version she wants. Run the tampering attack
          above, then send a message: it pauses at Eve first, and whatever she forwards is delivered
          without any error, because there's no mechanism here to notice it changed at all.
        </p>
      </div>
    </div>
  )
}

export default Level1
