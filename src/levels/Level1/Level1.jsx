import { useState, useRef, useEffect } from 'react'
import './Level1.css'

function Level1() {
  const [aliceMsgs, setAliceMsgs] = useState([])
  const [bobMsgs, setBobMsgs] = useState([])
  const [eveMsgs, setEveMsgs] = useState([])
  const [input, setInput] = useState('')
  const [sender, setSender] = useState('alice')
  const msgId = useRef(1)
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
  }, [eveMsgs])

  function sendMsg() {
    const text = input.trim()
    if (!text) return

    const ts = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    const id = msgId.current++

    const sentMsg      = { id, type: 'sent', text }
    const deliveredMsg = { id: id + 0.1, type: 'received', text }
    const eveMsg       = { id: id + 0.2, type: 'attacker', text, sender, ts }

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
    <div className="level1">
      <div className="chat-area">

        <div className="chat-col">
          <h3 className="col-heading">Alice</h3>
          <div className="messages" ref={aliceScrollRef}>
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
          <h3 className="col-heading eve">Intercepted</h3>
          <div className="messages" ref={eveScrollRef}>
            {eveMsgs.length === 0 && (
              <div className="empty-eve">Waiting for traffic…</div>
            )}
            {eveMsgs.map(m => (
              <div key={m.id} className="msg attacker">
                [{m.ts}] FROM: {m.sender.toUpperCase()}<br />{m.text}
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
          placeholder="Type a message — sent as plaintext…"
        />
        <button onClick={sendMsg}>Send</button>
      </div>

      <div className="info-panel">
        <h4>What's happening</h4>
        <p>
          Every message travels over the network as unencrypted plaintext.
          Eve intercepts and accesses all data, including sender, content, and timestamp.
        </p>
      </div>
    </div>
  )
}

export default Level1