import { useState, useEffect, useRef, useCallback } from 'react'
import { sendChatMessage } from '../api/client.js'
import './AIChat.css'

const SUGGESTIONS = [
  '► What is the most critical finding?',
  '► Is this APK safe to install?',
  '► How do I fix exported components?',
  '► What data can attackers access?',
]

function formatTime(ts) {
  const d = new Date(ts)
  const pad = n => String(n).padStart(2, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

function buildInitialLines(scanData) {
  if (!scanData) return []
  const total = Object.values(scanData.findings ?? {})
    .reduce((s, m) => s + (m?.findings?.length ?? 0), 0)
  return [
    '► AppEX ANALYST ONLINE',
    `► TARGET: ${scanData.app_name ?? 'UNKNOWN'}`,
    `► RISK LEVEL: ${scanData.risk_level ?? '—'} (${scanData.risk_score ?? 0}/100)`,
    `► ${total} FINDINGS DETECTED`,
    '► READY FOR INTERROGATION',
  ]
}

export default function AIChat({ scanId, scanData, appState, externalMessage, onExternalMessageHandled }) {
  const [messages,   setMessages]   = useState([])
  const [input,      setInput]      = useState('')
  const [loading,    setLoading]    = useState(false)
  const [bootLines,  setBootLines]  = useState([])
  const [showChips,  setShowChips]  = useState(true)
  const bottomRef = useRef(null)
  const inputRef  = useRef(null)
  const prevScanId = useRef(null)

  // Seed boot messages on new scan
  useEffect(() => {
    if (appState === 'complete' && scanData && scanData.scan_id !== prevScanId.current) {
      prevScanId.current = scanData.scan_id
      setMessages([])
      setShowChips(true)
      setBootLines(buildInitialLines(scanData))
    }
  }, [appState, scanData])

  // Handle external message from FindingCard
  useEffect(() => {
    if (!externalMessage) return
    onExternalMessageHandled?.()
    sendMessage(externalMessage)
  }, [externalMessage])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading, bootLines])

  const sendMessage = useCallback(async (text) => {
    if (!text?.trim() || !scanId) return
    setShowChips(false)
    const userMsg = { role: 'user', text: text.trim(), ts: Date.now() }
    setMessages(prev => [...prev, userMsg])
    setInput('')
    setLoading(true)

    try {
      const res = await sendChatMessage(scanId, text.trim())
      setMessages(prev => [...prev, { role: 'ai', text: res.response ?? res, ts: Date.now() }])
    } catch (err) {
      setMessages(prev => [...prev, {
        role: 'ai',
        text: `ERROR: ${err.message || 'Connection failed'}`,
        ts: Date.now(),
      }])
    } finally {
      setLoading(false)
    }
  }, [scanId])

  function handleKeyDown(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      sendMessage(input)
    }
  }

  function clearChat() {
    setMessages([])
    setBootLines(appState === 'complete' && scanData ? buildInitialLines(scanData) : [])
    setShowChips(true)
  }

  const isActive  = appState === 'complete'
  const hasText   = input.trim().length > 0

  return (
    <div className="aichat">
      <div className="aichat__header">
        <span className="aichat__header-label">// AI ANALYST</span>
        {isActive && loading && <span className="aichat__active-dot" />}
        {isActive && (
          <button className="aichat__clear" onClick={clearChat} title="Clear chat">✕</button>
        )}
      </div>

      <div className="aichat__messages">
        {!isActive ? (
          <div className="aichat__offline">
            <svg className="aichat__offline-icon" width="48" height="48" viewBox="0 0 48 48" fill="none">
              <rect x="4" y="16" width="40" height="24" rx="3" stroke="currentColor" strokeWidth="1.5"/>
              <path d="M14 16V12a10 10 0 0 1 20 0v4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
              <circle cx="18" cy="28" r="2.5" fill="currentColor"/>
              <circle cx="30" cy="28" r="2.5" fill="currentColor"/>
              <path d="M18 33c1.5 1.5 10.5 1.5 12 0" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
              <path d="M4 28h4M40 28h4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
            </svg>
            <span className="aichat__offline-title">ANALYST OFFLINE</span>
            <span className="aichat__offline-sub">SUBMIT SCAN TO ACTIVATE</span>
          </div>
        ) : (
          <>
            {bootLines.length > 0 && (
              <div className="aichat__system-msg">
                {bootLines.map((line, i) => (
                  <span
                    key={i}
                    className="aichat__system-line"
                    style={{ animationDelay: `${i * 150}ms` }}
                  >
                    {line}
                  </span>
                ))}
              </div>
            )}

            {showChips && messages.length === 0 && (
              <div className="aichat__chips">
                {SUGGESTIONS.map((s, i) => (
                  <button key={i} className="aichat__chip" onClick={() => sendMessage(s.replace(/^► /, ''))}>
                    {s}
                  </button>
                ))}
              </div>
            )}

            {messages.map((msg, i) =>
              msg.role === 'user' ? (
                <div key={i} className="aichat__msg-user">
                  <span className="aichat__msg-prefix">USER ›</span>
                  <span className="aichat__msg-text">{msg.text}</span>
                  <span className="aichat__msg-time">{formatTime(msg.ts)}</span>
                </div>
              ) : (
                <div key={i} className="aichat__msg-ai">
                  <span className="aichat__msg-prefix">ANALYST ›</span>
                  <span className="aichat__msg-text">{msg.text}</span>
                  <span className="aichat__msg-time">{formatTime(msg.ts)}</span>
                </div>
              )
            )}

            {loading && (
              <div className="aichat__typing">
                <span className="aichat__typing-text">ANALYST › PROCESSING ···</span>
              </div>
            )}

            <div ref={bottomRef} />
          </>
        )}
      </div>

      <div className="aichat__input-area">
        <input
          ref={inputRef}
          className="aichat__input"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={isActive ? 'QUERY ANALYST...' : 'OFFLINE'}
          disabled={!isActive || loading}
        />
        <button
          className={`aichat__send ${hasText ? 'has-text' : 'empty'}`}
          onClick={() => sendMessage(input)}
          disabled={!isActive || !hasText || loading}
        >
          ►
        </button>
      </div>
    </div>
  )
}
