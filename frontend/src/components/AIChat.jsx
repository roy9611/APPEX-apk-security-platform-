import { useState, useEffect, useRef, useCallback } from 'react'
import { sendChatMessage } from '../api/client.js'
import './AIChat.css'

const SUGGESTIONS = [
  'What is the most critical finding?',
  'Is this APK safe to install?',
  'How do I fix exported components?',
  'What data can attackers access?',
]

function formatTime(ts) {
  const d = new Date(ts)
  const pad = n => String(n).padStart(2, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function buildBootLines(scanData) {
  if (!scanData) return []
  const total = Object.values(scanData.findings ?? {})
    .reduce((s, m) => s + (m?.findings?.length ?? 0), 0)
  return [
    `AppEX ANALYST ONLINE`,
    `TARGET: ${scanData.app_name ?? 'UNKNOWN'}`,
    `RISK: ${scanData.risk_level ?? '—'} · SCORE ${scanData.risk_score ?? 0}/100`,
    `${total} FINDINGS ACROSS ${Object.keys(scanData.findings ?? {}).length} MODULES`,
  ]
}

export default function AIChat({ scanId, scanData, appState, externalMessage, onExternalMessageHandled }) {
  const [messages,  setMessages]  = useState([])
  const [input,     setInput]     = useState('')
  const [loading,   setLoading]   = useState(false)
  const [bootLines, setBootLines] = useState([])
  const [showChips, setShowChips] = useState(true)

  const bottomRef  = useRef(null)
  const inputRef   = useRef(null)
  const prevScanId = useRef(null)

  useEffect(() => {
    if (appState === 'complete' && scanData && scanData.scan_id !== prevScanId.current) {
      prevScanId.current = scanData.scan_id
      setMessages([])
      setShowChips(true)
      setBootLines(buildBootLines(scanData))
    }
  }, [appState, scanData])

  useEffect(() => {
    if (!externalMessage) return
    onExternalMessageHandled?.()
    sendMessage(externalMessage)
  }, [externalMessage])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading, bootLines])

  const sendMessage = useCallback(async (text) => {
    const trimmed = text?.trim()
    if (!trimmed || !scanId) return
    setShowChips(false)
    setMessages(prev => [...prev, { role: 'user', text: trimmed, ts: Date.now() }])
    setInput('')
    setLoading(true)
    try {
      const res = await sendChatMessage(scanId, trimmed)
      setMessages(prev => [...prev, { role: 'ai', text: res.response ?? res, ts: Date.now() }])
    } catch (err) {
      setMessages(prev => [...prev, { role: 'ai', text: `ERROR: ${err.message || 'Connection failed'}`, ts: Date.now() }])
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
    setBootLines(appState === 'complete' && scanData ? buildBootLines(scanData) : [])
    setShowChips(true)
  }

  const isActive = appState === 'complete'
  const hasText  = input.trim().length > 0

  return (
    <div className="aichat">

      {/* ── Header ── */}
      <div className="aichat__header">
        <div className="aichat__header-left">
          <span className={`aichat__status-dot ${isActive ? 'online' : ''}`} />
          <span className="aichat__header-label">AI ANALYST</span>
        </div>
        {isActive && loading && (
          <span className="aichat__processing">PROCESSING ···</span>
        )}
        {isActive && messages.length > 0 && !loading && (
          <button className="aichat__clear" onClick={clearChat}>CLEAR</button>
        )}
      </div>

      {/* ── Messages ── */}
      <div className="aichat__messages">
        {!isActive ? (
          <div className="aichat__offline">
            <div className="aichat__offline-icon">
              <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
                <circle cx="16" cy="16" r="14" stroke="currentColor" strokeWidth="1.2"/>
                <path d="M10 16h12M16 10v12" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" opacity="0.4"/>
                <circle cx="16" cy="16" r="3" fill="currentColor" opacity="0.3"/>
              </svg>
            </div>
            <span className="aichat__offline-title">ANALYST OFFLINE</span>
            <span className="aichat__offline-sub">Complete a scan to activate</span>
          </div>
        ) : (
          <>
            {/* Boot lines */}
            {bootLines.length > 0 && (
              <div className="aichat__boot">
                {bootLines.map((line, i) => (
                  <div key={i} className="aichat__boot-line" style={{ animationDelay: `${i * 120}ms` }}>
                    <span className="aichat__boot-arrow">▸</span>
                    <span>{line}</span>
                  </div>
                ))}
              </div>
            )}

            {/* Suggestion chips */}
            {showChips && messages.length === 0 && (
              <div className="aichat__chips">
                {SUGGESTIONS.map((s, i) => (
                  <button
                    key={i}
                    className="aichat__chip"
                    onClick={() => sendMessage(s)}
                  >
                    {s}
                  </button>
                ))}
              </div>
            )}

            {/* Messages */}
            {messages.map((msg, i) => (
              <div key={i} className={`aichat__msg aichat__msg--${msg.role}`}>
                <div className="aichat__msg-header">
                  <span className="aichat__msg-role">
                    {msg.role === 'user' ? 'YOU' : 'ANALYST'}
                  </span>
                  <span className="aichat__msg-time">{formatTime(msg.ts)}</span>
                </div>
                <div className="aichat__msg-body">{msg.text}</div>
              </div>
            ))}

            {/* Typing */}
            {loading && (
              <div className="aichat__msg aichat__msg--ai">
                <div className="aichat__msg-header">
                  <span className="aichat__msg-role">ANALYST</span>
                </div>
                <div className="aichat__typing-dots">
                  <span /><span /><span />
                </div>
              </div>
            )}

            <div ref={bottomRef} />
          </>
        )}
      </div>

      {/* ── Input ── */}
      <div className="aichat__input-wrap">
        <div className={`aichat__input-box${isActive ? ' active' : ''}`}>
          <input
            ref={inputRef}
            className="aichat__input"
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={isActive ? 'Ask the analyst anything...' : 'Scan an APK to activate'}
            disabled={!isActive || loading}
            maxLength={500}
          />
          <button
            className={`aichat__send${hasText && !loading ? ' ready' : ''}`}
            onClick={() => sendMessage(input)}
            disabled={!isActive || !hasText || loading}
          >
            <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
              <path d="M1 7h12M7 1l6 6-6 6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </button>
        </div>
      </div>

    </div>
  )
}
