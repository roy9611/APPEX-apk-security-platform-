import { useEffect, useState } from 'react'
import './TitleBar.css'

const TABS = [
  { id: 'upload',       label: '01 · UPLOAD' },
  { id: 'analysis',     label: '02 · ANALYSIS' },
  { id: 'findings',     label: '03 · FINDINGS' },
  { id: 'intelligence', label: '04 · INTELLIGENCE' },
]

export default function TitleBar({ isBackendOnline, scanData, appState, activeTab, onTabClick }) {
  const [time, setTime] = useState('')

  useEffect(() => {
    function tick() {
      const now = new Date()
      const pad = n => String(n).padStart(2, '0')
      setTime(`${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`)
    }
    tick()
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [])

  function handleDownload() {
    if (!scanData) return
    const blob = new Blob([JSON.stringify(scanData, null, 2)], { type: 'application/json' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = `appcheck-${scanData.scan_id ?? 'report'}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="titlebar">
      <div className="titlebar__brand">
        <svg className="titlebar__brand-icon" viewBox="0 0 16 16" fill="none">
          <path
            d="M8 1L2 4v4c0 3.3 2.5 6.4 6 7 3.5-.6 6-3.7 6-7V4L8 1z"
            stroke="currentColor"
            strokeWidth="1.2"
            fill="none"
          />
          <path d="M5.5 8l1.8 1.8 3.2-3.2" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
        <span className="titlebar__brand-name">APPCHECK</span>
        <span className="titlebar__brand-version">v1.0.0</span>
      </div>

      <div className="titlebar__divider" />
      <span className="titlebar__subtitle">APK SECURITY INTELLIGENCE ENGINE</span>

      <nav className="titlebar__nav">
        {TABS.map(tab => (
          <button
            key={tab.id}
            className={`titlebar__tab${activeTab === tab.id ? ' active' : ''}`}
            onClick={() => onTabClick(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <div className="titlebar__right">
        <div className="titlebar__status">
          <span className={`titlebar__status-dot ${isBackendOnline ? 'online' : 'offline'}`} />
          <span className={`titlebar__status-text ${isBackendOnline ? 'online' : ''}`}>
            BACKEND {isBackendOnline ? 'ONLINE' : 'OFFLINE'}
          </span>
        </div>
        <div className="titlebar__divider" />
        <span className="titlebar__clock">{time}</span>
        {appState === 'complete' && scanData && (
          <>
            <div className="titlebar__divider" />
            <button className="titlebar__download" onClick={handleDownload}>
              DOWNLOAD REPORT
            </button>
          </>
        )}
      </div>
    </div>
  )
}
