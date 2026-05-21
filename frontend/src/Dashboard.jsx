import { useState, useEffect, useRef, useCallback } from 'react'
import { uploadAPK, getScanStatus, getReport, checkHealth } from './api/client.js'
import TitleBar    from './components/TitleBar.jsx'
import SectionBar  from './components/SectionBar.jsx'
import LeftSidebar from './components/LeftSidebar.jsx'
import MainContent from './components/MainContent.jsx'
import RightPanel  from './components/RightPanel.jsx'
import StatusBar   from './components/StatusBar.jsx'
import './Dashboard.css'

const POLL_INTERVAL = 2000
const HISTORY_KEY   = 'apk_scan_history'
const MAX_HISTORY   = 5

function loadHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY) ?? '[]') }
  catch { return [] }
}

function saveHistory(entry, existing) {
  const updated = [entry, ...existing.filter(h => h.scan_id !== entry.scan_id)]
    .slice(0, MAX_HISTORY)
  localStorage.setItem(HISTORY_KEY, JSON.stringify(updated))
  return updated
}

const SECTION_IDS = ['upload','analysis','findings','intelligence']
const TAB_IDS     = ['upload','analysis','findings','intelligence']

export default function Dashboard() {
  const [appState,      setAppState]     = useState('empty')
  const [scanId,        setScanId]       = useState(null)
  const [scanData,      setScanData]     = useState(null)
  const [activeModule,  setActiveModule] = useState(null)
  const [isBackendOnline, setOnline]     = useState(false)
  const [scanHistory,   setScanHistory]  = useState(loadHistory)
  const [externalMsg,   setExternalMsg]  = useState(null)
  const [activeTab,     setActiveTab]    = useState('upload')

  const intervalRef = useRef(null)

  useEffect(() => {
    checkHealth()
      .then(() => setOnline(true))
      .catch(() => setOnline(false))
  }, [])

  // IntersectionObserver for auto-updating activeTab on scroll
  useEffect(() => {
    if (appState !== 'complete') return

    const observers = []
    SECTION_IDS.forEach(id => {
      const el = document.getElementById(id)
      if (!el) return
      const obs = new IntersectionObserver(
        entries => {
          if (entries[0].isIntersecting) setActiveTab(id)
        },
        { threshold: 0.3 }
      )
      obs.observe(el)
      observers.push(obs)
    })
    return () => observers.forEach(o => o.disconnect())
  }, [appState, scanData])

  function stopPolling() {
    if (intervalRef.current) {
      clearInterval(intervalRef.current)
      intervalRef.current = null
    }
  }

  async function poll(id) {
    try {
      const data = await getScanStatus(id)
      setScanData(prev => ({ ...prev, ...data }))

      if (data.status === 'complete') {
        stopPolling()
        const report = await getReport(id)
        setScanData(report)
        setAppState('complete')
        setScanHistory(prev => saveHistory({
          scan_id:    report.scan_id,
          app_name:   report.app_name,
          risk_level: report.risk_level,
          risk_score: report.risk_score,
          timestamp:  Date.now(),
        }, prev))
      } else if (data.status === 'failed') {
        stopPolling()
        setAppState('empty')
      }
    } catch {
      stopPolling()
      setAppState('empty')
    }
  }

  async function uploadFlow(file) {
    setAppState('uploading')
    setScanData(null)
    setScanId(null)
    stopPolling()

    try {
      const res = await uploadAPK(file)
      const id  = res.scan_id
      setScanId(id)
      setAppState('scanning')
      setScanData({ status: 'queued', app_name: file.name.replace('.apk', '') })

      await poll(id)
      intervalRef.current = setInterval(() => poll(id), POLL_INTERVAL)
    } catch {
      setAppState('empty')
    }
  }

  async function loadFromHistory(histScanId) {
    try {
      stopPolling()
      setAppState('scanning')
      const report = await getReport(histScanId)
      setScanId(histScanId)
      setScanData(report)
      setAppState('complete')
    } catch {
      setAppState('empty')
    }
  }

  function handleNewScan() {
    stopPolling()
    setAppState('empty')
    setScanData(null)
    setScanId(null)
    setActiveModule(null)
    setActiveTab('upload')
  }

  const sendToChat = useCallback((message) => {
    setExternalMsg(message)
  }, [])

  const handleExternalHandled = useCallback(() => {
    setExternalMsg(null)
  }, [])

  function handleTabClick(tabId) {
    setActiveTab(tabId)
    if (appState === 'complete') {
      const el = document.getElementById(tabId)
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  }

  useEffect(() => () => stopPolling(), [])

  return (
    <div className="dashboard">
      <TitleBar
        isBackendOnline={isBackendOnline}
        scanData={scanData}
        appState={appState}
        activeTab={activeTab}
        onTabClick={handleTabClick}
      />
      <SectionBar
        appState={appState}
        scanData={scanData}
        onNewScan={handleNewScan}
      />
      <LeftSidebar
        uploadFlow={uploadFlow}
        appState={appState}
        scanData={scanData}
        activeModule={activeModule}
        setActiveModule={setActiveModule}
        scanHistory={scanHistory}
        onLoadHistory={loadFromHistory}
      />
      <MainContent
        appState={appState}
        scanData={scanData}
        activeModule={activeModule}
        scanId={scanId}
        sendToChat={sendToChat}
      />
      <RightPanel
        scanData={scanData}
        appState={appState}
        scanId={scanId}
        externalMessage={externalMsg}
        onExternalMessageHandled={handleExternalHandled}
      />
      <StatusBar
        appState={appState}
        scanData={scanData}
      />
    </div>
  )
}
