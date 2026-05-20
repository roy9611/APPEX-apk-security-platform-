import './SectionBar.css'

const SEV_COLORS = {
  CRITICAL: 'var(--sev-critical)',
  HIGH:     'var(--sev-high)',
  MEDIUM:   'var(--sev-medium)',
  LOW:      'var(--sev-low)',
  INFO:     'var(--sev-info)',
}

function totalFindings(findings) {
  if (!findings) return 0
  return Object.values(findings).reduce((s, m) => s + (m?.findings?.length ?? 0), 0)
}

export default function SectionBar({ appState, scanData, onNewScan }) {
  const appName = scanData?.app_name ?? null

  function handleExport() {
    if (!scanData) return
    const blob = new Blob([JSON.stringify(scanData, null, 2)], { type: 'application/json' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = `appex-${scanData.scan_id ?? 'report'}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  function handleCopy() {
    if (!scanData) return
    navigator.clipboard.writeText(JSON.stringify(scanData, null, 2)).catch(() => {})
  }

  const total = totalFindings(scanData?.findings)

  return (
    <div className="sectionbar">
      <div className="sectionbar__breadcrumb">
        <span className="sectionbar__crumb">AppEX</span>
        <span className="sectionbar__crumb-sep">›</span>
        <span className="sectionbar__crumb">STATIC ANALYSIS</span>
        <span className="sectionbar__crumb-sep">›</span>
        <span className={`sectionbar__crumb${appName ? ' active' : ''}`}>
          {appName ?? 'NO TARGET'}
        </span>
      </div>

      <div className="sectionbar__status">
        {appState === 'empty' && (
          <span className="sectionbar__status-idle">
            AWAITING TARGET · DROP APK TO BEGIN
            <span className="sectionbar__blink"> _</span>
          </span>
        )}
        {(appState === 'uploading' || appState === 'scanning') && (
          <span className="sectionbar__status-scanning">
            <span className="spinner spinner-sm" />
            ANALYZING
            {scanData?.status === 'running' && scanData?.current_module && (
              <> · <span className="sectionbar__status-module">
                {scanData.current_module.toUpperCase()}
              </span></>
            )}
            <span className="sectionbar__dots"> ···</span>
          </span>
        )}
        {appState === 'complete' && scanData && (
          <span className="sectionbar__status-complete">
            <span className="sectionbar__status-complete-text">
              SCAN COMPLETE · {total} FINDINGS · RISK:&nbsp;
            </span>
            <span
              className="sectionbar__status-level"
              style={{ color: SEV_COLORS[scanData.risk_level] ?? 'var(--text-secondary)' }}
            >
              {scanData.risk_level}
            </span>
          </span>
        )}
      </div>

      <div className="sectionbar__actions">
        <button className="sectionbar__btn" onClick={onNewScan}>
          NEW SCAN
        </button>
        {appState === 'complete' && (
          <>
            <button className="sectionbar__btn" onClick={handleExport}>
              EXPORT JSON
            </button>
            <button className="sectionbar__btn" onClick={handleCopy}>
              COPY REPORT
            </button>
          </>
        )}
      </div>
    </div>
  )
}
