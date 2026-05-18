import './StatusBar.css'

const SEV_COLORS = {
  CRITICAL: 'var(--sev-critical)',
  HIGH:     'var(--sev-high)',
  MEDIUM:   'var(--sev-medium)',
  LOW:      'var(--sev-low)',
  INFO:     'var(--sev-info)',
}

const MODULES = ['MANIFEST','DEX BYTECODE','PERMISSIONS','SECRETS','FIREBASE','SSL/TLS','STORAGE','AI REPORT']

function totalFindings(findings) {
  if (!findings) return 0
  return Object.values(findings).reduce((s, m) => s + (m?.findings?.length ?? 0), 0)
}

export default function StatusBar({ appState, scanData }) {
  const total = totalFindings(scanData?.findings)
  const level = scanData?.risk_level

  return (
    <div className="statusbar">
      <div className="statusbar__left">
        {appState === 'empty' && (
          <span className="statusbar__static">
            APPCHECK STATIC ANALYSIS ENGINE · READY
          </span>
        )}

        {(appState === 'uploading' || appState === 'scanning') && (
          <div className="statusbar__marquee-wrap">
            <div className="statusbar__marquee">
              {[0, 1].map(copy => (
                <span key={copy} className="statusbar__marquee-text">
                  {MODULES.map((mod, i) => (
                    <span key={i}>
                      {i > 0 && ' · '}
                      <span
                        className={
                          scanData?.current_module?.toUpperCase().includes(mod.split(' ')[0])
                            ? 'highlight'
                            : ''
                        }
                      >
                        {mod}
                      </span>
                    </span>
                  ))}
                  {' ···'}
                </span>
              ))}
            </div>
          </div>
        )}

        {appState === 'complete' && scanData && (
          <div className="statusbar__complete">
            <span>SCAN COMPLETE · {total} FINDINGS DETECTED · RISK LEVEL:&nbsp;</span>
            <span
              className="statusbar__complete-level"
              style={{ color: SEV_COLORS[level] ?? 'var(--text-secondary)' }}
            >
              {level}
            </span>
            {scanData.scan_duration && (
              <span> · DURATION: {Number(scanData.scan_duration).toFixed(1)}s</span>
            )}
          </div>
        )}
      </div>

      <span className="statusbar__center">APPCHECK v1.0.0</span>

      <div className="statusbar__right">
        <span className="statusbar__right-item">PYTHON 3.14</span>
        <span className="statusbar__right-sep">·</span>
        <span className="statusbar__right-item">FASTAPI</span>
        <span className="statusbar__right-sep">·</span>
        <span className="statusbar__right-item">GROQ AI</span>
        <span className="statusbar__right-sep">·</span>
        <span className="statusbar__right-item">STATIC ENGINE</span>
        {appState === 'complete' && scanData && (
          <>
            <span className="statusbar__right-sep">·</span>
            <span
              className="statusbar__findings-count"
              style={{ color: SEV_COLORS[level] ?? 'var(--text-secondary)' }}
            >
              {total} FINDINGS
            </span>
          </>
        )}
      </div>
    </div>
  )
}
