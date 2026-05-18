import { useState } from 'react'
import './FindingCard.css'

const SEV_COLORS = {
  CRITICAL: 'var(--sev-critical)',
  HIGH:     'var(--sev-high)',
  MEDIUM:   'var(--sev-medium)',
  LOW:      'var(--sev-low)',
  INFO:     'var(--sev-info)',
}

const SEV_DIM = {
  CRITICAL: 'var(--sev-critical-dim)',
  HIGH:     'var(--sev-high-dim)',
  MEDIUM:   'var(--sev-medium-dim)',
  LOW:      'var(--sev-low-dim)',
  INFO:     'var(--sev-info-dim)',
}

export default function FindingCard({ finding, sendToChat }) {
  const [expanded, setExpanded] = useState(false)
  const sev     = finding.severity ?? 'INFO'
  const detail  = finding.detail ?? ''
  const longDetail = detail.length > 100

  function handleExplain() {
    sendToChat?.(
      `Explain this finding in detail:\n\nTitle: ${finding.title}\nSeverity: ${sev}\nDetail: ${detail}${finding.evidence ? `\nEvidence: ${finding.evidence}` : ''}`
    )
  }

  return (
    <div className="finding-card">
      <div className="finding-card__top">
        <span
          className="finding-card__badge"
          style={{
            color:      SEV_COLORS[sev],
            background: SEV_DIM[sev],
            border:     `1px solid ${SEV_COLORS[sev]}4d`,
          }}
        >
          {sev}
        </span>
        <span className="finding-card__title">{finding.title}</span>
        {finding.location && (
          <span className="finding-card__location" title={finding.location}>
            {finding.location}
          </span>
        )}
      </div>

      {detail && (
        <>
          <p className={`finding-card__detail${longDetail && !expanded ? ' truncated' : ''}`}>
            {detail}
          </p>
          {longDetail && (
            <button className="finding-card__toggle" onClick={() => setExpanded(e => !e)}>
              {expanded ? 'SHOW LESS ▲' : 'SHOW MORE ▼'}
            </button>
          )}
        </>
      )}

      {finding.evidence && (
        <div className="finding-card__evidence">
          <span className="finding-card__evidence-label">EVIDENCE:</span>
          <div className="finding-card__evidence-code">{finding.evidence}</div>
        </div>
      )}

      <div className="finding-card__bottom">
        <button className="finding-card__explain" onClick={handleExplain}>
          EXPLAIN ►
        </button>
      </div>
    </div>
  )
}
