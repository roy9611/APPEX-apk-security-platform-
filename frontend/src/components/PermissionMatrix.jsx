import './PermissionMatrix.css'

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

const SEV_COLORS = {
  CRITICAL: 'var(--sev-critical)',
  HIGH:     'var(--sev-high)',
  MEDIUM:   'var(--sev-medium)',
  LOW:      'var(--sev-low)',
  INFO:     'var(--sev-info)',
}

const SEV_BG = {
  CRITICAL: 'rgba(255,69,58,0.10)',
  HIGH:     'rgba(255,159,10,0.10)',
  MEDIUM:   'rgba(255,214,10,0.10)',
  LOW:      'rgba(10,132,255,0.10)',
  INFO:     'rgba(110,110,115,0.10)',
}

const SEV_BORDER = {
  CRITICAL: 'rgba(255,69,58,0.35)',
  HIGH:     'rgba(255,159,10,0.35)',
  MEDIUM:   'rgba(255,214,10,0.35)',
  LOW:      'rgba(10,132,255,0.35)',
  INFO:     'rgba(110,110,115,0.35)',
}

function permName(title) {
  return title
    .replace(/^Dangerous Permission:\s*/i, '')
    .replace(/^android\.permission\./i, '')
    .replace(/_/g, ' ')
}

export default function PermissionMatrix({ permissionsModule }) {
  if (!permissionsModule) return null

  const findings = permissionsModule.findings ?? []

  const combos    = findings.filter(f => f.title?.toLowerCase().includes('combination'))
  const regular   = findings.filter(f => !f.title?.toLowerCase().includes('combination'))
                            .filter(f => !f.title?.toLowerCase().startsWith('permission summary'))

  const grouped = {}
  SEV_ORDER.forEach(s => { grouped[s] = [] })
  regular.forEach(f => {
    const s = f.severity ?? 'INFO'
    if (grouped[s]) grouped[s].push(f)
    else grouped['INFO'].push(f)
  })

  return (
    <div className="perm-matrix">
      {SEV_ORDER.filter(s => grouped[s].length > 0).map(sev => (
        <div key={sev} className="perm-matrix__group">
          <span
            className="perm-matrix__group-label"
            style={{ color: SEV_COLORS[sev] }}
          >
            {sev}
          </span>
          <div className="perm-matrix__pills">
            {grouped[sev].map((f, i) => (
              <span
                key={i}
                className="perm-matrix__pill"
                title={f.detail}
                style={{
                  color:        SEV_COLORS[sev],
                  background:   SEV_BG[sev],
                  borderColor:  SEV_BORDER[sev],
                }}
              >
                {permName(f.title)}
              </span>
            ))}
          </div>
        </div>
      ))}

      {combos.length > 0 && (
        <div className="perm-matrix__combos">
          <span className="perm-matrix__group-label" style={{ color: 'var(--sev-critical)' }}>
            ⚠ Dangerous Combinations
          </span>
          {combos.map((f, i) => (
            <div key={i} className="perm-matrix__combo-card">
              <span className="perm-matrix__combo-title">{f.title}</span>
              <span className="perm-matrix__combo-detail">{f.detail}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
