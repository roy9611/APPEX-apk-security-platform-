import { useState } from 'react'
import { BarChart, LineGraph } from './Charts.jsx'
import './RightPanel.css'

function ChartSection({ label, children, defaultCollapsed = false }) {
  const [collapsed, setCollapsed] = useState(defaultCollapsed)

  return (
    <div className={`rightpanel__chart${collapsed ? ' collapsed' : ''}`}>
      <div className="rightpanel__chart-header" onClick={() => setCollapsed(c => !c)}>
        <span className="rightpanel__chart-title">
          {collapsed ? '▶' : '▼'} {label}
        </span>
        <span className="rightpanel__chart-toggle">
          {collapsed ? 'expand' : 'collapse'}
        </span>
      </div>
      <div className="rightpanel__chart-body">
        {children}
      </div>
    </div>
  )
}

export default function RightPanel({ scanData, appState }) {
  const data = appState === 'complete' ? scanData : null
  return (
    <div className="rightpanel">
      <div className="rightpanel__heading">// SCAN ANALYTICS</div>
      <ChartSection label="FINDINGS BY MODULE" defaultCollapsed={false}>
        <BarChart scanData={data} />
      </ChartSection>
      <ChartSection label="SEVERITY DISTRIBUTION" defaultCollapsed={false}>
        <LineGraph scanData={data} />
      </ChartSection>
    </div>
  )
}
