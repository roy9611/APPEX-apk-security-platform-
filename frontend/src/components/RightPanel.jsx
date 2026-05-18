import { BarChart, LineGraph } from './Charts.jsx'
import AIChat from './AIChat.jsx'
import './RightPanel.css'

export default function RightPanel({
  scanData, appState, scanId,
  externalMessage, onExternalMessageHandled,
}) {
  return (
    <div className="rightpanel">
      <div className="rightpanel__section rightpanel__section--bar">
        <BarChart scanData={appState === 'complete' ? scanData : null} />
      </div>

      <div className="rightpanel__section rightpanel__section--line">
        <LineGraph scanData={appState === 'complete' ? scanData : null} />
      </div>

      <div className="rightpanel__section rightpanel__section--chat">
        <AIChat
          scanId={scanId}
          scanData={scanData}
          appState={appState}
          externalMessage={externalMessage}
          onExternalMessageHandled={onExternalMessageHandled}
        />
      </div>
    </div>
  )
}
