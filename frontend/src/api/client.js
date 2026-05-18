/**
 * client.js — All API calls to the APK Security Intelligence backend.
 * Vite proxies /api/* to http://localhost:8000 in dev mode.
 * Every function throws a descriptive Error on non-ok HTTP responses.
 */

async function handleResponse(res) {
  if (!res.ok) {
    let message = `HTTP ${res.status}`
    try {
      const body = await res.json()
      message = body.detail || body.message || message
    } catch (_) {
      message = res.statusText || message
    }
    throw new Error(message)
  }
  return res.json()
}

/**
 * Upload an APK file and start a scan.
 * Returns { scan_id, status, message }
 */
export async function uploadAPK(file) {
  const form = new FormData()
  form.append('file', file)
  const res = await fetch('/api/scan', { method: 'POST', body: form })
  return handleResponse(res)
}

/**
 * Poll the current status of a running or queued scan.
 * Returns the full scan state including current_module and partial findings.
 */
export async function getScanStatus(scanId) {
  const res = await fetch(`/api/scan/${scanId}`)
  return handleResponse(res)
}

/**
 * Fetch the completed scan report.
 * Returns the full result with all module findings, risk score, and AI summary.
 */
export async function getReport(scanId) {
  const res = await fetch(`/api/report/${scanId}`)
  return handleResponse(res)
}

/**
 * Send a chat message about a completed scan.
 * Returns { response, scan_id }
 */
export async function sendChatMessage(scanId, message) {
  const res = await fetch('/api/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scan_id: scanId, message }),
  })
  return handleResponse(res)
}

/**
 * Check backend health.
 * Returns { app_name, status, version }
 */
export async function checkHealth() {
  const res = await fetch('/api/health')
  return handleResponse(res)
}

/**
 * Maps a severity string to its CSS variable string.
 * Usage: style={{ color: getSeverityColor('CRITICAL') }}
 */
export function getSeverityColor(severity) {
  const map = {
    CRITICAL: 'var(--severity-critical)',
    HIGH:     'var(--severity-high)',
    MEDIUM:   'var(--severity-medium)',
    LOW:      'var(--severity-low)',
    INFO:     'var(--severity-info)',
  }
  return map[severity] ?? 'var(--severity-info)'
}
