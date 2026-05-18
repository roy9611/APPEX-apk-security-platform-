"""
chat.py — AI-powered chat about a completed APK scan using Groq.

Builds a condensed scan context for the system prompt, then relays the user's
question to Groq and returns the response. Keeps answers under 150 words by default.
Returns a safe fallback string on API failure — never raises.
"""

from groq import Groq

import config

_client   = Groq(api_key=config.GROQ_API_KEY)
_FALLBACK = "I'm having trouble connecting to the AI service right now. Please try again."

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def chat_with_context(message: str, scan_result_dict: dict) -> str:
    """
    Answers a user's question using the full scan result as conversation context.
    Builds a condensed context string (top 10 findings sorted by severity) to
    avoid token overflow. Returns the AI response or a fallback on failure.
    """
    context = _build_chat_context(scan_result_dict)

    system_prompt = (
        "You are an Android security expert assistant. "
        "The user has scanned an APK and you have the full analysis results below. "
        "Answer questions accurately and concisely. "
        "Keep responses under 150 words unless a detailed technical explanation is genuinely needed. "
        "If the user asks about something not present in the scan results, say so clearly "
        "rather than speculating.\n\n"
        f"Scan context:\n{context}"
    )

    try:
        response = _client.chat.completions.create(
            model=config.GROQ_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": message,
                },
            ],
            max_tokens=400,
            temperature=0.4,
        )
        return response.choices[0].message.content.strip()
    except Exception as exc:
        return f"{_FALLBACK} (API error: {exc})"


def _build_chat_context(scan_result_dict: dict) -> str:
    """
    Builds a compact text context for the system prompt.
    Pulls the top 10 findings across all modules, sorted by severity (worst first).
    Truncates detail strings to avoid blowing the context window.
    """
    lines = [
        f"App:         {scan_result_dict.get('app_name', 'Unknown')}",
        f"Package:     {scan_result_dict.get('package_name', 'unknown')}",
        f"Risk Score:  {scan_result_dict.get('risk_score', 0)}/100  ({scan_result_dict.get('risk_level', 'UNKNOWN')})",
        f"AI Summary:  {scan_result_dict.get('ai_summary', 'Not yet generated')}",
        "",
        "Top findings (sorted by severity):",
    ]

    # Flatten all findings from all modules into one list with their module name
    all_findings = []
    findings_dict = scan_result_dict.get("findings", {})
    for module_name, module_data in findings_dict.items():
        if isinstance(module_data, dict):
            raw_findings = module_data.get("findings", [])
        else:
            raw_findings = getattr(module_data, "findings", [])

        for finding in raw_findings:
            if isinstance(finding, dict):
                sev    = finding.get("severity", "INFO")
                title  = finding.get("title", "")
                detail = finding.get("detail", "")
            else:
                sev    = finding.severity
                title  = finding.title
                detail = finding.detail

            sort_key = _SEVERITY_ORDER.index(sev) if sev in _SEVERITY_ORDER else 99
            all_findings.append((sort_key, module_name, sev, title, detail))

    all_findings.sort(key=lambda x: x[0])

    for _, module_name, sev, title, detail in all_findings[:10]:
        detail_snippet = detail[:80] + ("…" if len(detail) > 80 else "")
        lines.append(f"  [{sev}] ({module_name}) {title}: {detail_snippet}")

    return "\n".join(lines)
