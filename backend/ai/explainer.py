"""
explainer.py — Generates a developer-friendly AI explanation for a single security finding.

Takes one finding dict and returns a 2-3 sentence explanation covering what the issue means,
why it is dangerous, and one specific fix. Returns a safe fallback string on API failure.
"""

from groq import Groq

import config

_client   = Groq(api_key=config.GROQ_API_KEY)
_FALLBACK = "Explanation unavailable — please refer to the finding detail text above."


def explain_finding(finding_dict: dict) -> str:
    """
    Accepts a single finding dict and returns a 2-3 sentence developer explanation.
    Covers: what the finding means, why it is dangerous, and one concrete fix.
    Returns a fallback string if the Groq API call fails.
    """
    title    = finding_dict.get("title",    "Unknown Finding")
    detail   = finding_dict.get("detail",   "")
    severity = finding_dict.get("severity", "UNKNOWN")
    location = finding_dict.get("location", "")
    evidence = finding_dict.get("evidence", "")

    prompt = (
        "Explain this Android security finding to a developer in 2-3 sentences.\n"
        "Cover exactly these three points: what it means, why it is dangerous, "
        "and one specific code-level fix.\n\n"
        f"Finding:\n"
        f"  Title:    {title}\n"
        f"  Severity: {severity}\n"
        f"  Location: {location}\n"
        f"  Detail:   {detail}\n"
        f"  Evidence: {evidence}"
    )

    try:
        response = _client.chat.completions.create(
            model=config.GROQ_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "You are a senior Android application security engineer.",
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            max_tokens=200,
            temperature=0.2,
        )
        return response.choices[0].message.content.strip()
    except Exception as exc:
        return f"{_FALLBACK} (API error: {exc})"
