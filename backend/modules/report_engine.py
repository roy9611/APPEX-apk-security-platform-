"""
report_engine.py — Builds the final ScanResult from all module outputs.

calculate_risk_score  — sums severity weights and normalises to 0-100.
generate_remediation  — maps finding titles to specific developer action items.
build_scan_result     — assembles the complete ScanResult dataclass.
"""

from pathlib import Path

import config
from models import ModuleResult, ScanResult

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Normalisation baseline: a scan with ~300 raw weight points maps to 100%
_SCORE_NORMALISE_DIVISOR = 300


def calculate_risk_score(all_results: dict) -> tuple:
    """
    Sums SEVERITY_WEIGHTS for every finding across all module results.
    Normalises the raw sum to an integer 0-100 score.
    Maps score to a risk level label.
    Returns (int score, str level).
    """
    raw_score = 0

    for module_result in all_results.values():
        if isinstance(module_result, dict):
            findings = module_result.get("findings", [])
            for finding in findings:
                sev = finding.get("severity", "INFO") if isinstance(finding, dict) else finding.severity
                raw_score += config.SEVERITY_WEIGHTS.get(sev, 0)
        else:
            for finding in module_result.findings:
                raw_score += config.SEVERITY_WEIGHTS.get(finding.severity, 0)

    # Normalise to 0-100; cap at 100
    normalised = min(100, int((raw_score / _SCORE_NORMALISE_DIVISOR) * 100))

    if normalised >= 75:
        level = "CRITICAL"
    elif normalised >= 50:
        level = "HIGH"
    elif normalised >= 25:
        level = "MEDIUM"
    elif normalised >= 10:
        level = "LOW"
    else:
        level = "INFO"

    return normalised, level


def generate_remediation(all_results: dict) -> list:
    """
    Inspects all findings across modules and returns specific, ordered remediation steps.
    CRITICAL findings appear first, then HIGH, then everything else.
    Duplicate actions are removed while preserving order.
    """
    critical_actions = []
    high_actions     = []
    other_actions    = []

    for module_result in all_results.values():
        findings = []
        if isinstance(module_result, dict):
            raw = module_result.get("findings", [])
            findings = raw
        else:
            findings = module_result.findings

        for finding in findings:
            title    = finding.get("title", "")    if isinstance(finding, dict) else finding.title
            severity = finding.get("severity", "") if isinstance(finding, dict) else finding.severity
            action   = _title_to_action(title)
            if not action:
                continue
            if severity == "CRITICAL":
                critical_actions.append(action)
            elif severity == "HIGH":
                high_actions.append(action)
            else:
                other_actions.append(action)

    # Deduplicate while preserving insertion order
    seen        = set()
    remediation = []
    for action in critical_actions + high_actions + other_actions:
        if action not in seen:
            seen.add(action)
            remediation.append(action)

    return remediation


def _title_to_action(title: str) -> str:
    """
    Maps a finding title to a concrete remediation instruction.
    Returns an empty string if the title doesn't match any known pattern.
    """
    t = title.lower()

    if "debuggable" in t:
        return "Remove android:debuggable='true' from AndroidManifest.xml in all release build configurations."
    if "backup" in t:
        return "Set android:allowBackup='false' or restrict backup scope with android:fullBackupContent rules."
    if "unprotected exported" in t or ("exported" in t and "unprotected" in t):
        return "Add android:permission or android:exported='false' to all exported components that should not be publicly accessible."
    if "trustmanager" in t or ("certificate" in t and "accept" in t):
        return "Remove the custom TrustManager — never override checkServerTrusted() with an empty body. Use the system default TLS validation."
    if "hostname" in t and "true" in t:
        return "Remove the HostnameVerifier that returns true — use Android's default hostname verification."
    if "open firebase" in t:
        return "Add Firebase Realtime Database security rules to deny unauthenticated read and write access."
    if "aws" in t or "stripe" in t or "private key" in t:
        return "Rotate compromised credentials immediately and store them server-side — never embed credentials in APK source."
    if "hardcoded" in t or "high-entropy" in t:
        return "Remove all hardcoded secrets and API keys from source code; use a server-side configuration or a secrets manager."
    if "cleartext" in t and "url" in t:
        return "Replace all http:// endpoints with https:// and remove android:usesCleartextTraffic='true'."
    if "cleartext" in t:
        return "Replace all cleartext HTTP connections with HTTPS and remove cleartextTrafficPermitted='true' from network security config."
    if "user-installed certificates" in t or "user" in t and "certificate" in t:
        return "Remove <certificates src='user'/> from network security config to prevent interception with user-installed CAs."
    if "world-readable" in t or "world-writable" in t:
        return "Replace MODE_WORLD_READABLE and MODE_WORLD_WRITEABLE with MODE_PRIVATE for all file and SharedPreferences operations."
    if "external storage" in t:
        return "Store sensitive files in internal storage (getFilesDir()) rather than external storage."
    if "unencrypted sqlite" in t:
        return "Replace SQLiteOpenHelper with SQLCipher to encrypt the database at rest."
    if "certificate pinning" in t or "pin-set" in t:
        return "Implement certificate pinning with a <pin-set> in res/xml/network_security_config.xml."
    if "combination" in t or "exfiltration" in t or "surveillance" in t:
        return "Audit the declared permissions list and remove all permissions not essential to the app's core functionality."

    return ""


def build_scan_result(
    scan_id:            str,
    apk_path:           str,
    all_module_results: dict,
    ai_summary:         str,
    scan_duration:      float,
    package_name:       str = "unknown",
) -> ScanResult:
    """
    Assembles the final ScanResult from module outputs, a computed risk score,
    generated remediation steps, and an AI-written summary.
    Returns a fully populated ScanResult ready for serialisation.
    """
    app_name   = Path(apk_path).stem if apk_path else "Unknown"
    risk_score, risk_level = calculate_risk_score(all_module_results)
    remediation            = generate_remediation(all_module_results)

    # Serialise ModuleResult objects to plain dicts for the findings field
    findings_dict = {}
    for module_name, module_result in all_module_results.items():
        if isinstance(module_result, ModuleResult):
            findings_dict[module_name] = module_result.model_dump()
        else:
            findings_dict[module_name] = module_result

    return ScanResult(
        scan_id       = scan_id,
        app_name      = app_name,
        package_name  = package_name,
        risk_score    = risk_score,
        risk_level    = risk_level,
        scan_duration = scan_duration,
        status        = "complete",
        findings      = findings_dict,
        ai_summary    = ai_summary,
        remediation   = remediation,
    )
