"""
storage_analyzer.py — Scans decompiled Java source for insecure local data storage patterns.

Detects: world-readable/writable file modes, external storage use, unencrypted SQLite,
and world-readable SharedPreferences.
"""

from pathlib import Path

from models import Finding, ModuleResult

EVIDENCE_MAX_LEN = 60
_SEVERITY_ORDER  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def analyze_storage(workspace_paths: dict) -> ModuleResult:
    """
    Iterates all .java files in jadx_dir and checks each for insecure storage API usage.
    Returns a ModuleResult. Never raises — per-file errors are stored in errors[].
    """
    jadx_dir = Path(workspace_paths["jadx_dir"])
    findings = []
    errors   = []

    if not jadx_dir.exists():
        return ModuleResult(
            module="storage",
            severity="INFO",
            findings=[Finding(
                title="No Decompiled Java Source Available",
                detail="jadx output directory not found; storage analysis could not be performed.",
                severity="INFO",
                location="N/A",
                evidence=f"jadx_dir missing: {jadx_dir}",
            )],
            errors=[f"jadx_dir not found: {jadx_dir}"],
        )

    for java_file in jadx_dir.rglob("*.java"):
        try:
            _scan_java_file(java_file, findings)
        except Exception as exc:
            errors.append(f"Error scanning {java_file.name}: {exc}")

    highest = _highest_severity(findings)
    return ModuleResult(module="storage", severity=highest, findings=findings, errors=errors)


def _scan_java_file(java_file: Path, findings: list):
    """
    Checks a single .java file for insecure storage patterns.
    Tracks whether SQLCipher is imported to avoid false positives on encrypted databases.
    """
    try:
        content = java_file.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return

    has_sqlcipher = (
        "net.zetetic.database" in content
        or ("sqlcipher" in content.lower() and "import" in content.lower())
    )

    lines = content.splitlines()
    for line_number, line in enumerate(lines, start=1):
        evidence_prefix = f"{java_file.name}:{line_number}: "

        if "MODE_WORLD_READABLE" in line:
            # Combine SharedPreferences + world-readable into one higher-severity finding
            if "SharedPreferences" in line or "getSharedPreferences" in line:
                findings.append(Finding(
                    title="World-Readable SharedPreferences",
                    detail=(
                        "SharedPreferences opened with MODE_WORLD_READABLE allows any installed "
                        "app on the device to read the preferences file directly. Tokens, "
                        "passwords, and session IDs stored there are exposed to all apps."
                    ),
                    severity="HIGH",
                    location=f"{java_file.name}:{line_number}",
                    evidence=(evidence_prefix + line.strip())[:EVIDENCE_MAX_LEN],
                ))
            else:
                findings.append(Finding(
                    title="World-Readable File Mode",
                    detail=(
                        "MODE_WORLD_READABLE makes the created file readable by any app on "
                        "the device. Sensitive data stored with this mode is accessible to "
                        "malicious apps without any special permissions."
                    ),
                    severity="HIGH",
                    location=f"{java_file.name}:{line_number}",
                    evidence=(evidence_prefix + line.strip())[:EVIDENCE_MAX_LEN],
                ))

        elif "MODE_WORLD_WRITEABLE" in line:
            findings.append(Finding(
                title="World-Writable File Mode",
                detail=(
                    "MODE_WORLD_WRITEABLE allows any app on the device to overwrite this file. "
                    "Attackers can corrupt application data or inject malicious content."
                ),
                severity="HIGH",
                location=f"{java_file.name}:{line_number}",
                evidence=(evidence_prefix + line.strip())[:EVIDENCE_MAX_LEN],
            ))

        elif "getExternalStorageDirectory()" in line or "getExternalFilesDir(" in line:
            findings.append(Finding(
                title="Sensitive Data Written to External Storage",
                detail=(
                    "External storage is accessible to any app holding READ_EXTERNAL_STORAGE "
                    "and is visible over USB without root on many devices. Sensitive files "
                    "should be stored in internal storage (getFilesDir()) instead."
                ),
                severity="MEDIUM",
                location=f"{java_file.name}:{line_number}",
                evidence=(evidence_prefix + line.strip())[:EVIDENCE_MAX_LEN],
            ))

        elif "openOrCreateDatabase(" in line and not has_sqlcipher:
            findings.append(Finding(
                title="Unencrypted SQLite Database",
                detail=(
                    "The app creates a SQLite database without SQLCipher encryption. "
                    "The database file is stored in plaintext and is accessible to root "
                    "users and forensic imaging tools."
                ),
                severity="MEDIUM",
                location=f"{java_file.name}:{line_number}",
                evidence=(evidence_prefix + line.strip())[:EVIDENCE_MAX_LEN],
            ))


def _highest_severity(findings: list) -> str:
    for level in _SEVERITY_ORDER:
        if any(f.severity == level for f in findings):
            return level
    return "INFO"
