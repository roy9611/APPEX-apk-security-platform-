"""
secret_scanner.py — Scans decompiled source files for hardcoded secrets and high-entropy strings.

Uses two detection methods:
  1. Regex patterns (SECRET_PATTERNS from config) — finds well-known credential formats.
  2. Shannon entropy — flags suspiciously random strings near sensitive keywords.
"""

import math
from pathlib import Path

import config
from models import Finding, ModuleResult

EVIDENCE_MAX_LEN = 60
_SEVERITY_ORDER  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Patterns whose matches are always CRITICAL
_CRITICAL_PATTERN_NAMES = {
    "AWS Access Key ID",
    "AWS Secret Key",
    "Stripe Live Secret Key",
    "Private Key Block",
}


def calculate_entropy(text: str) -> float:
    """
    Calculates Shannon entropy of a string.
    High entropy (> 4.5) in a short token near a keyword indicates a random secret.
    Returns a float; returns 0.0 for empty input.
    """
    if not text:
        return 0.0
    frequency = {}
    for char in text:
        frequency[char] = frequency.get(char, 0) + 1
    total   = len(text)
    entropy = 0.0
    for count in frequency.values():
        probability = count / total
        entropy    -= probability * math.log2(probability)
    return entropy


def scan_file_for_secrets(file_path: Path) -> list:
    """
    Scans a single file for hardcoded secrets using regex patterns and entropy analysis.
    Returns a list of Finding objects. Never raises — I/O errors return an empty list.
    """
    findings = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    lines = content.splitlines()
    for line_number, line in enumerate(lines, start=1):

        # ── Regex-based detection ─────────────────────────────────────────────
        for pattern_name, pattern in config.SECRET_PATTERNS.items():
            match = pattern.search(line)
            if match:
                evidence = match.group(0)[:EVIDENCE_MAX_LEN]
                severity = "CRITICAL" if pattern_name in _CRITICAL_PATTERN_NAMES else "HIGH"
                findings.append(Finding(
                    title=f"Hardcoded {pattern_name}",
                    detail=(
                        f"A {pattern_name} was found hardcoded in the source. "
                        f"Anyone who decompiles this APK can extract it and use it to "
                        f"access the associated service."
                    ),
                    severity=severity,
                    location=f"{file_path.name}:{line_number}",
                    evidence=evidence,
                ))

        # ── Entropy-based detection ───────────────────────────────────────────
        # Only scan lines that contain at least one sensitive keyword
        line_lower = line.lower()
        has_keyword = any(kw in line_lower for kw in config.ENTROPY_KEYWORDS)
        if has_keyword:
            tokens = line.split()
            for token in tokens:
                # Strip common string delimiters before measuring entropy
                clean_token = token.strip("\"',;()[]{}=:+/*\\")
                if len(clean_token) < 16:
                    continue
                entropy = calculate_entropy(clean_token)
                if entropy > config.ENTROPY_THRESHOLD:
                    evidence = clean_token[:EVIDENCE_MAX_LEN]
                    findings.append(Finding(
                        title="High-Entropy String Near Sensitive Keyword",
                        detail=(
                            f"A string with entropy {entropy:.2f} (threshold {config.ENTROPY_THRESHOLD}) "
                            f"was found adjacent to a sensitive keyword. "
                            f"High randomness in a short token strongly indicates a hardcoded "
                            f"secret, API key, or cryptographic material."
                        ),
                        severity="HIGH",
                        location=f"{file_path.name}:{line_number}",
                        evidence=evidence,
                    ))

    return findings


def analyze_secrets(workspace_paths: dict) -> ModuleResult:
    """
    Collects all relevant files across the three analysis directories and scans each one.
    Deduplicates results by evidence string to prevent the same secret from appearing
    dozens of times across multiple Java class files.
    Returns a ModuleResult.
    """
    raw_dir     = Path(workspace_paths["raw_dir"])
    apktool_dir = Path(workspace_paths["apktool_dir"])
    jadx_dir    = Path(workspace_paths["jadx_dir"])
    errors      = []

    files_to_scan = []

    # All Java source files produced by jadx
    if jadx_dir.exists():
        files_to_scan.extend(jadx_dir.rglob("*.java"))

    # Decoded string resources from apktool
    strings_xml = apktool_dir / "res" / "values" / "strings.xml"
    if strings_xml.exists():
        files_to_scan.append(strings_xml)

    # Everything inside assets/
    assets_dir = raw_dir / "assets"
    if assets_dir.exists():
        for asset_file in assets_dir.rglob("*"):
            if asset_file.is_file():
                files_to_scan.append(asset_file)

    # JSON config files in the raw APK root (e.g. google-services.json)
    if raw_dir.exists():
        files_to_scan.extend(raw_dir.rglob("*.json"))

    all_findings = []
    seen_evidence = set()

    for file_path in files_to_scan:
        if not file_path.is_file():
            continue
        try:
            file_findings = scan_file_for_secrets(file_path)
            for finding in file_findings:
                if finding.evidence not in seen_evidence:
                    seen_evidence.add(finding.evidence)
                    all_findings.append(finding)
        except Exception as exc:
            errors.append(f"Error scanning {file_path.name}: {exc}")

    highest = _highest_severity(all_findings)
    return ModuleResult(module="secrets", severity=highest, findings=all_findings, errors=errors)


def _highest_severity(findings: list) -> str:
    for level in _SEVERITY_ORDER:
        if any(f.severity == level for f in findings):
            return level
    return "INFO"
