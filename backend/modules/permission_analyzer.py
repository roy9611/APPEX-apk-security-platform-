"""
permission_analyzer.py — Analyzes uses-permission declarations in AndroidManifest.xml.

Creates findings for individually dangerous permissions and for dangerous pairs that
together enable data exfiltration patterns (e.g. READ_SMS + INTERNET).
"""

import xml.etree.ElementTree as ET
from pathlib import Path

import config
from models import Finding, ModuleResult

NS = "{http://schemas.android.com/apk/res/android}"

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def analyze_permissions(workspace_paths: dict) -> ModuleResult:
    """
    Reads all uses-permission entries from AndroidManifest.xml.
    Produces findings for dangerous/high-risk permissions and dangerous combinations.
    Returns a ModuleResult.
    """
    apktool_dir   = Path(workspace_paths["apktool_dir"])
    manifest_path = apktool_dir / "AndroidManifest.xml"
    findings      = []
    errors        = []

    if not manifest_path.exists():
        return ModuleResult(
            module="permissions",
            severity="INFO",
            findings=[],
            errors=["AndroidManifest.xml not found — permission analysis skipped"],
        )

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        return ModuleResult(
            module="permissions",
            severity="INFO",
            findings=[],
            errors=[f"Failed to parse AndroidManifest.xml: {exc}"],
        )

    # Collect all declared permission names
    declared_permissions = set()
    for perm_tag in root.findall("uses-permission"):
        perm_name = perm_tag.get(f"{NS}name", "")
        if perm_name:
            declared_permissions.add(perm_name)

    dangerous_count = 0

    # Individual permission findings (DANGEROUS and HIGH only)
    for perm_name in sorted(declared_permissions):
        perm_info = config.PERMISSION_RISK_MAP.get(perm_name)
        if not perm_info:
            continue
        level = perm_info["level"]
        if level not in ("DANGEROUS", "HIGH"):
            continue

        dangerous_count += 1
        severity   = "CRITICAL" if level == "DANGEROUS" else "HIGH"
        short_name = perm_name.split(".")[-1]

        findings.append(Finding(
            title=f"Dangerous Permission: {short_name}",
            detail=perm_info["reason"],
            severity=severity,
            location="AndroidManifest.xml",
            evidence=f'<uses-permission android:name="{perm_name}" />',
        ))

    # Dangerous combination findings
    for perm_a, perm_b, description in config.DANGEROUS_COMBINATIONS:
        if perm_a in declared_permissions and perm_b in declared_permissions:
            short_a = perm_a.split(".")[-1]
            short_b = perm_b.split(".")[-1]
            findings.append(Finding(
                title=f"Dangerous Combination: {short_a} + {short_b}",
                detail=description,
                severity="CRITICAL",
                location="AndroidManifest.xml",
                evidence=f"{perm_a} AND {perm_b} both declared",
            ))

    # Summary INFO finding
    findings.append(Finding(
        title="Permission Summary",
        detail=(
            f"Application declares {len(declared_permissions)} total permissions, "
            f"of which {dangerous_count} are classified as DANGEROUS or HIGH risk."
        ),
        severity="INFO",
        location="AndroidManifest.xml",
        evidence=f"Total permissions: {len(declared_permissions)} | Dangerous/High: {dangerous_count}",
    ))

    highest = _highest_severity(findings)
    return ModuleResult(module="permissions", severity=highest, findings=findings, errors=errors)


def _highest_severity(findings: list) -> str:
    for level in _SEVERITY_ORDER:
        if any(f.severity == level for f in findings):
            return level
    return "INFO"
