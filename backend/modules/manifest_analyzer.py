"""
manifest_analyzer.py — Parses AndroidManifest.xml to detect dangerous security misconfigurations.

Detects: debuggable flag, backup flag, cleartext traffic flag, and exported components
that have no android:permission guard (accessible to any app on the device).
"""

import xml.etree.ElementTree as ET
from pathlib import Path

from models import Finding, ModuleResult

# Android XML namespace prefix used for all attribute names
NS = "{http://schemas.android.com/apk/res/android}"

# Component tags that can be exported and reached by other apps
COMPONENT_TAGS = ["activity", "service", "receiver", "provider"]

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def analyze_manifest(workspace_paths: dict) -> ModuleResult:
    """
    Parses AndroidManifest.xml from the apktool output directory.
    Returns a ModuleResult containing all findings, or an error entry if parsing fails.
    """
    apktool_dir   = Path(workspace_paths["apktool_dir"])
    manifest_path = apktool_dir / "AndroidManifest.xml"
    findings      = []
    errors        = []

    if not manifest_path.exists():
        return ModuleResult(
            module="manifest",
            severity="INFO",
            findings=[],
            errors=[f"AndroidManifest.xml not found at {manifest_path}"],
        )

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except ET.ParseError as exc:
        return ModuleResult(
            module="manifest",
            severity="INFO",
            findings=[],
            errors=[f"Failed to parse AndroidManifest.xml: {exc}"],
        )

    application = root.find("application")
    if application is not None:
        _check_application_flags(application, findings)
        _check_exported_components(application, findings)
    else:
        errors.append("No <application> element found in AndroidManifest.xml")

    highest = _highest_severity(findings)
    return ModuleResult(module="manifest", severity=highest, findings=findings, errors=errors)


def _check_application_flags(application, findings: list):
    """Inspects <application> tag attributes for three dangerous flags."""

    debuggable = application.get(f"{NS}debuggable", "false").lower()
    if debuggable == "true":
        findings.append(Finding(
            title="Application is Debuggable",
            detail=(
                "android:debuggable='true' allows anyone with ADB access to attach a debugger, "
                "inspect heap memory, extract credentials, and bypass runtime security controls. "
                "This flag must be absent (or explicitly false) in production builds."
            ),
            severity="CRITICAL",
            location="AndroidManifest.xml <application>",
            evidence='android:debuggable="true"',
        ))

    allow_backup = application.get(f"{NS}allowBackup", "true").lower()
    if allow_backup == "true":
        findings.append(Finding(
            title="Application Backup Enabled",
            detail=(
                "android:allowBackup='true' permits 'adb backup' to extract the app's private "
                "data directory (databases, SharedPreferences, tokens) without root access. "
                "An attacker with brief physical access can steal the entire app data store."
            ),
            severity="HIGH",
            location="AndroidManifest.xml <application>",
            evidence='android:allowBackup="true"',
        ))

    cleartext = application.get(f"{NS}usesCleartextTraffic", "false").lower()
    if cleartext == "true":
        findings.append(Finding(
            title="Cleartext Network Traffic Permitted",
            detail=(
                "android:usesCleartextTraffic='true' explicitly opts the entire application "
                "into unencrypted HTTP connections. All data on those connections is visible "
                "to anyone on the same network and can be intercepted or modified."
            ),
            severity="HIGH",
            location="AndroidManifest.xml <application>",
            evidence='android:usesCleartextTraffic="true"',
        ))


def _check_exported_components(application, findings: list):
    """
    Finds all activities, services, receivers, and providers that are exported
    (or effectively exported via intent-filter) but have no android:permission guard.
    """
    for tag in COMPONENT_TAGS:
        for component in application.iter(tag):
            component_name = component.get(f"{NS}name", "<unnamed>")
            exported_attr  = component.get(f"{NS}exported")
            has_filter     = component.find("intent-filter") is not None
            permission     = component.get(f"{NS}permission")

            # A component is considered exported if:
            # - android:exported="true" is set explicitly, OR
            # - it has an intent-filter AND android:exported is not explicitly "false"
            is_exported = exported_attr == "true" or (has_filter and exported_attr != "false")

            if is_exported and not permission:
                # Content providers are CRITICAL because they directly expose app data
                severity   = "CRITICAL" if tag == "provider" else "HIGH"
                short_name = component_name.split(".")[-1]
                findings.append(Finding(
                    title=f"Unprotected Exported {tag.capitalize()}: {short_name}",
                    detail=(
                        f"The {tag} '{component_name}' is exported and reachable by any installed "
                        f"app on the device with no android:permission restriction. "
                        f"An attacker can invoke it directly to trigger actions or access data."
                    ),
                    severity=severity,
                    location=f"AndroidManifest.xml <{tag}>",
                    evidence=f'android:name="{component_name}" — exported, no permission guard',
                ))


def _highest_severity(findings: list) -> str:
    """Returns the most critical severity level present in the findings list."""
    for level in _SEVERITY_ORDER:
        if any(f.severity == level for f in findings):
            return level
    return "INFO"
