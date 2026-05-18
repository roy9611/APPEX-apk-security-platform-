"""
ssl_checker.py — Detects SSL/TLS bypass patterns and insecure network security configuration.

Part 1: Parses res/xml/network_security_config.xml for misconfigurations.
Part 2: Scans Java source files for TrustManager and HostnameVerifier bypass patterns.
"""

import xml.etree.ElementTree as ET
from pathlib import Path

from models import Finding, ModuleResult

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def analyze_ssl(workspace_paths: dict) -> ModuleResult:
    """
    Runs both the config file check and the Java source scan.
    Returns a single ModuleResult combining all findings.
    """
    apktool_dir = Path(workspace_paths["apktool_dir"])
    jadx_dir    = Path(workspace_paths["jadx_dir"])
    findings    = []
    errors      = []

    _check_network_security_config(apktool_dir, findings, errors)
    _scan_java_for_tls_bypass(jadx_dir, findings, errors)

    highest = _highest_severity(findings)
    return ModuleResult(module="ssl", severity=highest, findings=findings, errors=errors)


# ── Part 1: network_security_config.xml ───────────────────────────────────────

def _check_network_security_config(apktool_dir: Path, findings: list, errors: list):
    """
    Parses res/xml/network_security_config.xml if it exists.
    Checks for cleartext, user certificates, and missing certificate pinning.
    """
    config_path = apktool_dir / "res" / "xml" / "network_security_config.xml"

    if not config_path.exists():
        findings.append(Finding(
            title="No Network Security Config Found",
            detail=(
                "No res/xml/network_security_config.xml file was found. "
                "The app relies on Android default TLS settings: cleartext is blocked on "
                "API 28+ and no certificate pinning is enforced."
            ),
            severity="INFO",
            location="res/xml/network_security_config.xml",
            evidence="File not present",
        ))
        return

    try:
        tree     = ET.parse(config_path)
        root     = tree.getroot()
        xml_text = config_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        errors.append(f"Failed to parse network_security_config.xml: {exc}")
        return

    # Check for cleartext traffic permission
    for element in root.iter():
        cleartext = element.get("cleartextTrafficPermitted", "")
        if cleartext.lower() == "true":
            findings.append(Finding(
                title="Cleartext Traffic Permitted in Network Security Config",
                detail=(
                    "cleartextTrafficPermitted='true' explicitly allows unencrypted HTTP "
                    "connections for one or more domains. All data on those connections is "
                    "plaintext and can be read or modified by anyone on the network."
                ),
                severity="HIGH",
                location="res/xml/network_security_config.xml",
                evidence='cleartextTrafficPermitted="true"',
            ))
            break

    # Check for user-installed certificate trust (enables Burp/mitmproxy interception)
    if 'src="user"' in xml_text or "src='user'" in xml_text:
        findings.append(Finding(
            title="User-Installed Certificates Trusted (MITM Interception Possible)",
            detail=(
                "The network security config trusts user-installed CA certificates. "
                "An attacker can install a Burp Suite or mitmproxy root CA to intercept "
                "and decrypt all HTTPS traffic from this app."
            ),
            severity="HIGH",
            location="res/xml/network_security_config.xml",
            evidence='<certificates src="user"/>',
        ))

    # Check for absent certificate pinning
    if "pin-set" not in xml_text:
        findings.append(Finding(
            title="No Certificate Pinning Configured",
            detail=(
                "The network security config exists but defines no <pin-set>. Without "
                "certificate pinning, any CA trusted by the device can issue a valid "
                "certificate for the app's server domains, enabling MITM attacks."
            ),
            severity="MEDIUM",
            location="res/xml/network_security_config.xml",
            evidence="No <pin-set> element found in network_security_config.xml",
        ))


# ── Part 2: Java source TLS bypass patterns ───────────────────────────────────

def _scan_java_for_tls_bypass(jadx_dir: Path, findings: list, errors: list):
    """Iterates all .java files and delegates to three per-file pattern checks."""
    if not jadx_dir.exists():
        return

    for java_file in jadx_dir.rglob("*.java"):
        try:
            content = java_file.read_text(encoding="utf-8", errors="ignore")
            lines   = content.splitlines()
        except Exception as exc:
            errors.append(f"Failed to read {java_file.name}: {exc}")
            continue

        _check_trustmanager_bypass(java_file, lines, findings)
        _check_hostname_verifier_bypass(java_file, lines, findings)
        _check_cleartext_urls(java_file, lines, findings)


def _check_trustmanager_bypass(java_file: Path, lines: list, findings: list):
    """
    Detects checkServerTrusted() implementations whose body appears empty (just braces).
    An empty body means all certificates are accepted without any validation.
    """
    for i, line in enumerate(lines):
        if "checkServerTrusted" not in line:
            continue

        # Inspect surrounding ±5 lines; count non-trivial lines excluding the signature
        surrounding       = lines[max(0, i - 1): min(len(lines), i + 7)]
        non_trivial_lines = [
            l.strip() for l in surrounding
            if l.strip() and l.strip() not in ("{", "}", "@Override")
            and "checkServerTrusted" not in l
        ]

        if len(non_trivial_lines) <= 1:
            findings.append(Finding(
                title="Custom TrustManager Accepts All Certificates",
                detail=(
                    "checkServerTrusted() appears to have an empty body, meaning it accepts "
                    "any TLS certificate without validation. This completely disables certificate "
                    "checking and makes HTTPS traffic trivially interceptable."
                ),
                severity="CRITICAL",
                location=f"{java_file.name}:{i + 1}",
                evidence=f"checkServerTrusted() empty body near line {i + 1}",
            ))
            return  # One finding per file is enough


def _check_hostname_verifier_bypass(java_file: Path, lines: list, findings: list):
    """
    Detects HostnameVerifier implementations that unconditionally return true.
    Combined with any trusted certificate, this enables MITM against any hostname.
    """
    for i, line in enumerate(lines):
        if "HostnameVerifier" not in line and "verify(" not in line:
            continue

        window = lines[max(0, i): min(len(lines), i + 7)]
        if any("return true" in l for l in window):
            findings.append(Finding(
                title="HostnameVerifier Always Returns True",
                detail=(
                    "A HostnameVerifier that unconditionally returns true disables hostname "
                    "validation. An attacker with any valid TLS certificate can perform a "
                    "man-in-the-middle attack against any domain this app connects to."
                ),
                severity="CRITICAL",
                location=f"{java_file.name}:{i + 1}",
                evidence=f"HostnameVerifier returns true near line {i + 1}",
            ))
            return


def _check_cleartext_urls(java_file: Path, lines: list, findings: list):
    """
    Flags hardcoded http:// URLs in Java source.
    Skips Android SDK namespace URIs and localhost references.
    Reports at most one finding per file to avoid noise.
    """
    for i, line in enumerate(lines):
        if "http://" not in line:
            continue
        if "schemas.android.com" in line or "localhost" in line or "127.0.0.1" in line:
            continue

        url_start   = line.find("http://")
        url_snippet = line[url_start:url_start + 80].split('"')[0].split("'")[0].split(" ")[0]

        findings.append(Finding(
            title="Hardcoded Cleartext HTTP URL",
            detail=(
                "A hardcoded http:// URL was found in source code. Any request to this "
                "endpoint is unencrypted and visible to network observers."
            ),
            severity="LOW",
            location=f"{java_file.name}:{i + 1}",
            evidence=url_snippet[:60],
        ))
        return  # One finding per file


def _highest_severity(findings: list) -> str:
    for level in _SEVERITY_ORDER:
        if any(f.severity == level for f in findings):
            return level
    return "INFO"
