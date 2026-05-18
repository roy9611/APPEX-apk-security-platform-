"""
firebase_checker.py — Tests whether the app's Firebase Realtime Database is publicly accessible.

Searches for Firebase configuration in google-services.json and strings.xml,
then makes an unauthenticated HTTP GET to the database /.json endpoint.
An HTTP 200 with real data means the database is open to the internet.
"""

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import requests

from models import Finding, ModuleResult

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def check_firebase(workspace_paths: dict) -> ModuleResult:
    """
    Locates Firebase configuration and tests database accessibility.
    Returns a ModuleResult. Never raises — all network and I/O errors are stored in errors[].
    """
    raw_dir     = Path(workspace_paths["raw_dir"])
    apktool_dir = Path(workspace_paths["apktool_dir"])
    findings    = []
    errors      = []

    firebase_url  = None
    config_source = None

    # ── Step 1: Check google-services.json ────────────────────────────────────
    for json_file in raw_dir.rglob("google-services.json"):
        try:
            data         = json.loads(json_file.read_text(encoding="utf-8"))
            project_info = data.get("project_info", {})
            project_id   = project_info.get("project_id")

            # Firebase JSON uses either "firebase_url" or "database_url" depending on version
            firebase_url = (
                project_info.get("firebase_url")
                or project_info.get("database_url")
            )

            # If no explicit URL but we have a project ID, construct the default URL
            if not firebase_url and project_id:
                firebase_url = f"https://{project_id}-default-rtdb.firebaseio.com"

            if firebase_url:
                config_source = json_file.name
                break
        except Exception as exc:
            errors.append(f"Failed to parse {json_file.name}: {exc}")

    # ── Step 2: Fallback — check strings.xml for firebase_database_url ────────
    if not firebase_url:
        strings_xml = apktool_dir / "res" / "values" / "strings.xml"
        if strings_xml.exists():
            try:
                tree = ET.parse(strings_xml)
                for string_tag in tree.getroot().findall("string"):
                    name  = string_tag.get("name", "").lower()
                    value = (string_tag.text or "").strip()
                    if "firebase" in name and value.startswith("https://"):
                        firebase_url  = value
                        config_source = "res/values/strings.xml"
                        break
            except Exception as exc:
                errors.append(f"Failed to parse strings.xml: {exc}")

    # ── No Firebase found at all ──────────────────────────────────────────────
    if not firebase_url:
        findings.append(Finding(
            title="No Firebase Configuration Detected",
            detail=(
                "No google-services.json or firebase_database_url string resource was found. "
                "The app does not appear to use Firebase Realtime Database."
            ),
            severity="INFO",
            location="N/A",
            evidence="No Firebase config found in raw/ or res/values/strings.xml",
        ))
        return ModuleResult(module="firebase", severity="INFO", findings=findings, errors=errors)

    # ── Step 3: Test database accessibility ───────────────────────────────────
    test_url = firebase_url.rstrip("/") + "/.json"
    try:
        response = requests.get(test_url, timeout=5)
        body     = response.text.strip()

        if response.status_code == 200 and "Permission denied" not in body:
            # Real data returned — database is open
            findings.append(Finding(
                title="Open Firebase Realtime Database",
                detail=(
                    f"The Firebase database at {firebase_url} responded to an unauthenticated "
                    f"GET request with real data. Any user on the internet can read — and "
                    f"potentially write — this database without any credentials."
                ),
                severity="CRITICAL",
                location=config_source,
                evidence=f"GET {test_url} → HTTP {response.status_code}: {body[:60]}",
            ))
        else:
            findings.append(Finding(
                title="Firebase Database Properly Secured",
                detail=(
                    f"The Firebase database at {firebase_url} returned 'Permission denied', "
                    f"indicating that security rules are in place and unauthenticated access is blocked."
                ),
                severity="INFO",
                location=config_source,
                evidence=f"GET {test_url} → HTTP {response.status_code}",
            ))

    except requests.exceptions.Timeout:
        errors.append(f"Connection timed out reaching {test_url}")
        findings.append(Finding(
            title="Firebase Database URL Found (Timeout)",
            detail=(
                f"Firebase configuration references {firebase_url} but the connection timed out. "
                f"The database may be disabled or the URL may be a test placeholder."
            ),
            severity="MEDIUM",
            location=config_source,
            evidence=f"URL: {firebase_url} (timeout after 5s)",
        ))
    except requests.exceptions.ConnectionError as exc:
        errors.append(f"Could not reach {test_url}: {exc}")
        findings.append(Finding(
            title="Firebase Database URL Found (Unreachable)",
            detail=(
                f"Firebase configuration references {firebase_url} but the URL was not "
                f"reachable during this scan. The database may have been deleted."
            ),
            severity="MEDIUM",
            location=config_source,
            evidence=f"URL: {firebase_url} (connection error)",
        ))
    except Exception as exc:
        errors.append(f"Unexpected error checking Firebase: {exc}")

    highest = _highest_severity(findings)
    return ModuleResult(module="firebase", severity=highest, findings=findings, errors=errors)


def _highest_severity(findings: list) -> str:
    for level in _SEVERITY_ORDER:
        if any(f.severity == level for f in findings):
            return level
    return "INFO"
