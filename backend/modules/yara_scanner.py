"""
yara_scanner.py — YARA rule-based scanning layer for AppCheck.

Compiles all .yar rule files on import and scans the extracted APK workspace.
Adds a 'yara' findings module with high-confidence, deduplicated results.
"""

import yara
from pathlib import Path

import config
from models import Finding, ModuleResult

RULES_DIR = config.BASE_DIR / "rules"

# Rules that are never deduplicated — every match is a distinct credential
NO_DEDUP_RULES = {"AWS_Access_Key", "Private_Key_Block", "Stripe_Live_Secret_Key"}

# Severity ordering for calculating overall module severity
_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def load_rules() -> dict:
    """Compile each .yar file in RULES_DIR separately. Skip files that fail."""
    compiled = {}
    if not RULES_DIR.exists():
        return compiled
    for rule_file in sorted(RULES_DIR.glob("*.yar")):
        try:
            compiled[rule_file.stem] = yara.compile(filepath=str(rule_file))
        except Exception as e:
            print(f"[yara_scanner] WARNING: failed to compile {rule_file.name}: {e}")
    return compiled


# Compile once at import time
_COMPILED_RULES: dict = load_rules()


def _rule_title(rule_name: str) -> str:
    """Convert Snake_Case_Rule_Name to Title Case With Spaces."""
    return rule_name.replace("_", " ").title()


def _location_str(file_path: Path) -> str:
    """Return last 3 path components joined by /."""
    parts = file_path.parts
    return "/".join(parts[-3:]) if len(parts) >= 3 else str(file_path)


def scan_file_with_rules(file_path: Path, rule_keys: list[str]) -> list[Finding]:
    """
    Scan a single file against the specified rule sets.
    Returns a list of Finding objects (may be empty).
    """
    findings = []
    try:
        content = file_path.read_bytes()
    except Exception:
        return findings

    for key in rule_keys:
        rules = _COMPILED_RULES.get(key)
        if rules is None:
            continue
        try:
            matches = rules.match(data=content)
        except Exception:
            continue

        for match in matches:
            meta       = match.meta or {}
            severity   = meta.get("severity", "MEDIUM").upper()
            confidence = meta.get("confidence", "MEDIUM").upper()
            category   = meta.get("category", key)
            description = meta.get("description", match.rule)

            findings.append(Finding(
                title    = _rule_title(match.rule),
                detail   = description,
                severity = severity,
                location = _location_str(file_path),
                evidence = (
                    f"YARA rule '{match.rule}' matched in "
                    f"{file_path.name} — confidence: {confidence}"
                ),
            ))

    return findings


def _overall_severity(findings: list[Finding]) -> str:
    counts = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    for sev in _SEV_ORDER:
        if counts[sev] > 0:
            return sev
    return "INFO"


def analyze_yara(workspace_paths: dict) -> ModuleResult:
    """
    Scan the APK workspace with all YARA rules.
    Returns a ModuleResult with deduplicated, confidence-filtered findings.
    """
    errors: list[str] = []

    if not _COMPILED_RULES:
        errors.append("No YARA rules loaded — check backend/rules/ directory")
        return ModuleResult(module="yara_scanner", severity="INFO",
                            findings=[], errors=errors)

    raw_dir     = Path(workspace_paths.get("raw_dir",     ""))
    apktool_dir = Path(workspace_paths.get("apktool_dir", ""))
    jadx_dir    = Path(workspace_paths.get("jadx_dir",    ""))

    all_findings: list[Finding] = []

    # 1. AndroidManifest.xml — manifest rules only
    manifest_path = apktool_dir / "AndroidManifest.xml"
    if manifest_path.exists():
        all_findings += scan_file_with_rules(manifest_path, ["manifest"])

    # 2. Java source files — secrets, network, storage, malware rules
    java_rules = ["secrets", "network", "storage", "malware"]
    if jadx_dir.exists():
        java_files = sorted(jadx_dir.rglob("*.java"))[:500]
        for jf in java_files:
            all_findings += scan_file_with_rules(jf, java_rules)

    # 3. strings.xml — secrets rules only
    strings_xml = apktool_dir / "res" / "values" / "strings.xml"
    if strings_xml.exists():
        all_findings += scan_file_with_rules(strings_xml, ["secrets"])

    # 4. network_security_config.xml — network rules only
    nsc_xml = apktool_dir / "res" / "xml" / "network_security_config.xml"
    if nsc_xml.exists():
        all_findings += scan_file_with_rules(nsc_xml, ["network"])

    # 5. JSON files in raw_dir — secrets rules only
    if raw_dir.exists():
        for jf in raw_dir.rglob("*.json"):
            all_findings += scan_file_with_rules(jf, ["secrets"])

    # ── Confidence filtering ──────────────────────────────────────────────────
    # LOW confidence findings kept only for malware_indicators category
    def _keep(f: Finding) -> bool:
        ev = f.evidence.lower()
        # Derive confidence from evidence string
        if "confidence: low" in ev:
            return "malware" in ev
        return True

    all_findings = [f for f in all_findings if _keep(f)]

    # ── Deduplication ─────────────────────────────────────────────────────────
    seen: set[tuple[str, str]] = set()
    deduplicated: list[Finding] = []

    for f in all_findings:
        # Extract rule name from evidence: "YARA rule 'Rule_Name' matched in ..."
        rule_name = f.evidence.split("'")[1] if "'" in f.evidence else f.title
        # Derive a file-type key from evidence (use the filename stem)
        file_stem = f.evidence.split(" matched in ")[-1].split(" —")[0].rsplit(".", 1)[0]

        if rule_name in NO_DEDUP_RULES:
            deduplicated.append(f)
            continue

        key = (rule_name, file_stem)
        if key not in seen:
            seen.add(key)
            deduplicated.append(f)

    overall = _overall_severity(deduplicated)

    return ModuleResult(
        module   = "yara_scanner",
        severity = overall,
        findings = deduplicated,
        errors   = errors,
    )
