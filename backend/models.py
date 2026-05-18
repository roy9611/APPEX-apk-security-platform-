"""
models.py — Pydantic v2 data models for the APK Security Intelligence Platform.
"""

from enum import Enum
from pydantic import BaseModel, Field


# ── Enums ─────────────────────────────────────────────────────────────────────

class ScanStatus(str, Enum):
    """Lifecycle states of a background scan job."""
    QUEUED   = "queued"
    RUNNING  = "running"
    COMPLETE = "complete"
    FAILED   = "failed"


class SeverityLevel(str, Enum):
    """Ordered severity levels used across all analysis modules."""
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


# ── Core models ───────────────────────────────────────────────────────────────

class Finding(BaseModel):
    """
    A single security finding from an analysis module.
    Supports both positional and keyword construction for convenience.
    """
    title:    str
    detail:   str
    severity: str
    location: str
    evidence: str

    def __init__(
        self,
        title:    str = "",
        detail:   str = "",
        severity: str = "INFO",
        location: str = "",
        evidence: str = "",
        **kwargs,
    ):
        super().__init__(
            title=title,
            detail=detail,
            severity=severity,
            location=location,
            evidence=evidence,
            **kwargs,
        )


class ModuleResult(BaseModel):
    """
    The standardised return value for every analysis module.
    On module failure, errors are stored here and findings is empty.
    """
    module:   str
    severity: str                          = "INFO"
    findings: list[Finding]                = Field(default_factory=list)
    errors:   list[str]                    = Field(default_factory=list)

    def highest_severity(self) -> str:
        """Returns the most severe level found across all findings, or INFO if none."""
        for level in _SEVERITY_ORDER:
            if any(f.severity == level for f in self.findings):
                return level
        return "INFO"


class ScanResult(BaseModel):
    """
    The complete output of a full APK scan.
    Stored in memory during the scan and serialised to JSON on completion.
    """
    scan_id:       str
    app_name:      str       = "Unknown"
    package_name:  str       = "unknown"
    risk_score:    int       = 0
    risk_level:    str       = "INFO"
    scan_duration: float     = 0.0
    status:        str       = ScanStatus.QUEUED
    findings:      dict      = Field(default_factory=dict)
    ai_summary:    str       = ""
    remediation:   list[str] = Field(default_factory=list)
    error_message: str       = ""


# ── API request / response models ─────────────────────────────────────────────

class ChatRequest(BaseModel):
    """Request body for POST /api/chat."""
    scan_id: str
    message: str


class ChatResponse(BaseModel):
    """Response body for POST /api/chat."""
    response: str
    scan_id:  str
