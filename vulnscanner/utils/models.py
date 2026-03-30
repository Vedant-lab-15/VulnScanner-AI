"""
Shared Pydantic data models used across the entire scanner pipeline.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class OWASPCategory(str, Enum):
    A01_BROKEN_ACCESS_CONTROL = "A01:2025 – Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2025 – Cryptographic Failures"
    A03_INJECTION = "A03:2025 – Injection"
    A04_INSECURE_DESIGN = "A04:2025 – Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2025 – Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2025 – Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2025 – Identification and Authentication Failures"
    A08_INTEGRITY_FAILURES = "A08:2025 – Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2025 – Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2025 – Server-Side Request Forgery (SSRF)"


class DetectionMethod(str, Enum):
    PATTERN = "pattern"
    ML = "ml"
    SIMULATION = "simulation"
    SCA = "sca"
    COMBINED = "combined"


# ---------------------------------------------------------------------------
# Core finding model
# ---------------------------------------------------------------------------

class CodeSnippet(BaseModel):
    file: str
    line_start: int
    line_end: int
    content: str
    language: str = "unknown"


class RemediationGuide(BaseModel):
    summary: str
    steps: list[str]
    code_fix: str | None = None
    references: list[str] = Field(default_factory=list)


class MLPrediction(BaseModel):
    confidence: float          # 0.0 – 1.0
    model_version: str
    top_features: list[tuple[str, float]] = Field(default_factory=list)
    shap_values: dict[str, float] = Field(default_factory=dict)


class SimulationResult(BaseModel):
    payload_used: str
    response_snippet: str | None = None
    risk_indicator: str          # e.g. "error message leaked", "reflected input"
    confirmed: bool = False


class Finding(BaseModel):
    """A single vulnerability finding."""

    id: str                                  # e.g. "VULN-0001"
    title: str
    owasp_category: OWASPCategory
    severity: Severity
    cvss_score: float = Field(ge=0.0, le=10.0)
    cwe_id: str | None = None                # e.g. "CWE-89"
    description: str
    detection_method: DetectionMethod
    snippet: CodeSnippet | None = None
    ml_prediction: MLPrediction | None = None
    simulation: SimulationResult | None = None
    remediation: RemediationGuide
    tags: list[str] = Field(default_factory=list)
    false_positive_likelihood: float = Field(default=0.1, ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# Scan result
# ---------------------------------------------------------------------------

class ScanTarget(BaseModel):
    kind: str                   # "directory" | "url" | "github"
    value: str
    resolved_path: str | None = None


class ScanMetadata(BaseModel):
    scanner_version: str
    scan_id: str
    started_at: str
    finished_at: str
    target: ScanTarget
    files_scanned: int = 0
    lines_scanned: int = 0
    languages_detected: list[str] = Field(default_factory=list)


class RiskSummary(BaseModel):
    total_findings: int
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    overall_risk_score: float = 0.0   # 0–100
    owasp_coverage: dict[str, int] = Field(default_factory=dict)


class ScanResult(BaseModel):
    metadata: ScanMetadata
    summary: RiskSummary
    findings: list[Finding] = Field(default_factory=list)
    sca_findings: list[dict[str, Any]] = Field(default_factory=list)
    raw_stats: dict[str, Any] = Field(default_factory=dict)
