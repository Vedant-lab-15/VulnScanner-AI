"""
Shared pytest fixtures for VulnScanner AI test suite.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure the project root is on the path when running tests directly
sys.path.insert(0, str(Path(__file__).parents[1]))

from vulnscanner.utils.models import (
    CodeSnippet, DetectionMethod, Finding, OWASPCategory,
    RemediationGuide, Severity, ScanResult, ScanMetadata,
    ScanTarget, RiskSummary,
)


@pytest.fixture
def sample_finding() -> Finding:
    return Finding(
        id="VULN-0001",
        title="SQL Injection via string concatenation",
        owasp_category=OWASPCategory.A03_INJECTION,
        severity=Severity.CRITICAL,
        cvss_score=9.1,
        cwe_id="CWE-89",
        description="User input concatenated into SQL query.",
        detection_method=DetectionMethod.PATTERN,
        snippet=CodeSnippet(
            file="app.py",
            line_start=42,
            line_end=46,
            content='cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
            language="python",
        ),
        remediation=RemediationGuide(
            summary="Use parameterised queries.",
            steps=["Replace string concat with %s placeholder."],
            code_fix='cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
        ),
    )


@pytest.fixture
def sample_scan_result(sample_finding) -> ScanResult:
    return ScanResult(
        metadata=ScanMetadata(
            scanner_version="1.0.0",
            scan_id="TEST0001",
            started_at="2025-01-01T00:00:00",
            finished_at="2025-01-01T00:00:05",
            target=ScanTarget(kind="directory", value="/tmp/test"),
            files_scanned=4,
            lines_scanned=200,
            languages_detected=["python", "javascript"],
        ),
        summary=RiskSummary(
            total_findings=1,
            critical=1,
            overall_risk_score=10.0,
            owasp_coverage={"A03:2025 – Injection": 1},
        ),
        findings=[sample_finding],
    )


@pytest.fixture
def rules_dir() -> Path:
    return Path(__file__).parents[1] / "rules"


@pytest.fixture
def samples_dir() -> Path:
    return Path(__file__).parents[1] / "samples"


@pytest.fixture
def pattern_engine(rules_dir):
    from vulnscanner.patterns.engine import PatternEngine
    return PatternEngine(rules_dir=rules_dir)
