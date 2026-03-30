"""
SARIF 2.1.0 export — compatible with GitHub Advanced Security.
https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

from typing import Any

from vulnscanner.utils.models import ScanResult, Finding, Severity

_LEVEL_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def to_sarif(result: ScanResult) -> dict[str, Any]:
    """Convert a ScanResult to a SARIF 2.1.0 document."""
    rules = _build_rules(result.findings)
    results = [_finding_to_result(f) for f in result.findings]

    # Add SCA findings as SARIF results
    for sca in result.sca_findings:
        results.append(_sca_to_result(sca))

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "VulnScanner AI",
                    "version": result.metadata.scanner_version,
                    "informationUri": "https://github.com/your-org/vulnscanner-ai",
                    "rules": rules,
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": result.metadata.started_at,
                "endTimeUtc": result.metadata.finished_at,
            }],
            "properties": {
                "scanId": result.metadata.scan_id,
                "target": result.metadata.target.value,
                "filesScanned": result.metadata.files_scanned,
                "overallRiskScore": result.summary.overall_risk_score,
            },
        }],
    }


def _build_rules(findings: list[Finding]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    rules = []
    for f in findings:
        rule_id = f.tags[2] if len(f.tags) >= 3 else f.id
        if rule_id in seen:
            continue
        seen.add(rule_id)
        rules.append({
            "id": rule_id,
            "name": f.title.replace(" ", ""),
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.description[:1000]},
            "helpUri": f.remediation.references[0] if f.remediation.references else "",
            "properties": {
                "tags": f.tags,
                "precision": "medium",
                "problem.severity": _LEVEL_MAP.get(f.severity, "warning"),
                "security-severity": str(f.cvss_score),
            },
        })
    return rules


def _finding_to_result(f: Finding) -> dict[str, Any]:
    rule_id = f.tags[2] if len(f.tags) >= 3 else f.id
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": _LEVEL_MAP.get(f.severity, "warning"),
        "message": {
            "text": f"{f.title}\n\n{f.description}\n\nRemediation: {f.remediation.summary}"
        },
        "properties": {
            "cvssScore": f.cvss_score,
            "owaspCategory": f.owasp_category.value,
            "cweId": f.cwe_id or "",
            "detectionMethod": f.detection_method.value,
            "mlConfidence": f.ml_prediction.confidence if f.ml_prediction else None,
        },
    }

    if f.snippet and f.snippet.file and not f.snippet.file.startswith("http"):
        result["locations"] = [{
            "physicalLocation": {
                "artifactLocation": {"uri": f.snippet.file, "uriBaseId": "%SRCROOT%"},
                "region": {
                    "startLine": max(1, f.snippet.line_start),
                    "endLine": max(1, f.snippet.line_end),
                    "snippet": {"text": f.snippet.content[:500]},
                },
            }
        }]

    return result


def _sca_to_result(sca: dict) -> dict[str, Any]:
    return {
        "ruleId": "SCA-VULN-COMPONENT",
        "level": "error" if sca.get("severity") in ("CRITICAL", "HIGH") else "warning",
        "message": {
            "text": (
                f"Vulnerable dependency: {sca['package']} {sca['version']} — "
                f"{sca['cve']}: {sca['description']}. "
                f"Fix: upgrade to {sca['fixed_version']}."
            )
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": sca.get("file", ""), "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": 1},
            }
        }],
        "properties": {"owaspCategory": "A06:2025 – Vulnerable and Outdated Components"},
    }
