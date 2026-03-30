"""
Pattern-based detection engine.

Loads YAML rule files from the rules/ directory and applies regex patterns
to source code files. Returns a list of raw Finding objects.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from vulnscanner.utils.helpers import detect_language, generate_finding_id
from vulnscanner.utils.logging import get_logger
from vulnscanner.utils.models import (
    CodeSnippet,
    DetectionMethod,
    Finding,
    OWASPCategory,
    RemediationGuide,
    Severity,
)

logger = get_logger(__name__)

# Map short OWASP codes used in YAML to full enum values
_OWASP_MAP: dict[str, OWASPCategory] = {
    "A01": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    "A02": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "A03": OWASPCategory.A03_INJECTION,
    "A04": OWASPCategory.A04_INSECURE_DESIGN,
    "A05": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
    "A06": OWASPCategory.A06_VULNERABLE_COMPONENTS,
    "A07": OWASPCategory.A07_AUTH_FAILURES,
    "A08": OWASPCategory.A08_INTEGRITY_FAILURES,
    "A09": OWASPCategory.A09_LOGGING_FAILURES,
    "A10": OWASPCategory.A10_SSRF,
}

_SEVERITY_MAP: dict[str, Severity] = {s.value: s for s in Severity}


class PatternEngine:
    """Loads rules from YAML files and scans source files via regex."""

    def __init__(self, rules_dir: Path | None = None) -> None:
        if rules_dir is None:
            # Try relative to this file first (installed package), then CWD
            candidate = Path(__file__).parents[3] / "rules"
            if not candidate.exists():
                candidate = Path(__file__).parents[2] / "rules"
            if not candidate.exists():
                candidate = Path.cwd() / "rules"
            rules_dir = candidate
        self.rules_dir = rules_dir
        self._rules: list[dict[str, Any]] = []
        self._load_rules()

    # ------------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------------

    def _load_rules(self) -> None:
        """Parse all YAML rule files in the rules directory."""
        if not self.rules_dir.exists():
            logger.warning(f"Rules directory not found: {self.rules_dir}")
            return

        for yaml_file in sorted(self.rules_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
                rules = data.get("rules", [])
                self._rules.extend(rules)
                logger.debug(f"Loaded {len(rules)} rules from {yaml_file.name}")
            except Exception as exc:
                logger.error(f"Failed to load {yaml_file}: {exc}")

        logger.info(f"Pattern engine loaded {len(self._rules)} rules total")

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def scan_file(self, path: Path, counter_start: int = 1) -> list[Finding]:
        """Scan a single file and return all pattern matches as Findings."""
        language = detect_language(path)
        if language == "unknown":
            return []

        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning(f"Cannot read {path}: {exc}")
            return []

        lines = source.splitlines()
        findings: list[Finding] = []
        counter = counter_start

        for rule in self._rules:
            rule_langs = rule.get("languages", [])
            if language not in rule_langs:
                continue

            patterns_by_lang: dict[str, list[str]] = rule.get("patterns", {})
            lang_patterns = patterns_by_lang.get(language, [])

            for pattern_str in lang_patterns:
                try:
                    regex = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                except re.error as exc:
                    logger.debug(f"Bad regex in rule {rule['id']}: {exc}")
                    continue

                for match in regex.finditer(source):
                    line_no = source[: match.start()].count("\n") + 1
                    snippet_lines = lines[max(0, line_no - 2) : line_no + 3]
                    snippet_text = "\n".join(snippet_lines)

                    finding = self._build_finding(
                        rule=rule,
                        path=path,
                        line_no=line_no,
                        snippet=snippet_text,
                        language=language,
                        finding_id=generate_finding_id(counter),
                    )
                    findings.append(finding)
                    counter += 1
                    break  # one finding per rule per file (avoid noise)

        return findings

    def scan_files(self, paths: list[Path]) -> list[Finding]:
        """Scan multiple files, maintaining a global counter."""
        all_findings: list[Finding] = []
        for path in paths:
            file_findings = self.scan_file(path, counter_start=len(all_findings) + 1)
            all_findings.extend(file_findings)
        return all_findings

    # ------------------------------------------------------------------
    # Finding construction
    # ------------------------------------------------------------------

    def _build_finding(
        self,
        rule: dict[str, Any],
        path: Path,
        line_no: int,
        snippet: str,
        language: str,
        finding_id: str,
    ) -> Finding:
        owasp_short = rule.get("owasp", "A03")
        owasp_cat = _OWASP_MAP.get(owasp_short, OWASPCategory.A03_INJECTION)
        severity_str = rule.get("severity", "MEDIUM")
        severity = _SEVERITY_MAP.get(severity_str, Severity.MEDIUM)
        cvss = float(rule.get("cvss", 5.0))

        rem_data = rule.get("remediation", {})
        remediation = RemediationGuide(
            summary=rem_data.get("summary", "Review and fix the identified issue."),
            steps=rem_data.get("steps", []),
            code_fix=rem_data.get("code_fix"),
            references=rem_data.get("references", []),
        )

        return Finding(
            id=finding_id,
            title=rule.get("title", "Unknown vulnerability"),
            owasp_category=owasp_cat,
            severity=severity,
            cvss_score=cvss,
            cwe_id=rule.get("cwe"),
            description=rule.get("description", ""),
            detection_method=DetectionMethod.PATTERN,
            snippet=CodeSnippet(
                file=str(path),
                line_start=max(1, line_no - 1),
                line_end=line_no + 3,
                content=snippet,
                language=language,
            ),
            remediation=remediation,
            tags=[owasp_short, language, rule.get("id", "")],
        )
