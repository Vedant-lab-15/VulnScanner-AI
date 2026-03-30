"""
Core scanner orchestrator.

Coordinates:
  1. Source file collection
  2. Pattern-based detection
  3. ML classification (enriches pattern findings + standalone)
  4. Safe simulation (code taint analysis)
  5. SCA dependency scanning
  6. Risk scoring and deduplication
"""

from __future__ import annotations

import datetime
import tempfile
from pathlib import Path
from typing import Any

from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

from vulnscanner.utils.helpers import collect_source_files, generate_scan_id, cvss_to_severity
from vulnscanner.utils.logging import get_logger
from vulnscanner.utils.models import (
    DetectionMethod, Finding, MLPrediction, OWASPCategory,
    RiskSummary, ScanMetadata, ScanResult, ScanTarget, Severity,
)
from vulnscanner.patterns.engine import PatternEngine
from vulnscanner.ml.classifier import VulnClassifier
from vulnscanner.simulation.simulator import SafeSimulator
from vulnscanner.scanner.sca import SCAScanner

logger = get_logger(__name__)


class Scanner:
    """Main scanner orchestrator for directory and GitHub targets."""

    def __init__(
        self,
        enable_ml: bool = True,
        enable_simulation: bool = True,
        enable_sca: bool = True,
        skip_tests: bool = True,
        ml_threshold: float = 0.4,
    ) -> None:
        self.enable_ml = enable_ml
        self.enable_simulation = enable_simulation
        self.enable_sca = enable_sca
        self.skip_tests = skip_tests
        self.ml_threshold = ml_threshold

        self._pattern_engine = PatternEngine()
        self._classifier = VulnClassifier() if enable_ml else None
        self._sca = SCAScanner() if enable_sca else None

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def scan_directory(self, path: Path) -> ScanResult:
        """Scan a local directory."""
        started = datetime.datetime.utcnow().isoformat()
        target = ScanTarget(kind="directory", value=str(path), resolved_path=str(path.resolve()))

        files = collect_source_files(path, skip_tests=self.skip_tests)
        logger.info(f"Found {len(files)} source files to scan")

        findings = self._run_pipeline(files, path)
        sca_findings = self._sca.scan_directory(path) if self._sca else []

        finished = datetime.datetime.utcnow().isoformat()
        return self._build_result(target, findings, sca_findings, files, started, finished)

    def scan_github(self, repo_url: str) -> ScanResult:
        """Clone a GitHub repo to a temp dir and scan it."""
        import git

        with tempfile.TemporaryDirectory(prefix="vulnscanner_") as tmpdir:
            tmp_path = Path(tmpdir)
            logger.info(f"Cloning {repo_url} ...")
            try:
                git.Repo.clone_from(repo_url, tmp_path, depth=1)
            except Exception as exc:
                raise RuntimeError(f"Failed to clone {repo_url}: {exc}") from exc

            started = datetime.datetime.utcnow().isoformat()
            target = ScanTarget(kind="github", value=repo_url, resolved_path=tmpdir)
            files = collect_source_files(tmp_path, skip_tests=self.skip_tests)
            findings = self._run_pipeline(files, tmp_path)
            sca_findings = self._sca.scan_directory(tmp_path) if self._sca else []
            finished = datetime.datetime.utcnow().isoformat()

            # Rewrite paths to be relative to repo root
            for f in findings:
                if f.snippet:
                    f.snippet.file = f.snippet.file.replace(tmpdir, repo_url)

            return self._build_result(target, findings, sca_findings, files, started, finished)

    # ------------------------------------------------------------------
    # Pipeline
    # ------------------------------------------------------------------

    def _run_pipeline(self, files: list[Path], root: Path) -> list[Finding]:
        all_findings: list[Finding] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
        ) as progress:

            # Step 1: Pattern scanning
            task = progress.add_task("Pattern scanning...", total=len(files))
            for f in files:
                file_findings = self._pattern_engine.scan_file(
                    f, counter_start=len(all_findings) + 1
                )
                all_findings.extend(file_findings)
                progress.advance(task)

            # Step 2: ML enrichment
            if self._classifier:
                task2 = progress.add_task("ML classification...", total=len(all_findings))
                for finding in all_findings:
                    if finding.snippet:
                        self._enrich_with_ml(finding)
                    progress.advance(task2)

            # Step 3: Simulation (code taint)
            if self.enable_simulation:
                task3 = progress.add_task("Taint simulation...", total=len(all_findings))
                with SafeSimulator() as sim:
                    for finding in all_findings:
                        if finding.snippet and finding.simulation is None:
                            vuln_type = self._owasp_to_vuln_type(finding.owasp_category)
                            result = sim.simulate_code(
                                finding.snippet.content,
                                vuln_type,
                                finding.snippet.language,
                            )
                            if result:
                                finding.simulation = result
                                # Boost confidence if simulation confirms
                                if result.confirmed and finding.ml_prediction:
                                    finding.ml_prediction.confidence = min(
                                        finding.ml_prediction.confidence + 0.1, 1.0
                                    )
                        progress.advance(task3)

        # Deduplicate: same file + same rule = keep highest confidence
        all_findings = self._deduplicate(all_findings)
        logger.info(f"Pipeline complete: {len(all_findings)} findings")
        return all_findings

    def _enrich_with_ml(self, finding: Finding) -> None:
        """Add ML prediction to an existing pattern finding."""
        assert self._classifier is not None
        code = finding.snippet.content  # type: ignore[union-attr]
        lang = finding.snippet.language  # type: ignore[union-attr]

        label, confidence = self._classifier.predict(code, lang)
        top_feats = self._classifier.top_features(code, lang)

        finding.ml_prediction = MLPrediction(
            confidence=confidence,
            model_version=self._classifier.model_version,
            top_features=top_feats,
        )

        # If ML says safe with high confidence, mark as likely false positive
        if label == 0 and confidence > 0.75:
            finding.false_positive_likelihood = 0.7

    # ------------------------------------------------------------------
    # Result assembly
    # ------------------------------------------------------------------

    def _build_result(
        self,
        target: ScanTarget,
        findings: list[Finding],
        sca_findings: list[dict[str, Any]],
        files: list[Path],
        started: str,
        finished: str,
    ) -> ScanResult:
        total_lines = sum(
            len(f.read_text(encoding="utf-8", errors="replace").splitlines())
            for f in files
        )
        languages = list({f.suffix.lstrip(".") for f in files if f.suffix})

        metadata = ScanMetadata(
            scanner_version="1.0.0",
            scan_id=generate_scan_id(),
            started_at=started,
            finished_at=finished,
            target=target,
            files_scanned=len(files),
            lines_scanned=total_lines,
            languages_detected=languages,
        )

        summary = self._compute_summary(findings, sca_findings)

        return ScanResult(
            metadata=metadata,
            summary=summary,
            findings=findings,
            sca_findings=sca_findings,
        )

    def _compute_summary(
        self, findings: list[Finding], sca_findings: list[dict[str, Any]]
    ) -> RiskSummary:
        counts = {s: 0 for s in Severity}
        owasp_counts: dict[str, int] = {}

        for f in findings:
            counts[f.severity] += 1
            cat = f.owasp_category.value
            owasp_counts[cat] = owasp_counts.get(cat, 0) + 1

        # Add SCA findings to counts
        sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                   "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
        for sf in sca_findings:
            sev = sev_map.get(sf.get("severity", "MEDIUM"), Severity.MEDIUM)
            counts[sev] += 1
            owasp_counts["A06:2025 – Vulnerable and Outdated Components"] = (
                owasp_counts.get("A06:2025 – Vulnerable and Outdated Components", 0) + 1
            )

        total = len(findings) + len(sca_findings)

        # CVSS-inspired risk score (0–100)
        risk_score = min(
            counts[Severity.CRITICAL] * 10
            + counts[Severity.HIGH] * 7
            + counts[Severity.MEDIUM] * 4
            + counts[Severity.LOW] * 1,
            100,
        )

        return RiskSummary(
            total_findings=total,
            critical=counts[Severity.CRITICAL],
            high=counts[Severity.HIGH],
            medium=counts[Severity.MEDIUM],
            low=counts[Severity.LOW],
            info=counts[Severity.INFO],
            overall_risk_score=float(risk_score),
            owasp_coverage=owasp_counts,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _owasp_to_vuln_type(cat: OWASPCategory) -> str:
        mapping = {
            OWASPCategory.A03_INJECTION: "sqli",
            OWASPCategory.A10_SSRF: "ssrf",
            OWASPCategory.A01_BROKEN_ACCESS_CONTROL: "path_traversal",
        }
        return mapping.get(cat, "sqli")

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings (same file + same title)."""
        seen: set[str] = set()
        unique: list[Finding] = []
        for f in findings:
            key = f"{f.snippet.file if f.snippet else 'N/A'}::{f.title}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
