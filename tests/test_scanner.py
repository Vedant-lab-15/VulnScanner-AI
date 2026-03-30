"""
Tests for the core scanner orchestrator, SCA scanner, and simulation engine.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from vulnscanner.utils.models import Severity, OWASPCategory, DetectionMethod


class TestScannerCore:
    def test_scan_directory_returns_result(self, samples_dir):
        from vulnscanner.scanner.core import Scanner
        scanner = Scanner(enable_ml=False, enable_simulation=False, enable_sca=False)
        result = scanner.scan_directory(samples_dir)
        assert result.summary.total_findings >= 10
        assert result.metadata.files_scanned >= 4
        assert result.metadata.scanner_version == "1.0.0"

    def test_scan_finds_critical_vulns(self, samples_dir):
        from vulnscanner.scanner.core import Scanner
        scanner = Scanner(enable_ml=False, enable_simulation=False, enable_sca=False)
        result = scanner.scan_directory(samples_dir)
        assert result.summary.critical >= 1

    def test_scan_metadata_populated(self, samples_dir):
        from vulnscanner.scanner.core import Scanner
        result = Scanner(enable_ml=False, enable_simulation=False, enable_sca=False).scan_directory(samples_dir)
        assert result.metadata.scan_id
        assert result.metadata.started_at
        assert result.metadata.finished_at
        assert result.metadata.lines_scanned > 0
        assert len(result.metadata.languages_detected) >= 1

    def test_risk_score_nonzero_for_vulns(self, samples_dir):
        from vulnscanner.scanner.core import Scanner
        result = Scanner(enable_ml=False, enable_simulation=False, enable_sca=False).scan_directory(samples_dir)
        assert result.summary.overall_risk_score > 0

    def test_ml_enrichment_adds_prediction(self, samples_dir):
        from vulnscanner.scanner.core import Scanner
        result = Scanner(enable_ml=True, enable_simulation=False, enable_sca=False).scan_directory(samples_dir)
        findings_with_ml = [f for f in result.findings if f.ml_prediction is not None]
        assert len(findings_with_ml) >= 1

    def test_ml_confidence_in_range(self, samples_dir):
        from vulnscanner.scanner.core import Scanner
        result = Scanner(enable_ml=True, enable_simulation=False, enable_sca=False).scan_directory(samples_dir)
        for f in result.findings:
            if f.ml_prediction:
                assert 0.0 <= f.ml_prediction.confidence <= 1.0

    def test_deduplication_no_exact_duplicates(self, samples_dir):
        from vulnscanner.scanner.core import Scanner
        result = Scanner(enable_ml=False, enable_simulation=False, enable_sca=False).scan_directory(samples_dir)
        keys = [(f.snippet.file if f.snippet else "", f.title) for f in result.findings]
        assert len(keys) == len(set(keys)), "Duplicate findings detected"

    def test_empty_directory_returns_zero_findings(self, tmp_path):
        from vulnscanner.scanner.core import Scanner
        result = Scanner(enable_ml=False, enable_simulation=False, enable_sca=False).scan_directory(tmp_path)
        assert result.summary.total_findings == 0
        assert result.metadata.files_scanned == 0

    def test_owasp_coverage_populated(self, samples_dir):
        from vulnscanner.scanner.core import Scanner
        result = Scanner(enable_ml=False, enable_simulation=False, enable_sca=False).scan_directory(samples_dir)
        assert len(result.summary.owasp_coverage) >= 3

    def test_findings_have_valid_cvss(self, samples_dir):
        from vulnscanner.scanner.core import Scanner
        result = Scanner(enable_ml=False, enable_simulation=False, enable_sca=False).scan_directory(samples_dir)
        for f in result.findings:
            assert 0.0 <= f.cvss_score <= 10.0


class TestSCAScanner:
    def test_detects_vulnerable_django(self, tmp_path):
        from vulnscanner.scanner.sca import SCAScanner
        req = tmp_path / "requirements.txt"
        req.write_text("django==4.2.0\nrequests==2.28.0\n")
        sca = SCAScanner(use_osv_api=False)
        findings = sca.scan_directory(tmp_path)
        pkgs = [f["package"] for f in findings]
        assert "django" in pkgs

    def test_detects_vulnerable_flask(self, tmp_path):
        from vulnscanner.scanner.sca import SCAScanner
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.3.0\n")
        sca = SCAScanner(use_osv_api=False)
        findings = sca.scan_directory(tmp_path)
        assert any(f["package"] == "flask" for f in findings)

    def test_safe_version_not_flagged(self, tmp_path):
        from vulnscanner.scanner.sca import SCAScanner
        req = tmp_path / "requirements.txt"
        req.write_text("django==4.2.10\n")  # patched version
        sca = SCAScanner(use_osv_api=False)
        findings = sca.scan_directory(tmp_path)
        assert len(findings) == 0

    def test_parses_package_json(self, tmp_path):
        from vulnscanner.scanner.sca import SCAScanner
        import json
        pkg = tmp_path / "package.json"
        pkg.write_text(json.dumps({"dependencies": {"lodash": "4.17.15"}}))
        sca = SCAScanner(use_osv_api=False)
        findings = sca.scan_directory(tmp_path)
        assert any(f["package"] == "lodash" for f in findings)

    def test_finding_has_required_fields(self, tmp_path):
        from vulnscanner.scanner.sca import SCAScanner
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.3.0\n")
        sca = SCAScanner(use_osv_api=False)
        findings = sca.scan_directory(tmp_path)
        assert len(findings) >= 1
        f = findings[0]
        assert "package" in f
        assert "version" in f
        assert "cve" in f
        assert "severity" in f
        assert "fixed_version" in f

    def test_skips_node_modules(self, tmp_path):
        from vulnscanner.scanner.sca import SCAScanner
        import json
        nm = tmp_path / "node_modules" / "lodash"
        nm.mkdir(parents=True)
        pkg = nm / "package.json"
        pkg.write_text(json.dumps({"dependencies": {"lodash": "4.17.15"}}))
        sca = SCAScanner(use_osv_api=False)
        findings = sca.scan_directory(tmp_path)
        assert len(findings) == 0

    def test_log4j_detected(self, tmp_path):
        from vulnscanner.scanner.sca import SCAScanner
        pom = tmp_path / "pom.xml"
        pom.write_text("""
        <dependencies>
          <dependency>
            <artifactId>log4j</artifactId>
            <version>2.14.0</version>
          </dependency>
        </dependencies>
        """)
        sca = SCAScanner(use_osv_api=False)
        findings = sca.scan_directory(tmp_path)
        assert any(f["package"] == "log4j" for f in findings)


class TestSimulator:
    def test_taint_analysis_detects_sqli(self):
        from vulnscanner.simulation.simulator import SafeSimulator
        with SafeSimulator() as sim:
            result = sim.simulate_code(
                'user_id = request.args["id"]\ncursor.execute("SELECT * FROM users WHERE id = " + user_id)',
                "sqli", "python"
            )
        assert result is not None
        assert "sink" in result.risk_indicator.lower() or "taint" in result.risk_indicator.lower()

    def test_taint_analysis_detects_ssrf(self):
        from vulnscanner.simulation.simulator import SafeSimulator
        with SafeSimulator() as sim:
            result = sim.simulate_code(
                'requests.get(request.args["url"])',
                "ssrf", "python"
            )
        assert result is not None

    def test_safe_code_no_taint(self):
        from vulnscanner.simulation.simulator import SafeSimulator
        with SafeSimulator() as sim:
            result = sim.simulate_code(
                'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
                "sqli", "python"
            )
        # Parameterised query — no source→sink flow
        assert result is None or not result.confirmed

    def test_simulation_result_fields(self):
        from vulnscanner.simulation.simulator import SafeSimulator
        with SafeSimulator() as sim:
            result = sim.simulate_code(
                'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
                "sqli", "python"
            )
        if result:
            assert result.payload_used
            assert result.risk_indicator
            assert isinstance(result.confirmed, bool)


class TestModels:
    def test_finding_serialisation(self, sample_finding):
        json_str = sample_finding.model_dump_json()
        assert "SQL Injection" in json_str
        assert "CRITICAL" in json_str

    def test_scan_result_serialisation(self, sample_scan_result):
        json_str = sample_scan_result.model_dump_json()
        assert "TEST0001" in json_str
        assert "total_findings" in json_str

    def test_scan_result_deserialisation(self, sample_scan_result):
        from vulnscanner.utils.models import ScanResult
        json_str = sample_scan_result.model_dump_json()
        restored = ScanResult.model_validate_json(json_str)
        assert restored.metadata.scan_id == "TEST0001"
        assert len(restored.findings) == 1
        assert restored.findings[0].title == "SQL Injection via string concatenation"

    def test_severity_ordering(self):
        from vulnscanner.utils.models import Severity
        sevs = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        assert all(s.value for s in sevs)
