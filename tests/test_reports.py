"""
Tests for report generation — HTML, SARIF, JSON outputs.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulnscanner.report.generator import ReportGenerator
from vulnscanner.report.sarif import to_sarif
from vulnscanner.report.charts import build_charts_json


class TestHTMLReport:
    def test_generates_html_file(self, sample_scan_result, tmp_path):
        gen = ReportGenerator()
        out = tmp_path / "report.html"
        gen.generate_html(sample_scan_result, out)
        assert out.exists()
        assert out.stat().st_size > 1000

    def test_html_contains_scan_id(self, sample_scan_result, tmp_path):
        gen = ReportGenerator()
        out = tmp_path / "report.html"
        gen.generate_html(sample_scan_result, out)
        content = out.read_text()
        assert sample_scan_result.metadata.scan_id in content

    def test_html_contains_finding_title(self, sample_scan_result, tmp_path):
        gen = ReportGenerator()
        out = tmp_path / "report.html"
        gen.generate_html(sample_scan_result, out)
        content = out.read_text()
        assert "SQL Injection" in content

    def test_html_no_unrendered_jinja_tags(self, sample_scan_result, tmp_path):
        gen = ReportGenerator()
        out = tmp_path / "report.html"
        gen.generate_html(sample_scan_result, out)
        content = out.read_text()
        assert "{{" not in content, "Unrendered Jinja2 tags found in output"
        assert "{%" not in content, "Unrendered Jinja2 block tags found in output"

    def test_html_dark_theme_present(self, sample_scan_result, tmp_path):
        gen = ReportGenerator()
        out = tmp_path / "report.html"
        gen.generate_html(sample_scan_result, out)
        content = out.read_text()
        assert "--bg-primary" in content or "0d1117" in content

    def test_html_creates_parent_dirs(self, sample_scan_result, tmp_path):
        gen = ReportGenerator()
        out = tmp_path / "nested" / "deep" / "report.html"
        gen.generate_html(sample_scan_result, out)
        assert out.exists()

    def test_fallback_renderer_works_without_template(self, sample_scan_result, tmp_path):
        gen = ReportGenerator(templates_dir=tmp_path / "nonexistent")
        out = tmp_path / "report.html"
        gen.generate_html(sample_scan_result, out)
        assert out.exists()
        content = out.read_text()
        assert "VulnScanner AI" in content
        assert "SQL Injection" in content


class TestSARIFReport:
    def test_generates_sarif_file(self, sample_scan_result, tmp_path):
        gen = ReportGenerator()
        out = tmp_path / "report.sarif.json"
        gen.generate_sarif(sample_scan_result, out)
        assert out.exists()

    def test_sarif_valid_json(self, sample_scan_result, tmp_path):
        gen = ReportGenerator()
        out = tmp_path / "report.sarif.json"
        gen.generate_sarif(sample_scan_result, out)
        data = json.loads(out.read_text())
        assert isinstance(data, dict)

    def test_sarif_version_2_1_0(self, sample_scan_result):
        sarif = to_sarif(sample_scan_result)
        assert sarif["version"] == "2.1.0"

    def test_sarif_has_schema(self, sample_scan_result):
        sarif = to_sarif(sample_scan_result)
        assert "$schema" in sarif
        assert "sarif" in sarif["$schema"]

    def test_sarif_has_runs(self, sample_scan_result):
        sarif = to_sarif(sample_scan_result)
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_sarif_tool_name(self, sample_scan_result):
        sarif = to_sarif(sample_scan_result)
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "VulnScanner AI"

    def test_sarif_results_count(self, sample_scan_result):
        sarif = to_sarif(sample_scan_result)
        results = sarif["runs"][0]["results"]
        assert len(results) == len(sample_scan_result.findings)

    def test_sarif_result_has_level(self, sample_scan_result):
        sarif = to_sarif(sample_scan_result)
        result = sarif["runs"][0]["results"][0]
        assert result["level"] in ("error", "warning", "note", "none")

    def test_sarif_result_has_message(self, sample_scan_result):
        sarif = to_sarif(sample_scan_result)
        result = sarif["runs"][0]["results"][0]
        assert "message" in result
        assert "text" in result["message"]

    def test_sarif_result_has_location(self, sample_scan_result):
        sarif = to_sarif(sample_scan_result)
        result = sarif["runs"][0]["results"][0]
        assert "locations" in result
        assert len(result["locations"]) >= 1

    def test_sarif_rules_populated(self, sample_scan_result):
        sarif = to_sarif(sample_scan_result)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) >= 1

    def test_sarif_sca_findings_included(self, sample_scan_result):
        sample_scan_result.sca_findings = [{
            "package": "django", "version": "4.2.0",
            "cve": "CVE-2023-36053", "severity": "HIGH",
            "description": "ReDoS", "fixed_version": "4.2.3",
            "file": "requirements.txt",
        }]
        sarif = to_sarif(sample_scan_result)
        results = sarif["runs"][0]["results"]
        # findings + 1 SCA
        assert len(results) == len(sample_scan_result.findings) + 1


class TestJSONReport:
    def test_generates_json_file(self, sample_scan_result, tmp_path):
        gen = ReportGenerator()
        out = tmp_path / "result.json"
        gen.generate_json(sample_scan_result, out)
        assert out.exists()

    def test_json_valid_and_parseable(self, sample_scan_result, tmp_path):
        gen = ReportGenerator()
        out = tmp_path / "result.json"
        gen.generate_json(sample_scan_result, out)
        data = json.loads(out.read_text())
        assert "metadata" in data
        assert "findings" in data
        assert "summary" in data

    def test_json_round_trip(self, sample_scan_result, tmp_path):
        from vulnscanner.utils.models import ScanResult
        gen = ReportGenerator()
        out = tmp_path / "result.json"
        gen.generate_json(sample_scan_result, out)
        restored = ScanResult.model_validate_json(out.read_text())
        assert restored.metadata.scan_id == sample_scan_result.metadata.scan_id
        assert len(restored.findings) == len(sample_scan_result.findings)


class TestCharts:
    def test_build_charts_returns_all_keys(self, sample_scan_result):
        charts = build_charts_json(sample_scan_result)
        assert "severity_pie" in charts
        assert "owasp_bar" in charts
        assert "risk_gauge" in charts
        assert "detection_method_donut" in charts

    def test_charts_are_valid_json(self, sample_scan_result):
        charts = build_charts_json(sample_scan_result)
        for key, val in charts.items():
            data = json.loads(val)
            assert "data" in data
            assert "layout" in data

    def test_risk_gauge_value_matches_score(self, sample_scan_result):
        charts = build_charts_json(sample_scan_result)
        gauge = json.loads(charts["risk_gauge"])
        assert gauge["data"][0]["value"] == sample_scan_result.summary.overall_risk_score

    def test_severity_pie_has_five_slices(self, sample_scan_result):
        charts = build_charts_json(sample_scan_result)
        pie = json.loads(charts["severity_pie"])
        assert len(pie["data"][0]["labels"]) == 5
