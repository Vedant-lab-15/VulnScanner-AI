"""
Report generator — produces HTML, SARIF, and optional PDF outputs.
"""

from __future__ import annotations

import json
import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from vulnscanner.utils.logging import get_logger
from vulnscanner.utils.models import ScanResult, Severity, Finding
from .charts import build_charts_json
from .sarif import to_sarif

logger = get_logger(__name__)

def _resolve_templates_dir() -> Path:
    for p in [Path(__file__).parents[3], Path(__file__).parents[2], Path.cwd()]:
        candidate = p / "templates"
        if candidate.exists():
            return candidate
    return Path.cwd() / "templates"

_TEMPLATES_DIR = _resolve_templates_dir()


class ReportGenerator:
    """Generates all report formats from a ScanResult."""

    def __init__(self, templates_dir: Path | None = None) -> None:
        self.templates_dir = templates_dir or _TEMPLATES_DIR
        self._env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=select_autoescape(["html"]),  # .j2 files opt-in via | safe
        )
        self._env.filters["severity_color"] = _severity_color
        self._env.filters["severity_badge"] = _severity_badge
        self._env.filters["truncate_code"] = lambda s, n=300: s[:n] + "…" if len(s) > n else s

    # ------------------------------------------------------------------
    # HTML report
    # ------------------------------------------------------------------

    def generate_html(self, result: ScanResult, output_path: Path) -> Path:
        """Render the self-contained dark-theme HTML report."""
        charts = build_charts_json(result)

        # Try to embed Plotly inline for offline use; fall back to CDN
        plotly_script = self._get_plotly_script()

        context = {
            "result": result,
            "charts": charts,
            "plotly_script": plotly_script,
            "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "severity_order": [s.value for s in Severity],
            "findings_by_severity": _group_by_severity(result.findings),
            "owasp_coverage": result.summary.owasp_coverage,
            "sca_findings": result.sca_findings,
        }

        try:
            # Try .j2 first (Jinja2 template), then plain .html
            for tpl_name in ("report.html.j2", "report.html"):
                try:
                    template = self._env.get_template(tpl_name)
                    break
                except Exception:
                    continue
            else:
                raise FileNotFoundError("No report template found")
            html = template.render(**context)
        except Exception as exc:
            logger.warning(f"Template render failed ({exc}), using fallback renderer")
            html = _fallback_html(result, charts, plotly_script)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")
        logger.info(f"HTML report saved to {output_path}")
        return output_path

    def generate_sarif(self, result: ScanResult, output_path: Path) -> Path:
        sarif_doc = to_sarif(result)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
        logger.info(f"SARIF report saved to {output_path}")
        return output_path

    # ------------------------------------------------------------------
    # JSON export (machine-readable)
    # ------------------------------------------------------------------

    def generate_json(self, result: ScanResult, output_path: Path) -> Path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        logger.info(f"JSON report saved to {output_path}")
        return output_path

    # ------------------------------------------------------------------
    # PDF export (optional — requires weasyprint)
    # ------------------------------------------------------------------

    def generate_pdf(self, result: ScanResult, output_path: Path) -> Path:
        html_path = output_path.with_suffix(".html")
        self.generate_html(result, html_path)
        try:
            from weasyprint import HTML
            HTML(filename=str(html_path)).write_pdf(str(output_path))
            logger.info(f"PDF report saved to {output_path}")
        except ImportError:
            logger.warning("weasyprint not installed — PDF export skipped")
        return output_path

    # ------------------------------------------------------------------
    # Plotly bundling
    # ------------------------------------------------------------------

    def _get_plotly_script(self) -> str:
        """
        Return either an inline <script> with Plotly bundled (offline-safe)
        or a CDN <script src> tag as fallback.
        """
        # Check for a locally cached copy next to the templates dir
        candidates = [
            self.templates_dir / "plotly.min.js",
            Path(__file__).parents[3] / "templates" / "plotly.min.js",
        ]
        for p in candidates:
            if p.exists() and p.stat().st_size > 100_000:
                logger.debug(f"Using local Plotly bundle: {p}")
                return f"<script>{p.read_text(encoding='utf-8')}</script>"

        # Try downloading and caching it
        try:
            import urllib.request
            url = "https://cdn.plot.ly/plotly-2.27.0.min.js"
            cache_path = self.templates_dir / "plotly.min.js"
            urllib.request.urlretrieve(url, cache_path)
            logger.info("Plotly downloaded and cached for offline use")
            return f"<script>{cache_path.read_text(encoding='utf-8')}</script>"
        except Exception:
            pass

        # Final fallback: CDN tag (requires internet)
        return '<script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>'


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _group_by_severity(findings: list[Finding]) -> dict[str, list[Finding]]:
    groups: dict[str, list[Finding]] = {s.value: [] for s in Severity}
    for f in findings:
        groups[f.severity.value].append(f)
    return groups


def _severity_color(severity: str) -> str:
    return {
        "CRITICAL": "#ff4757",
        "HIGH": "#ff6b35",
        "MEDIUM": "#ffa502",
        "LOW": "#2ed573",
        "INFO": "#70a1ff",
    }.get(severity, "#a4b0be")


def _severity_badge(severity: str) -> str:
    colors = {
        "CRITICAL": "bg-red-600",
        "HIGH": "bg-orange-500",
        "MEDIUM": "bg-yellow-500",
        "LOW": "bg-green-500",
        "INFO": "bg-blue-500",
    }
    cls = colors.get(severity, "bg-gray-500")
    return f'<span class="px-2 py-0.5 rounded text-xs font-bold text-white {cls}">{severity}</span>'


def _fallback_html(result: ScanResult, charts: dict[str, Any], plotly_script: str = "") -> str:
    """Minimal inline HTML when the Jinja2 template is unavailable."""
    findings_html = ""
    for f in result.findings:
        color = _severity_color(f.severity.value)
        snippet = f.snippet.content.replace("<", "&lt;").replace(">", "&gt;") if f.snippet else ""
        findings_html += f"""
        <div class="finding">
          <h3 style="color:{color}">[{f.severity.value}] {f.id} — {f.title}</h3>
          <p><b>OWASP:</b> {f.owasp_category.value}</p>
          <p><b>CVSS:</b> {f.cvss_score} | <b>CWE:</b> {f.cwe_id or 'N/A'}</p>
          <p>{f.description}</p>
          {"<pre><code>" + snippet + "</code></pre>" if snippet else ""}
          <p><b>Remediation:</b> {f.remediation.summary}</p>
        </div>
        """

    sca_html = ""
    for s in result.sca_findings:
        sca_html += f"""
        <div class="finding">
          <h3 style="color:#ff6b35">[{s['severity']}] {s['package']} {s['version']} — {s['cve']}</h3>
          <p>{s['description']}</p>
          <p><b>Fix:</b> Upgrade to {s['fixed_version']}</p>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnScanner AI — Security Report</title>
{plotly_script}
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', sans-serif; padding: 2rem; }}
  h1 {{ color: #58a6ff; font-size: 2rem; margin-bottom: 0.5rem; }}
  h2 {{ color: #79c0ff; margin: 2rem 0 1rem; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; }}
  h3 {{ margin-bottom: 0.5rem; }}
  .meta {{ color: #8b949e; margin-bottom: 2rem; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; text-align: center; }}
  .stat-card .num {{ font-size: 2rem; font-weight: bold; }}
  .finding {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; }}
  .finding p {{ margin: 0.4rem 0; color: #8b949e; }}
  pre {{ background: #0d1117; border: 1px solid #30363d; border-radius: 4px; padding: 1rem; overflow-x: auto; margin: 0.5rem 0; font-size: 0.85rem; }}
  code {{ color: #e6edf3; }}
  .risk-score {{ font-size: 3rem; font-weight: bold; color: #ff4757; }}
</style>
</head>
<body>
<h1>🛡️ VulnScanner AI — Security Report</h1>
<div class="meta">
  Scan ID: {result.metadata.scan_id} &nbsp;|&nbsp;
  Target: {result.metadata.target.value} &nbsp;|&nbsp;
  Generated: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
</div>

<h2>Executive Summary</h2>
<div class="summary-grid">
  <div class="stat-card"><div class="num" style="color:#ff4757">{result.summary.critical}</div><div>Critical</div></div>
  <div class="stat-card"><div class="num" style="color:#ff6b35">{result.summary.high}</div><div>High</div></div>
  <div class="stat-card"><div class="num" style="color:#ffa502">{result.summary.medium}</div><div>Medium</div></div>
  <div class="stat-card"><div class="num" style="color:#2ed573">{result.summary.low}</div><div>Low</div></div>
  <div class="stat-card"><div class="num risk-score">{result.summary.overall_risk_score:.0f}</div><div>Risk Score</div></div>
  <div class="stat-card"><div class="num" style="color:#58a6ff">{result.metadata.files_scanned}</div><div>Files Scanned</div></div>
</div>

<h2>Vulnerability Findings ({len(result.findings)})</h2>
{findings_html}

<h2>Dependency Vulnerabilities ({len(result.sca_findings)})</h2>
{sca_html}

<footer style="margin-top:3rem;color:#484f58;font-size:0.8rem;">
  Generated by VulnScanner AI v{result.metadata.scanner_version} &nbsp;|&nbsp;
  Only scan systems you are authorised to test.
</footer>
</body>
</html>"""
