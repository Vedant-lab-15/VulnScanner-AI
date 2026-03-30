"""
Plotly chart data builders for the HTML report.
Returns JSON-serialisable dicts that are embedded directly in the HTML.
"""

from __future__ import annotations

import json
from typing import Any

from vulnscanner.utils.models import ScanResult, Severity


def build_charts_json(result: ScanResult) -> dict[str, str]:
    """Return a dict of chart_name -> JSON string for Plotly."""
    return {
        "severity_pie": json.dumps(_severity_pie(result)),
        "owasp_bar": json.dumps(_owasp_bar(result)),
        "risk_gauge": json.dumps(_risk_gauge(result)),
        "detection_method_donut": json.dumps(_detection_method_donut(result)),
    }


def _severity_pie(result: ScanResult) -> dict[str, Any]:
    labels = ["Critical", "High", "Medium", "Low", "Info"]
    values = [
        result.summary.critical,
        result.summary.high,
        result.summary.medium,
        result.summary.low,
        result.summary.info,
    ]
    colors = ["#ff4757", "#ff6b35", "#ffa502", "#2ed573", "#70a1ff"]
    return {
        "data": [{
            "type": "pie",
            "labels": labels,
            "values": values,
            "marker": {"colors": colors},
            "hole": 0.4,
            "textinfo": "label+percent",
            "textfont": {"color": "#c9d1d9"},
        }],
        "layout": {
            "paper_bgcolor": "#161b22",
            "plot_bgcolor": "#161b22",
            "font": {"color": "#c9d1d9"},
            "title": {"text": "Findings by Severity", "font": {"color": "#58a6ff"}},
            "showlegend": True,
            "legend": {"font": {"color": "#c9d1d9"}},
            "margin": {"t": 50, "b": 20, "l": 20, "r": 20},
        },
    }


def _owasp_bar(result: ScanResult) -> dict[str, Any]:
    coverage = result.summary.owasp_coverage
    # Shorten labels for display
    labels = [k.split("–")[0].strip() for k in coverage.keys()]
    values = list(coverage.values())
    return {
        "data": [{
            "type": "bar",
            "x": labels,
            "y": values,
            "marker": {
                "color": values,
                "colorscale": [[0, "#2ed573"], [0.5, "#ffa502"], [1, "#ff4757"]],
                "showscale": False,
            },
            "text": values,
            "textposition": "outside",
            "textfont": {"color": "#c9d1d9"},
        }],
        "layout": {
            "paper_bgcolor": "#161b22",
            "plot_bgcolor": "#161b22",
            "font": {"color": "#c9d1d9"},
            "title": {"text": "OWASP Top 10 Coverage", "font": {"color": "#58a6ff"}},
            "xaxis": {"tickfont": {"color": "#8b949e"}, "gridcolor": "#30363d"},
            "yaxis": {"tickfont": {"color": "#8b949e"}, "gridcolor": "#30363d"},
            "margin": {"t": 50, "b": 80, "l": 40, "r": 20},
        },
    }


def _risk_gauge(result: ScanResult) -> dict[str, Any]:
    score = result.summary.overall_risk_score
    return {
        "data": [{
            "type": "indicator",
            "mode": "gauge+number+delta",
            "value": score,
            "title": {"text": "Overall Risk Score", "font": {"color": "#58a6ff", "size": 16}},
            "number": {"font": {"color": "#c9d1d9", "size": 40}},
            "gauge": {
                "axis": {"range": [0, 100], "tickcolor": "#8b949e"},
                "bar": {"color": "#ff4757" if score >= 70 else "#ffa502" if score >= 40 else "#2ed573"},
                "bgcolor": "#0d1117",
                "bordercolor": "#30363d",
                "steps": [
                    {"range": [0, 40], "color": "#1a2a1a"},
                    {"range": [40, 70], "color": "#2a2a1a"},
                    {"range": [70, 100], "color": "#2a1a1a"},
                ],
                "threshold": {
                    "line": {"color": "#ff4757", "width": 4},
                    "thickness": 0.75,
                    "value": 70,
                },
            },
        }],
        "layout": {
            "paper_bgcolor": "#161b22",
            "font": {"color": "#c9d1d9"},
            "margin": {"t": 60, "b": 20, "l": 30, "r": 30},
            "height": 250,
        },
    }


def _detection_method_donut(result: ScanResult) -> dict[str, Any]:
    from collections import Counter
    counts = Counter(f.detection_method.value for f in result.findings)
    labels = list(counts.keys())
    values = list(counts.values())
    colors = {"pattern": "#58a6ff", "ml": "#bc8cff", "simulation": "#ff6b35", "sca": "#2ed573", "combined": "#ffa502"}
    marker_colors = [colors.get(l, "#a4b0be") for l in labels]
    return {
        "data": [{
            "type": "pie",
            "labels": labels,
            "values": values,
            "marker": {"colors": marker_colors},
            "hole": 0.5,
            "textinfo": "label+value",
            "textfont": {"color": "#c9d1d9"},
        }],
        "layout": {
            "paper_bgcolor": "#161b22",
            "font": {"color": "#c9d1d9"},
            "title": {"text": "Detection Methods", "font": {"color": "#58a6ff"}},
            "showlegend": True,
            "legend": {"font": {"color": "#c9d1d9"}},
            "margin": {"t": 50, "b": 20, "l": 20, "r": 20},
        },
    }
