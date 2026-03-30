"""
Safe test payload library.

IMPORTANT: These payloads are designed to be DETECTABLE but NOT HARMFUL.
They use well-known benign probe strings that trigger error messages or
observable behaviour without causing data loss, system compromise, or
denial of service.

All payloads are sourced from public security research and OWASP testing guides.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Payload:
    name: str
    value: str
    category: str
    risk_indicators: list[str]   # strings to look for in responses
    description: str


# ---------------------------------------------------------------------------
# SQL Injection probes (error-based detection only — no data extraction)
# ---------------------------------------------------------------------------
SQL_PAYLOADS: list[Payload] = [
    Payload(
        name="single_quote",
        value="'",
        category="sqli",
        risk_indicators=["syntax error", "mysql_fetch", "ORA-", "sqlite3", "pg_query", "SQLSTATE"],
        description="Single quote to trigger SQL syntax error",
    ),
    Payload(
        name="boolean_true",
        value="1 OR 1=1",
        category="sqli",
        risk_indicators=["syntax error", "warning", "error"],
        description="Boolean tautology probe",
    ),
    Payload(
        name="comment_probe",
        value="1--",
        category="sqli",
        risk_indicators=["syntax error", "unexpected", "warning"],
        description="SQL comment terminator probe",
    ),
]

# ---------------------------------------------------------------------------
# XSS probes (non-executing — checks for reflection only)
# ---------------------------------------------------------------------------
XSS_PAYLOADS: list[Payload] = [
    Payload(
        name="xss_probe_tag",
        value="<vulnscanner-xss-probe>",
        category="xss",
        risk_indicators=["<vulnscanner-xss-probe>"],
        description="Custom non-executing tag to detect reflection",
    ),
    Payload(
        name="xss_probe_attr",
        value='"><vulnscanner-probe',
        category="xss",
        risk_indicators=["vulnscanner-probe"],
        description="Attribute breakout probe (non-executing)",
    ),
]

# ---------------------------------------------------------------------------
# SSRF probes (uses safe internal probe endpoints)
# ---------------------------------------------------------------------------
SSRF_PAYLOADS: list[Payload] = [
    Payload(
        name="ssrf_localhost",
        value="http://127.0.0.1:80/",
        category="ssrf",
        risk_indicators=["connection refused", "timeout", "200 ok", "html"],
        description="Localhost probe to detect SSRF",
    ),
    Payload(
        name="ssrf_metadata_aws",
        value="http://169.254.169.254/latest/meta-data/",
        category="ssrf",
        risk_indicators=["ami-id", "instance-id", "200"],
        description="AWS metadata endpoint probe (read-only)",
    ),
]

# ---------------------------------------------------------------------------
# Path traversal probes
# ---------------------------------------------------------------------------
PATH_TRAVERSAL_PAYLOADS: list[Payload] = [
    Payload(
        name="traversal_unix",
        value="../../../../etc/passwd",
        category="path_traversal",
        risk_indicators=["root:x:", "daemon:", "nobody:"],
        description="Unix path traversal probe",
    ),
    Payload(
        name="traversal_windows",
        value="..\\..\\..\\windows\\win.ini",
        category="path_traversal",
        risk_indicators=["[fonts]", "[extensions]", "[mci"],
        description="Windows path traversal probe",
    ),
]

# ---------------------------------------------------------------------------
# Command injection probes (safe — uses echo/sleep with unique markers)
# ---------------------------------------------------------------------------
CMD_INJECTION_PAYLOADS: list[Payload] = [
    Payload(
        name="cmd_echo_unix",
        value=";echo VULNSCANNER_CMD_PROBE_7x9z",
        category="cmdi",
        risk_indicators=["VULNSCANNER_CMD_PROBE_7x9z"],
        description="Echo probe to detect command injection (Unix)",
    ),
    Payload(
        name="cmd_echo_windows",
        value="&echo VULNSCANNER_CMD_PROBE_7x9z",
        category="cmdi",
        risk_indicators=["VULNSCANNER_CMD_PROBE_7x9z"],
        description="Echo probe to detect command injection (Windows)",
    ),
]

ALL_PAYLOADS: dict[str, list[Payload]] = {
    "sqli": SQL_PAYLOADS,
    "xss": XSS_PAYLOADS,
    "ssrf": SSRF_PAYLOADS,
    "path_traversal": PATH_TRAVERSAL_PAYLOADS,
    "cmdi": CMD_INJECTION_PAYLOADS,
}
