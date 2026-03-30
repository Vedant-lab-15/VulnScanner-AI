"""
Safe exploit simulation engine.

For URL-based scans: sends benign probe payloads to discovered endpoints
and analyses responses for risk indicators — no actual exploitation.

For code-based scans: performs static taint analysis to simulate whether
a payload could reach a sink, returning a risk confidence score.

ETHICAL NOTE: Only scan systems you own or have explicit written permission
to test. This tool is for authorised security assessments only.
"""

from __future__ import annotations

import re
import time
from urllib.parse import urlencode, urljoin, urlparse

import httpx

from vulnscanner.utils.logging import get_logger
from vulnscanner.utils.models import SimulationResult
from .payloads import ALL_PAYLOADS, Payload

logger = get_logger(__name__)

# Safety limits
_MAX_REQUESTS_PER_ENDPOINT = 5
_REQUEST_TIMEOUT = 8.0
_DELAY_BETWEEN_REQUESTS = 0.5   # seconds — be polite


class SafeSimulator:
    """
    Performs safe, non-destructive exploit simulation.

    URL mode: sends probe payloads to GET parameters and analyses responses.
    Code mode: static taint-flow analysis to estimate exploitability.
    """

    def __init__(self, timeout: float = _REQUEST_TIMEOUT, delay: float = _DELAY_BETWEEN_REQUESTS) -> None:
        self.timeout = timeout
        self.delay = delay
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            verify=True,
            headers={"User-Agent": "VulnScanner-AI/1.0 (Security Research; Authorised)"},
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "SafeSimulator":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # URL-based simulation
    # ------------------------------------------------------------------

    def simulate_url(
        self,
        base_url: str,
        param_name: str,
        vuln_type: str,
        original_value: str = "1",
    ) -> SimulationResult | None:
        """
        Send probe payloads for *vuln_type* to *param_name* in *base_url*.
        Returns the first SimulationResult that shows a risk indicator, or None.
        """
        payloads = ALL_PAYLOADS.get(vuln_type, [])
        if not payloads:
            return None

        for payload in payloads[:_MAX_REQUESTS_PER_ENDPOINT]:
            result = self._probe_get_param(base_url, param_name, payload)
            if result:
                return result
            time.sleep(self.delay)

        return None

    def _probe_get_param(
        self, base_url: str, param: str, payload: Payload
    ) -> SimulationResult | None:
        """Inject payload into a single GET parameter and check response."""
        try:
            url = f"{base_url}?{urlencode({param: payload.value})}"
            resp = self._client.get(url)
            body = resp.text[:4000]  # limit response analysis

            for indicator in payload.risk_indicators:
                if indicator.lower() in body.lower():
                    snippet = self._extract_context(body, indicator)
                    logger.debug(f"Risk indicator '{indicator}' found for {payload.name}")
                    return SimulationResult(
                        payload_used=payload.value,
                        response_snippet=snippet,
                        risk_indicator=indicator,
                        confirmed=True,
                    )

            # Check for error patterns even without exact indicator match
            if resp.status_code >= 500:
                return SimulationResult(
                    payload_used=payload.value,
                    response_snippet=body[:200],
                    risk_indicator=f"HTTP {resp.status_code} server error",
                    confirmed=False,
                )

        except httpx.RequestError as exc:
            logger.debug(f"Request failed for {base_url}: {exc}")

        return None

    # ------------------------------------------------------------------
    # Code-based taint simulation
    # ------------------------------------------------------------------

    def simulate_code(self, code: str, vuln_type: str, language: str = "python") -> SimulationResult | None:
        """
        Static taint analysis: check if user input can reach a dangerous sink.
        Returns a SimulationResult with a risk assessment.
        """
        taint_result = self._taint_analysis(code, vuln_type, language)
        if taint_result["tainted"]:
            payload = ALL_PAYLOADS.get(vuln_type, [{}])[0] if ALL_PAYLOADS.get(vuln_type) else None
            return SimulationResult(
                payload_used=payload.value if payload else "N/A",
                response_snippet=taint_result.get("evidence"),
                risk_indicator=taint_result["reason"],
                confirmed=taint_result["confidence"] > 0.7,
            )
        return None

    def _taint_analysis(self, code: str, vuln_type: str, language: str) -> dict:
        """
        Simplified taint analysis: check for source→sink data flow patterns.
        """
        sources = {
            "python": [
                r"request\.(args|form|json|data|cookies)\[",
                r"request\.(args|form|json|data|cookies)\.get\(",
            ],
            "javascript": [
                r"req\.(query|body|params)\.",
                r"request\.(query|body|params)\.",
            ],
            "php": [r"\$_(GET|POST|REQUEST|COOKIE)\["],
            "java": [r"request\.getParameter\(", r"request\.getHeader\("],
        }

        sinks = {
            "sqli": [r"execute\s*\(", r"query\s*\(", r"raw\s*\("],
            "xss": [r"innerHTML", r"render_template_string", r"echo\s+\$", r"document\.write"],
            "cmdi": [r"os\.system\s*\(", r"subprocess\.", r"exec\s*\(", r"shell_exec"],
            "ssrf": [r"requests\.(get|post)", r"urllib", r"fetch\s*\(", r"curl_"],
            "path_traversal": [r"open\s*\(", r"readFile\s*\(", r"file_get_contents"],
        }

        lang_sources = sources.get(language, [])
        vuln_sinks = sinks.get(vuln_type, [])

        has_source = any(re.search(p, code, re.IGNORECASE) for p in lang_sources)
        has_sink = any(re.search(p, code, re.IGNORECASE) for p in vuln_sinks)

        if has_source and has_sink:
            # Check for sanitisation
            sanitisers = [
                r"escape\s*\(", r"sanitize\s*\(", r"sanitise\s*\(",
                r"htmlspecialchars", r"htmlentities", r"parameteriz",
                r"prepared_statement", r"bindParam", r"bindValue",
            ]
            has_sanitiser = any(re.search(p, code, re.IGNORECASE) for p in sanitisers)
            confidence = 0.85 if not has_sanitiser else 0.3

            return {
                "tainted": True,
                "confidence": confidence,
                "reason": f"User input flows to {vuln_type} sink" + (" (sanitiser detected)" if has_sanitiser else ""),
                "evidence": code[:200],
            }

        return {"tainted": False, "confidence": 0.0, "reason": "No taint flow detected"}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_context(text: str, indicator: str, context: int = 100) -> str:
        idx = text.lower().find(indicator.lower())
        if idx == -1:
            return text[:200]
        start = max(0, idx - context)
        end = min(len(text), idx + len(indicator) + context)
        return text[start:end]
