"""
URL-based web application scanner.

Crawls a target URL, discovers parameters, and runs safe simulation probes.
Only scans targets you are authorised to test.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import httpx
from bs4 import BeautifulSoup

from vulnscanner.utils.logging import get_logger
from vulnscanner.utils.models import (
    CodeSnippet, DetectionMethod, Finding, OWASPCategory,
    RemediationGuide, Severity, SimulationResult,
)
from vulnscanner.utils.helpers import generate_finding_id
from vulnscanner.simulation.simulator import SafeSimulator

logger = get_logger(__name__)

_VULN_TYPE_MAP = {
    "sqli": (OWASPCategory.A03_INJECTION, Severity.CRITICAL, 9.1, "CWE-89"),
    "xss": (OWASPCategory.A03_INJECTION, Severity.HIGH, 7.4, "CWE-79"),
    "ssrf": (OWASPCategory.A10_SSRF, Severity.HIGH, 8.6, "CWE-918"),
    "path_traversal": (OWASPCategory.A01_BROKEN_ACCESS_CONTROL, Severity.HIGH, 7.5, "CWE-22"),
    "cmdi": (OWASPCategory.A03_INJECTION, Severity.CRITICAL, 9.8, "CWE-78"),
}


class URLScanner:
    """Crawls a web app and runs safe probe simulations on discovered endpoints."""

    def __init__(self, max_pages: int = 20, max_params_per_page: int = 5) -> None:
        self.max_pages = max_pages
        self.max_params_per_page = max_params_per_page
        self._visited: set[str] = set()
        self._client = httpx.Client(
            timeout=10.0,
            follow_redirects=True,
            verify=True,
            headers={"User-Agent": "VulnScanner-AI/1.0 (Authorised Security Test)"},
        )

    def close(self) -> None:
        self._client.close()

    def scan(self, base_url: str) -> list[Finding]:
        """Crawl *base_url* and return all findings."""
        findings: list[Finding] = []
        pages = self._crawl(base_url)
        logger.info(f"Discovered {len(pages)} pages to probe")

        counter = 1
        with SafeSimulator() as sim:
            for page_url, params in pages:
                for param in params[:self.max_params_per_page]:
                    for vuln_type in ["sqli", "xss", "ssrf", "path_traversal", "cmdi"]:
                        result = sim.simulate_url(page_url, param, vuln_type)
                        if result:
                            finding = self._build_finding(
                                page_url, param, vuln_type, result,
                                generate_finding_id(counter)
                            )
                            findings.append(finding)
                            counter += 1
                            logger.info(f"[{vuln_type.upper()}] Potential finding at {page_url}?{param}=...")

        return findings

    # ------------------------------------------------------------------
    # Crawler
    # ------------------------------------------------------------------

    def _crawl(self, start_url: str) -> list[tuple[str, list[str]]]:
        """BFS crawl returning (url, [param_names]) pairs."""
        base = urlparse(start_url)
        queue = [start_url]
        results: list[tuple[str, list[str]]] = []

        while queue and len(self._visited) < self.max_pages:
            url = queue.pop(0)
            if url in self._visited:
                continue
            self._visited.add(url)

            try:
                resp = self._client.get(url)
                if resp.status_code != 200:
                    continue

                # Extract GET params from current URL
                params = list(parse_qs(urlparse(url).query).keys())
                if params:
                    results.append((url.split("?")[0], params))

                # Discover links
                soup = BeautifulSoup(resp.text, "html.parser")
                for tag in soup.find_all(["a", "form"]):
                    href = tag.get("href") or tag.get("action", "")
                    if not href:
                        continue
                    full_url = urljoin(url, href)
                    parsed = urlparse(full_url)
                    # Stay on same domain
                    if parsed.netloc != base.netloc:
                        continue
                    if full_url not in self._visited:
                        queue.append(full_url)

                # Extract form inputs
                for form in soup.find_all("form"):
                    action = form.get("action", url)
                    full_action = urljoin(url, action)
                    input_names = [
                        inp.get("name", "")
                        for inp in form.find_all("input")
                        if inp.get("name")
                    ]
                    if input_names:
                        results.append((full_action, input_names))

            except Exception as exc:
                logger.debug(f"Crawl error at {url}: {exc}")

        return results

    # ------------------------------------------------------------------
    # Finding builder
    # ------------------------------------------------------------------

    def _build_finding(
        self,
        url: str,
        param: str,
        vuln_type: str,
        sim_result: SimulationResult,
        finding_id: str,
    ) -> Finding:
        owasp_cat, severity, cvss, cwe = _VULN_TYPE_MAP.get(
            vuln_type, (OWASPCategory.A03_INJECTION, Severity.MEDIUM, 5.0, None)
        )

        title_map = {
            "sqli": "SQL Injection (confirmed via probe)",
            "xss": "Cross-Site Scripting — reflected (confirmed via probe)",
            "ssrf": "Server-Side Request Forgery (confirmed via probe)",
            "path_traversal": "Path Traversal (confirmed via probe)",
            "cmdi": "OS Command Injection (confirmed via probe)",
        }

        return Finding(
            id=finding_id,
            title=title_map.get(vuln_type, f"{vuln_type.upper()} vulnerability"),
            owasp_category=owasp_cat,
            severity=severity,
            cvss_score=cvss,
            cwe_id=cwe,
            description=(
                f"Safe probe payload '{sim_result.payload_used}' sent to parameter "
                f"'{param}' at {url} triggered risk indicator: '{sim_result.risk_indicator}'."
            ),
            detection_method=DetectionMethod.SIMULATION,
            snippet=CodeSnippet(
                file=url,
                line_start=0,
                line_end=0,
                content=sim_result.response_snippet or "",
                language="http",
            ),
            simulation=sim_result,
            remediation=RemediationGuide(
                summary=f"Sanitise and validate the '{param}' parameter.",
                steps=[
                    "Use parameterised queries / safe APIs.",
                    "Validate input against a strict allowlist.",
                    "Apply output encoding appropriate to the context.",
                ],
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
            ),
            tags=[vuln_type, "url-scan", "simulation-confirmed"],
        )
