"""
Software Composition Analysis (SCA) — A06:2025.

Scans dependency manifests (requirements.txt, package.json, pom.xml, etc.)
and checks versions against a local known-vulnerable database + OSV API.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import httpx
from packaging.version import Version, InvalidVersion

from vulnscanner.utils.logging import get_logger

logger = get_logger(__name__)

_OSV_API = "https://api.osv.dev/v1/query"
_REQUEST_TIMEOUT = 10.0

# Local fallback: well-known CVEs for common packages (version ranges)
_LOCAL_VULN_DB: dict[str, list[dict[str, Any]]] = {
    "django": [
        {"cve": "CVE-2023-36053", "fixed": "4.2.3", "severity": "HIGH", "desc": "ReDoS in EmailValidator"},
        {"cve": "CVE-2023-41164", "fixed": "4.2.5", "severity": "HIGH", "desc": "Potential DoS via large multipart"},
    ],
    "flask": [
        {"cve": "CVE-2023-30861", "fixed": "2.3.2", "severity": "HIGH", "desc": "Cookie header injection"},
    ],
    "requests": [
        {"cve": "CVE-2023-32681", "fixed": "2.31.0", "severity": "MEDIUM", "desc": "Proxy-Authorization header leak"},
    ],
    "pillow": [
        {"cve": "CVE-2023-44271", "fixed": "10.0.1", "severity": "HIGH", "desc": "Uncontrolled resource consumption"},
    ],
    "cryptography": [
        {"cve": "CVE-2023-49083", "fixed": "41.0.6", "severity": "MEDIUM", "desc": "NULL pointer dereference"},
    ],
    "lodash": [
        {"cve": "CVE-2021-23337", "fixed": "4.17.21", "severity": "HIGH", "desc": "Command injection via template"},
        {"cve": "CVE-2020-8203", "fixed": "4.17.19", "severity": "HIGH", "desc": "Prototype pollution"},
    ],
    "express": [
        {"cve": "CVE-2022-24999", "fixed": "4.18.2", "severity": "HIGH", "desc": "Open redirect"},
    ],
    "log4j": [
        {"cve": "CVE-2021-44228", "fixed": "2.17.1", "severity": "CRITICAL", "desc": "Log4Shell RCE"},
    ],
    "spring-core": [
        {"cve": "CVE-2022-22965", "fixed": "5.3.18", "severity": "CRITICAL", "desc": "Spring4Shell RCE"},
    ],
}


class SCAScanner:
    """Scans dependency files for known vulnerable packages."""

    def __init__(self, use_osv_api: bool = True) -> None:
        self.use_osv_api = use_osv_api

    def scan_directory(self, root: Path) -> list[dict[str, Any]]:
        """Find and scan all dependency manifests under *root*."""
        findings: list[dict[str, Any]] = []

        manifest_handlers = {
            "requirements.txt": self._parse_requirements,
            "requirements-dev.txt": self._parse_requirements,
            "requirements-prod.txt": self._parse_requirements,
            "Pipfile": self._parse_pipfile,
            "package.json": self._parse_package_json,
            "pom.xml": self._parse_pom_xml,
            "build.gradle": self._parse_gradle,
        }

        for filename, handler in manifest_handlers.items():
            for manifest in root.rglob(filename):
                # Skip node_modules, venv, etc.
                if any(p in manifest.parts for p in ["node_modules", "venv", ".venv", "dist"]):
                    continue
                try:
                    deps = handler(manifest)
                    for pkg, version in deps:
                        vulns = self._check_package(pkg, version)
                        for vuln in vulns:
                            findings.append({
                                "file": str(manifest),
                                "package": pkg,
                                "version": version,
                                "cve": vuln.get("cve", "N/A"),
                                "severity": vuln.get("severity", "MEDIUM"),
                                "description": vuln.get("desc", ""),
                                "fixed_version": vuln.get("fixed", "unknown"),
                                "owasp": "A06:2025 – Vulnerable and Outdated Components",
                            })
                except Exception as exc:
                    logger.warning(f"SCA parse error for {manifest}: {exc}")

        return findings

    # ------------------------------------------------------------------
    # Manifest parsers
    # ------------------------------------------------------------------

    def _parse_requirements(self, path: Path) -> list[tuple[str, str]]:
        deps: list[tuple[str, str]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Handle: package==1.2.3, package>=1.2, package~=1.2
            m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*[=~><]{1,2}\s*([0-9][^\s;#]*)", line)
            if m:
                deps.append((m.group(1).lower(), m.group(2).strip()))
            else:
                # No version pinned
                pkg = re.match(r"^([A-Za-z0-9_\-\.]+)", line)
                if pkg:
                    deps.append((pkg.group(1).lower(), "0.0.0"))
        return deps

    def _parse_pipfile(self, path: Path) -> list[tuple[str, str]]:
        deps: list[tuple[str, str]] = []
        try:
            import toml
            data = toml.loads(path.read_text(encoding="utf-8"))
            for section in ("packages", "dev-packages"):
                for pkg, ver in data.get(section, {}).items():
                    version = ver if isinstance(ver, str) else "0.0.0"
                    version = version.lstrip("=~><").strip() or "0.0.0"
                    deps.append((pkg.lower(), version))
        except ImportError:
            logger.debug("toml not available for Pipfile parsing")
        return deps

    def _parse_package_json(self, path: Path) -> list[tuple[str, str]]:
        deps: list[tuple[str, str]] = []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for section in ("dependencies", "devDependencies"):
                for pkg, ver in data.get(section, {}).items():
                    version = re.sub(r"[^0-9.]", "", ver).strip(".") or "0.0.0"
                    deps.append((pkg.lower(), version))
        except json.JSONDecodeError:
            pass
        return deps

    def _parse_pom_xml(self, path: Path) -> list[tuple[str, str]]:
        deps: list[tuple[str, str]] = []
        content = path.read_text(encoding="utf-8")
        # Simple regex extraction (no full XML parse to avoid lxml dependency)
        blocks = re.findall(r"<dependency>(.*?)</dependency>", content, re.DOTALL)
        for block in blocks:
            artifact = re.search(r"<artifactId>(.*?)</artifactId>", block)
            version = re.search(r"<version>(.*?)</version>", block)
            if artifact:
                pkg = artifact.group(1).lower()
                ver = version.group(1) if version else "0.0.0"
                deps.append((pkg, ver))
        return deps

    def _parse_gradle(self, path: Path) -> list[tuple[str, str]]:
        deps: list[tuple[str, str]] = []
        content = path.read_text(encoding="utf-8")
        # Match: implementation 'group:artifact:version'
        for m in re.finditer(r"['\"][\w\.\-]+:([\w\.\-]+):([\d\.]+)['\"]", content):
            deps.append((m.group(1).lower(), m.group(2)))
        return deps

    # ------------------------------------------------------------------
    # Vulnerability lookup
    # ------------------------------------------------------------------

    def _check_package(self, package: str, version: str) -> list[dict[str, Any]]:
        """Check local DB first, then OSV API if enabled."""
        results = self._check_local(package, version)
        if not results and self.use_osv_api:
            results = self._check_osv(package, version)
        return results

    def _check_local(self, package: str, version: str) -> list[dict[str, Any]]:
        vulns = _LOCAL_VULN_DB.get(package.lower(), [])
        results = []
        for vuln in vulns:
            try:
                if Version(version) < Version(vuln["fixed"]):
                    results.append(vuln)
            except InvalidVersion:
                pass
        return results

    def _check_osv(self, package: str, version: str) -> list[dict[str, Any]]:
        """Query the OSV.dev API for known vulnerabilities."""
        try:
            payload = {"version": version, "package": {"name": package, "ecosystem": "PyPI"}}
            resp = httpx.post(_OSV_API, json=payload, timeout=_REQUEST_TIMEOUT)
            if resp.status_code == 200:
                data = resp.json()
                results = []
                for vuln in data.get("vulns", [])[:3]:  # limit to 3 per package
                    results.append({
                        "cve": vuln.get("id", "N/A"),
                        "severity": "HIGH",
                        "desc": vuln.get("summary", "See OSV for details"),
                        "fixed": "see advisory",
                    })
                return results
        except Exception as exc:
            logger.debug(f"OSV API error for {package}: {exc}")
        return []
