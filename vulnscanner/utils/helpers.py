"""
Miscellaneous helper utilities.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from pathlib import Path


LANGUAGE_MAP: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".php": "php",
    ".rb": "ruby",
    ".go": "go",
    ".cs": "csharp",
    ".cpp": "cpp",
    ".c": "c",
    ".html": "html",
    ".xml": "xml",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".sh": "bash",
    ".env": "dotenv",
    ".tf": "terraform",
}

SCANNABLE_EXTENSIONS = set(LANGUAGE_MAP.keys())


def detect_language(path: Path) -> str:
    return LANGUAGE_MAP.get(path.suffix.lower(), "unknown")


def generate_finding_id(counter: int) -> str:
    return f"VULN-{counter:04d}"


def generate_scan_id() -> str:
    return str(uuid.uuid4())[:8].upper()


def file_hash(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()[:12]


def truncate(text: str, max_len: int = 300) -> str:
    return text if len(text) <= max_len else text[:max_len] + "…"


def is_test_file(path: Path) -> bool:
    """Heuristic: skip obvious test/fixture files to reduce noise."""
    name = path.name.lower()
    parts = {p.lower() for p in path.parts}
    return (
        name.startswith("test_")
        or name.endswith("_test.py")
        or "tests" in parts
        or "fixtures" in parts
        or "__pycache__" in parts
    )


def collect_source_files(root: Path, skip_tests: bool = False) -> list[Path]:
    """Recursively collect all scannable source files under *root*."""
    files: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in SCANNABLE_EXTENSIONS:
            continue
        if skip_tests and is_test_file(p):
            continue
        # skip hidden dirs, node_modules, venv, etc.
        skip_dirs = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}
        if any(part in skip_dirs for part in p.parts):
            continue
        files.append(p)
    return sorted(files)


def cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return "INFO"
