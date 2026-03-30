"""
Feature extraction for ML vulnerability classification.

Extracts a fixed-length numeric feature vector from a code snippet using:
  - Token-level statistics
  - Keyword presence flags (security-sensitive APIs)
  - Structural heuristics (string concatenation, user input proximity)
  - N-gram character features (via sklearn's HashingVectorizer)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import numpy as np

# Security-sensitive keyword groups
_SINK_KEYWORDS = [
    # SQL
    "execute", "executemany", "raw", "cursor", "query",
    # OS
    "system", "popen", "subprocess", "exec", "eval",
    # File
    "open", "read", "write", "send_file", "readfile",
    # Network
    "requests.get", "requests.post", "urlopen", "fetch", "axios",
    # Crypto
    "md5", "sha1", "des", "rc4", "ecb",
    # Auth
    "jwt", "token", "password", "secret", "api_key",
    # Template
    "render_template_string", "innerHTML", "dangerouslySetInnerHTML",
]

_SOURCE_KEYWORDS = [
    "request.args", "request.form", "request.json", "request.data",
    "req.query", "req.body", "req.params",
    "getParameter", "getQueryString",
    "$_GET", "$_POST", "$_REQUEST", "$_COOKIE",
    "user_input", "user_data", "userinput",
]

_CONCAT_PATTERNS = [
    r'"\s*\+\s*\w',   # "string" + var
    r"'\s*\+\s*\w",
    r'f".*\{',        # f-string
    r"f'.*\{",
    r'`.*\$\{',       # JS template literal
    r'%s.*%\s*\(',    # printf-style
]

_DANGEROUS_FUNCS = [
    "eval", "exec", "compile", "os.system", "subprocess.call",
    "subprocess.run", "shell_exec", "passthru", "system",
]


@dataclass
class FeatureVector:
    """Named feature vector for a code snippet."""

    # Raw counts
    line_count: int = 0
    token_count: int = 0
    string_literal_count: int = 0
    comment_count: int = 0

    # Sink/source proximity
    sink_keyword_count: int = 0
    source_keyword_count: int = 0
    concat_pattern_count: int = 0
    dangerous_func_count: int = 0

    # Structural flags (0/1)
    has_user_input: int = 0
    has_sql_keyword: int = 0
    has_shell_keyword: int = 0
    has_crypto_keyword: int = 0
    has_auth_keyword: int = 0
    has_file_keyword: int = 0
    has_network_keyword: int = 0
    has_hardcoded_string: int = 0

    # Ratios
    avg_line_length: float = 0.0
    string_density: float = 0.0   # string literals / tokens

    def to_array(self) -> np.ndarray:
        return np.array([
            self.line_count, self.token_count, self.string_literal_count,
            self.comment_count, self.sink_keyword_count, self.source_keyword_count,
            self.concat_pattern_count, self.dangerous_func_count,
            self.has_user_input, self.has_sql_keyword, self.has_shell_keyword,
            self.has_crypto_keyword, self.has_auth_keyword, self.has_file_keyword,
            self.has_network_keyword, self.has_hardcoded_string,
            self.avg_line_length, self.string_density,
        ], dtype=np.float32)

    @classmethod
    def feature_names(cls) -> list[str]:
        return [f.name for f in cls.__dataclass_fields__.values()]  # type: ignore[attr-defined]


class FeatureExtractor:
    """Converts raw code snippets into numeric feature vectors."""

    def extract(self, code: str, language: str = "python") -> FeatureVector:
        fv = FeatureVector()
        lines = code.splitlines()
        fv.line_count = len(lines)
        fv.avg_line_length = sum(len(l) for l in lines) / max(len(lines), 1)

        tokens = re.findall(r"\w+", code)
        fv.token_count = len(tokens)

        # String literals
        strings = re.findall(r'["\'][^"\']{3,}["\']', code)
        fv.string_literal_count = len(strings)
        fv.string_density = len(strings) / max(len(tokens), 1)

        # Comments
        fv.comment_count = len(re.findall(r"(#.*|//.*|/\*.*?\*/)", code, re.DOTALL))

        code_lower = code.lower()

        # Sink keywords
        fv.sink_keyword_count = sum(1 for kw in _SINK_KEYWORDS if kw in code_lower)

        # Source keywords
        fv.source_keyword_count = sum(1 for kw in _SOURCE_KEYWORDS if kw.lower() in code_lower)
        fv.has_user_input = int(fv.source_keyword_count > 0)

        # Concatenation patterns
        fv.concat_pattern_count = sum(
            1 for p in _CONCAT_PATTERNS if re.search(p, code)
        )

        # Dangerous functions
        fv.dangerous_func_count = sum(1 for f in _DANGEROUS_FUNCS if f in code_lower)

        # Category flags
        fv.has_sql_keyword = int(
            any(kw in code_lower for kw in ["select", "insert", "update", "delete", "execute", "cursor"])
        )
        fv.has_shell_keyword = int(
            any(kw in code_lower for kw in ["system", "popen", "subprocess", "shell", "exec"])
        )
        fv.has_crypto_keyword = int(
            any(kw in code_lower for kw in ["md5", "sha1", "des", "rc4", "encrypt", "decrypt", "hash"])
        )
        fv.has_auth_keyword = int(
            any(kw in code_lower for kw in ["password", "token", "jwt", "secret", "auth", "login"])
        )
        fv.has_file_keyword = int(
            any(kw in code_lower for kw in ["open(", "readfile", "fopen", "file_get_contents"])
        )
        fv.has_network_keyword = int(
            any(kw in code_lower for kw in ["requests", "urllib", "fetch", "axios", "curl", "http"])
        )
        fv.has_hardcoded_string = int(
            bool(re.search(r'(password|secret|key|token)\s*=\s*["\'][^"\']{4,}["\']', code, re.IGNORECASE))
        )

        return fv

    def extract_batch(self, snippets: list[tuple[str, str]]) -> np.ndarray:
        """Extract features for a list of (code, language) tuples."""
        return np.vstack([self.extract(code, lang).to_array() for code, lang in snippets])
