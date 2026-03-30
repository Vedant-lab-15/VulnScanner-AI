<div align="center">

# 🛡️ VulnScanner AI

### ML-powered OWASP Top 10 (2025) Vulnerability Scanner

*Hybrid static analysis · XGBoost classification · Safe exploit simulation · Beautiful dark-theme reports*

[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010%202025-e44d26?style=flat-square)](https://owasp.org/Top10/)
[![Tests](https://img.shields.io/badge/Tests-103%20passing-2ed573?style=flat-square)](#testing)
[![SARIF](https://img.shields.io/badge/Export-SARIF%202.1.0-58a6ff?style=flat-square)](https://sarifweb.azurewebsites.net/)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ed?style=flat-square&logo=docker&logoColor=white)](Dockerfile)

</div>

---

## What is VulnScanner AI?

VulnScanner AI is a **production-grade, open-source security scanner** that detects OWASP Top 10 vulnerabilities using a three-layer hybrid approach:

```
Source Code / URL / GitHub Repo
         │
   ┌─────▼──────────────────────────────────────┐
   │  Layer 1 — Pattern Engine                  │
   │  29 YAML rules · regex · multi-language    │
   └─────┬──────────────────────────────────────┘
         │
   ┌─────▼──────────────────────────────────────┐
   │  Layer 2 — ML Classifier                   │
   │  XGBoost · 18 security features · SHAP     │
   └─────┬──────────────────────────────────────┘
         │
   ┌─────▼──────────────────────────────────────┐
   │  Layer 3 — Safe Simulation                 │
   │  Taint analysis · benign probe payloads    │
   └─────┬──────────────────────────────────────┘
         │
   ┌─────▼──────────────────────────────────────┐
   │  Reports: HTML · SARIF 2.1.0 · JSON · PDF  │
   └────────────────────────────────────────────┘
```

It goes far beyond grep-based tools — every finding includes ML confidence scores, SHAP feature explanations, taint-flow confirmation, CVSS-inspired risk scoring, and actionable remediation with code fix examples.

---

## Features at a Glance

| Capability | Details |
|---|---|
| **Scan targets** | Local directory, live URL (web app), GitHub repository |
| **Languages** | Python, JavaScript, TypeScript, Java, PHP, Ruby, Go |
| **OWASP 2025** | All 10 categories — A01 through A10 |
| **Detection** | Pattern matching + XGBoost ML + taint simulation + SCA |
| **ML model** | XGBoost with 18 hand-crafted security features + SHAP explainability |
| **Dependency scan** | requirements.txt, package.json, pom.xml, build.gradle, Pipfile |
| **Reports** | Self-contained HTML (dark theme + Plotly), SARIF 2.1.0, JSON, PDF |
| **CI/CD** | Exit codes 0/1/2 · SARIF uploads to GitHub Security tab |
| **Tests** | 103 pytest tests, 100% passing |
| **Container** | Multi-stage Dockerfile + docker-compose |

---

## Quick Start

### One-click setup (recommended for new users)

```bash
git clone https://github.com/your-username/vulnscanner-ai
cd vulnscanner-ai
chmod +x run.sh
./run.sh          # opens interactive menu
```

The script handles everything: creates a virtual environment, installs all dependencies, trains the ML model, and launches the scanner. No Python knowledge required.

```
  ╔══════════════════════════════════════════════════════╗
  ║          🛡️  VulnScanner AI  v1.0.0                  ║
  ║   ML-powered OWASP Top 10 Vulnerability Scanner      ║
  ╚══════════════════════════════════════════════════════╝

  What would you like to do?

  1) Setup          — Install dependencies & train ML model
  2) Demo scan      — Scan built-in vulnerable samples
  3) Scan directory — Scan your own source code
  4) Scan URL       — Scan a live web application
  5) Scan GitHub    — Clone and scan a GitHub repository
  6) Train model    — Retrain the ML classifier
  7) Run tests      — Run the full pytest suite (103 tests)
  8) Open notebook  — Launch Jupyter training notebook
  9) Build Docker   — Build the Docker image
```

Or use direct commands:

```bash
./run.sh setup              # install everything first
./run.sh demo               # scan built-in vulnerable samples → opens report
./run.sh scan ./my-project  # scan your own code
./run.sh train              # retrain the ML model
./run.sh test               # run 103 tests
```

### Manual install

```bash
git clone https://github.com/your-username/vulnscanner-ai
cd vulnscanner-ai
pip install -e .
```

### Scan a directory

```bash
vulnscanner scan ./my-project
# Generates: vulnscanner_report.html
```

### Full scan with all outputs

```bash
vulnscanner scan ./my-project \
  --output reports/scan \
  --sarif \
  --json \
  --pdf
```

### Scan a web application

```bash
# Only scan systems you are authorised to test
vulnscanner url https://your-app.example.com --max-pages 50
```

### Scan a GitHub repository

```bash
vulnscanner github https://github.com/example/vulnerable-app --sarif
```

### Train the ML model

```bash
# Uses built-in synthetic dataset (42 samples, CV AUC ~0.73)
vulnscanner train

# Train on a larger custom dataset for better accuracy
vulnscanner train --data datasets/my_dataset.csv
```

### Docker

```bash
# Build image
docker build -t vulnscanner-ai .

# Scan a local directory
docker run --rm \
  -v $(pwd)/my-project:/scan-target:ro \
  -v $(pwd)/reports:/reports \
  vulnscanner-ai scan /scan-target --output /reports/report --sarif --json

# Or with docker-compose
cp -r my-project scan-target/
docker-compose up vulnscanner
```

---

## run.sh — One-Click Launcher

`run.sh` is a zero-friction entry point for anyone who just cloned the repo. It handles Python detection, virtual environment creation, dependency installation, model training, and report generation — all automatically.

```bash
chmod +x run.sh
./run.sh          # interactive numbered menu
```

**Direct commands (no menu):**

| Command | What it does |
|---|---|
| `./run.sh setup` | Creates `.venv`, installs all deps, trains ML model |
| `./run.sh demo` | Scans built-in vulnerable samples, opens HTML report |
| `./run.sh scan ./my-project` | Scans any local directory |
| `./run.sh url https://target.com` | Web app scan (with ethical consent prompt) |
| `./run.sh github https://github.com/org/repo` | Clones + scans a GitHub repo |
| `./run.sh train` | Retrains the XGBoost classifier |
| `./run.sh test` | Runs all 103 pytest tests with coverage |
| `./run.sh notebook` | Opens the Jupyter training notebook |
| `./run.sh docker` | Builds the Docker image |

**What it handles automatically:**
- Detects Python 3.10+ across `python3.11`, `python3.12`, `python3`, etc.
- Creates and activates `.venv` (skips if already inside a venv)
- Installs `requirements.txt` and the package in editable mode
- Trains the ML model on first run if `models/vuln_classifier.joblib` is missing
- Opens the generated HTML report in your default browser
- Shows an ethical consent prompt before URL/web scanning

**Requirements:** Python 3.10+, bash (Linux / macOS / WSL). No other tools needed.

---

## CLI Reference

```
Commands:
  scan PATH     Scan a local source code directory
  url URL       Scan a live web application (safe probes only)
  github URL    Clone and scan a GitHub repository
  train         Train the ML vulnerability classifier
  report JSON   Re-render reports from a saved JSON result

vulnscanner scan PATH [OPTIONS]
  -o, --output TEXT       Output base name  [default: vulnscanner_report]
  --no-ml                 Disable ML classification
  --no-sim                Disable taint simulation
  --no-sca                Disable dependency scanning
  --sarif                 Export SARIF 2.1.0 (for GitHub Security)
  --pdf                   Export PDF report (requires weasyprint)
  --json                  Export raw JSON result
  --log-file PATH         Mirror logs to a file
  -v, --verbose           Debug-level output

vulnscanner url URL [OPTIONS]
  -o, --output TEXT
  --max-pages INT         Max pages to crawl  [default: 20]
  --sarif / --json

vulnscanner github REPO_URL [OPTIONS]
  -o, --output TEXT
  --no-ml / --sarif / --json

vulnscanner train [OPTIONS]
  -d, --data PATH         Training CSV (columns: code_snippet, language, label)
  --output-dir PATH       Where to save model artifacts
```

**Exit codes for CI/CD pipelines:**

| Code | Meaning |
|------|---------|
| `0` | Clean — no findings, or only medium/low |
| `1` | High severity findings present |
| `2` | Critical severity findings present |

---

## OWASP Top 10 (2025) Coverage

| ID | Category | Pattern Rules | ML | Simulation | SCA |
|----|----------|:---:|:---:|:---:|:---:|
| **A01** | Broken Access Control | ✅ 3 rules | ✅ | ✅ | — |
| **A02** | Cryptographic Failures | ✅ 4 rules | ✅ | — | — |
| **A03** | Injection (SQLi · XSS · CMDi · LDAP) | ✅ 4 rules | ✅ | ✅ | — |
| **A04** | Insecure Design | ✅ 4 rules | ✅ | — | — |
| **A05** | Security Misconfiguration | ✅ 3 rules | ✅ | — | — |
| **A06** | Vulnerable & Outdated Components | — | — | — | ✅ |
| **A07** | Auth & Session Failures | ✅ 3 rules | ✅ | — | — |
| **A08** | Software & Data Integrity Failures | ✅ 5 rules | ✅ | — | — |
| **A09** | Security Logging & Monitoring | ✅ 2 rules | ✅ | — | — |
| **A10** | Server-Side Request Forgery | ✅ 1 rule | ✅ | ✅ | — |

**29 detection rules** across 9 YAML files · **7 languages** · **SCA** via OSV.dev API + local CVE database

---

## How It Works

### Layer 1 — Pattern Engine

YAML-defined rules with per-language regex patterns. Each rule maps to an OWASP category, CWE ID, CVSS score, and remediation guide. The engine scans all source files, extracts matching code snippets with line numbers, and produces structured `Finding` objects.

```yaml
# Example rule from rules/injection.yaml
- id: INJ-001
  title: "SQL Injection via string concatenation"
  owasp: A03
  cwe: CWE-89
  severity: CRITICAL
  cvss: 9.1
  patterns:
    python:
      - "cursor\\.execute\\s*\\(\\s*f[\"']"
      - "cursor\\.execute\\s*\\(\\s*\"[^\"]*\"\\s*\\+\\s*\\w"
```

### Layer 2 — ML Classifier

An XGBoost model trained on 18 hand-crafted security features extracted from code snippets:

| Feature Group | Features |
|---|---|
| Token stats | `line_count`, `token_count`, `string_literal_count`, `string_density` |
| Sink keywords | `sink_keyword_count`, `dangerous_func_count` |
| Source keywords | `source_keyword_count`, `has_user_input` |
| Structural | `concat_pattern_count`, `has_hardcoded_string` |
| Category flags | `has_sql_keyword`, `has_shell_keyword`, `has_crypto_keyword`, `has_auth_keyword`, `has_file_keyword`, `has_network_keyword` |

Every prediction includes **SHAP feature importance values** — you can see exactly which code characteristics drove the classification.

```
Finding: SQL Injection via string concatenation
ML Confidence: 85%
Top SHAP features:
  has_user_input:      +0.312
  concat_pattern_count: +0.241
  sink_keyword_count:  +0.198
  has_sql_keyword:     +0.156
```

### Layer 3 — Safe Simulation

**Code mode (static taint analysis):** Traces data flow from user-controlled sources (`request.args`, `$_GET`, `req.body`) to dangerous sinks (`execute()`, `os.system()`, `requests.get()`). Detects source→sink paths and checks for sanitisation.

**URL mode (safe probes):** Sends benign, non-destructive payloads to discovered parameters and analyses responses for risk indicators — no actual exploitation.

```python
# Safe probe examples (non-destructive)
SQL:  "'"                          → looks for "syntax error", "ORA-", "SQLSTATE"
XSS:  "<vulnscanner-xss-probe>"   → looks for reflection in response
SSRF: "http://127.0.0.1:80/"      → looks for connection indicators
CMDi: ";echo VULNSCANNER_PROBE"   → looks for echo output in response
```

### Dependency Scanning (SCA)

Parses manifest files and checks against:
- **Local CVE database** — curated entries for Django, Flask, Requests, Lodash, Log4j, Spring, and more
- **OSV.dev API** — real-time lookup against the Open Source Vulnerabilities database

---

## Report

The HTML report is a **single self-contained file** (~190KB) with no external dependencies at render time:

- **Overview tab** — risk score gauge, severity breakdown, scan metadata
- **Findings tab** — collapsible cards sorted by CVSS, with severity filter buttons
  - Each card shows: location, description, code snippet, ML confidence bar + SHAP features, simulation result, remediation steps + code fix, references
- **Dependencies tab** — SCA findings table with CVE IDs and fix versions
- **Charts tab** — Plotly interactive charts (OWASP bar, severity pie, detection method donut, risk gauge)
- **OWASP Coverage tab** — per-category finding counts and grouped finding list

**SARIF export** is compatible with GitHub Advanced Security — upload it as a code scanning result to see findings directly in the Security tab of your repository.

---

## ML Model Performance

Trained on synthetic dataset (42 samples). For production use, retrain on [Big-Vul](https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset) or [Devign](https://sites.google.com/view/devign).

| Metric | Synthetic Dataset |
|--------|:-----------------:|
| CV ROC-AUC (5-fold) | 0.730 ± 0.069 |
| Train ROC-AUC | 0.989 |
| Features | 18 |
| Model | XGBoost |
| Explainability | SHAP TreeExplainer |

See [`notebooks/model_training.ipynb`](notebooks/model_training.ipynb) for the full training walkthrough with visualised CV results, ROC/PR curves, confusion matrix, and SHAP analysis.

---

## Comparison

| Feature | VulnScanner AI | Bandit | Semgrep (free) | Snyk (free) |
|---------|:-:|:-:|:-:|:-:|
| OWASP Top 10 (all 10) | ✅ | ❌ | Partial | Partial |
| ML classification | ✅ | ❌ | ❌ | ❌ |
| SHAP explainability | ✅ | ❌ | ❌ | ❌ |
| Safe exploit simulation | ✅ | ❌ | ❌ | ❌ |
| Dependency scanning | ✅ | ❌ | ✅ (paid) | ✅ |
| Multi-language (7+) | ✅ | Python only | ✅ | ✅ |
| SARIF export | ✅ | ✅ | ✅ | ✅ |
| Dark HTML report | ✅ | ❌ | ❌ | ❌ |
| GitHub repo scanning | ✅ | ❌ | ❌ | ❌ |
| URL / web scanning | ✅ | ❌ | ❌ | ❌ |
| Trainable model | ✅ | ❌ | ❌ | ❌ |
| 100% open source | ✅ | ✅ | Partial | ❌ |

---

## Project Structure

```
vulnscanner-ai/
│
├── vulnscanner/                    # Main package
│   ├── cli.py                      # Typer CLI (scan, url, github, train, report)
│   ├── scanner/
│   │   ├── core.py                 # Orchestrator — coordinates all layers
│   │   ├── sca.py                  # Dependency scanner (OSV API + local DB)
│   │   └── url_scanner.py          # Web crawler + safe probe engine
│   ├── patterns/
│   │   └── engine.py               # YAML rule loader + regex scanner
│   ├── ml/
│   │   ├── features.py             # 18-feature security extractor
│   │   ├── classifier.py           # XGBoost wrapper + SHAP explainer
│   │   └── trainer.py              # Full training pipeline
│   ├── simulation/
│   │   ├── payloads.py             # Safe probe payload library
│   │   └── simulator.py            # Taint analysis + URL probing
│   ├── report/
│   │   ├── generator.py            # HTML / SARIF / JSON / PDF output
│   │   ├── charts.py               # Plotly chart builders
│   │   └── sarif.py                # SARIF 2.1.0 serialiser
│   └── utils/
│       ├── models.py               # Pydantic data models (Finding, ScanResult…)
│       ├── helpers.py              # File utilities, language detection
│       └── logging.py              # Rich logging setup
│
├── rules/                          # YAML detection rules (29 rules, 9 files)
│   ├── injection.yaml              # A03: SQLi, XSS, CMDi, LDAP
│   ├── crypto.yaml                 # A02: Weak hash, hardcoded secrets, bad TLS
│   ├── access_control.yaml         # A01: IDOR, path traversal, missing auth
│   ├── auth.yaml                   # A07: JWT, sessions, weak passwords
│   ├── misconfiguration.yaml       # A05: Debug mode, CORS, admin exposure
│   ├── insecure_design.yaml        # A04: Mass assignment, file upload, rate limiting
│   ├── integrity_failures.yaml     # A08: pickle RCE, Java deserialize, eval, XStream
│   ├── ssrf.yaml                   # A10: SSRF
│   └── logging.yaml                # A09: Sensitive data in logs, silent exceptions
│
├── templates/
│   ├── report.html.j2              # Dark-theme Jinja2 report template
│   └── plotly.min.js               # Plotly bundle (auto-downloaded, offline-safe)
│
├── models/                         # Trained model artifacts (git-ignored by default)
│   ├── vuln_classifier.joblib
│   ├── model_meta.json
│   └── training_metrics.json
│
├── datasets/
│   ├── generate_dataset.py         # Synthetic + Big-Vul dataset generator
│   └── synthetic_training.csv      # Built-in training data (42 samples)
│
├── notebooks/
│   └── model_training.ipynb        # Full ML training walkthrough
│
├── samples/                        # Intentionally vulnerable test code
│   ├── python/vulnerable_app.py
│   ├── javascript/vulnerable_app.js
│   ├── php/vulnerable_app.php
│   └── java/VulnerableApp.java
│
├── tests/                          # pytest suite (103 tests)
│   ├── conftest.py
│   ├── test_pattern_engine.py      # 19 tests
│   ├── test_ml.py                  # 28 tests
│   ├── test_scanner.py             # 24 tests
│   └── test_reports.py             # 32 tests
│
├── Dockerfile                      # Multi-stage build
├── docker-compose.yml
├── run.sh                          # One-click launcher (setup, demo, scan, train, test)
├── pyproject.toml
├── requirements.txt
├── architecture.md                 # Full system architecture
└── .env.example
```

---

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v --cov=vulnscanner --cov-report=term-missing

# Lint + format
ruff check vulnscanner/
black vulnscanner/

# Type check
mypy vulnscanner/

# Generate training dataset
python datasets/generate_dataset.py --synthetic

# Scan the project itself
vulnscanner scan . --no-sca --output self_scan

# Open training notebook
jupyter notebook notebooks/model_training.ipynb
```

### Adding a New Detection Rule

1. Open or create a YAML file in `rules/`
2. Add a rule following the existing schema:

```yaml
- id: MY-001
  title: "Descriptive vulnerability title"
  owasp: A03          # A01–A10
  cwe: CWE-89
  severity: HIGH      # CRITICAL / HIGH / MEDIUM / LOW / INFO
  cvss: 7.5
  languages: [python, javascript]
  patterns:
    python:
      - "your_regex_pattern_here"
  description: "What the vulnerability is and why it's dangerous."
  remediation:
    summary: "One-line fix summary."
    steps:
      - "Step 1"
      - "Step 2"
    code_fix: |
      # BEFORE
      ...
      # AFTER
      ...
    references:
      - "https://owasp.org/..."
```

3. Add a test in `tests/test_pattern_engine.py`
4. Run `pytest tests/test_pattern_engine.py -v`

---

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request]

jobs:
  vulnscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.11' }
      - run: pip install vulnscanner-ai
      - run: vulnscanner scan . --sarif --output security-report
        continue-on-error: true   # don't block on findings
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: security-report.sarif.json
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: vulnscanner
        name: VulnScanner AI
        entry: vulnscanner scan
        args: [--no-sca, --no-sim]
        language: system
        pass_filenames: false
```

---

## Ethical Use

> ⚠️ **This tool is for authorised security testing only.**
>
> Only scan systems you **own** or have **explicit written permission** to test.
> Unauthorised scanning may violate computer crime laws in your jurisdiction
> (CFAA, Computer Misuse Act, etc.).
>
> The "exploit simulation" feature sends only benign, non-destructive probe
> payloads. No actual exploitation or data exfiltration occurs.
>
> The authors and contributors accept **no liability** for misuse.

---

## Contributing

Contributions are welcome — especially:
- New detection rules for underrepresented vulnerability classes
- Additional language support (Ruby, Go, C/C++)
- Larger training datasets (Big-Vul, Devign integration)
- False positive reduction improvements

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/new-rule-xxxx`
3. Add your rule + test
4. Ensure `pytest tests/ -v` passes
5. Submit a pull request

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">

Built for AppSec · DevSecOps · AI Security roles

*Star ⭐ the repo if you find it useful*

</div>
