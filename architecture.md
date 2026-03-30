# VulnScanner AI — Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        VulnScanner AI v1.0                          │
│                   ML-powered OWASP Top 10 Scanner                   │
└─────────────────────────────────────────────────────────────────────┘

         ┌──────────┐    ┌──────────┐    ┌──────────────┐
         │  Local   │    │   URL    │    │   GitHub     │
         │  Code    │    │  Target  │    │   Repo       │
         └────┬─────┘    └────┬─────┘    └──────┬───────┘
              │               │                  │ git clone
              └───────────────┴──────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │   Scanner Core     │
                    │  (orchestrator)    │
                    └─────────┬──────────┘
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
   ┌──────▼──────┐   ┌────────▼───────┐   ┌──────▼──────┐
   │  Pattern    │   │  ML Classifier │   │    SCA      │
   │  Engine     │   │  (XGBoost)     │   │  Scanner    │
   │             │   │                │   │             │
   │ YAML rules  │   │ Feature        │   │ OSV API +   │
   │ Regex/AST   │   │ Extraction     │   │ Local DB    │
   └──────┬──────┘   └────────┬───────┘   └──────┬──────┘
          │                   │                   │
          │            ┌──────▼──────┐            │
          │            │    SHAP     │            │
          │            │ Explainer   │            │
          │            └──────┬──────┘            │
          │                   │                   │
          └───────────────────┼───────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │  Safe Simulation   │
                    │  Engine            │
                    │                   │
                    │ • Taint analysis   │
                    │ • Probe payloads   │
                    │ • Risk scoring     │
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────┐
                    │  Report Generator  │
                    │                   │
                    │ • HTML (dark UI)   │
                    │ • SARIF 2.1.0      │
                    │ • JSON             │
                    │ • PDF (optional)   │
                    └────────────────────┘
```

## Component Details

### 1. Pattern Engine (`vulnscanner/patterns/`)
- Loads YAML rule files from `rules/`
- Applies regex patterns per language
- Covers all OWASP Top 10 categories
- Returns structured `Finding` objects

### 2. ML Classifier (`vulnscanner/ml/`)
- **Feature Extraction**: 18 security-relevant features (token stats, sink/source keywords, taint indicators)
- **Model**: XGBoost (GradientBoosting fallback)
- **Explainability**: SHAP TreeExplainer for per-prediction feature importance
- **Training**: `vulnscanner train` — 5-fold CV, synthetic + public datasets

### 3. Safe Simulation Engine (`vulnscanner/simulation/`)
- **Code mode**: Static taint analysis (source → sink flow detection)
- **URL mode**: Benign probe payloads sent to discovered parameters
- All payloads are non-destructive and detectable-only
- Confirms pattern findings, boosts confidence scores

### 4. SCA Scanner (`vulnscanner/scanner/sca.py`)
- Parses: `requirements.txt`, `package.json`, `pom.xml`, `build.gradle`, `Pipfile`
- Checks against local CVE database + OSV.dev API
- Reports: package, version, CVE, severity, fix version

### 5. Report Generator (`vulnscanner/report/`)
- **HTML**: Self-contained dark-theme report with embedded Plotly charts
- **SARIF**: GitHub Advanced Security compatible (SARIF 2.1.0)
- **JSON**: Machine-readable full scan result
- **PDF**: WeasyPrint-based PDF export

## Data Flow

```
Source File
    │
    ├─► Pattern Engine ──► Finding (method=PATTERN)
    │                           │
    ├─► ML Classifier ──────────► MLPrediction (confidence, SHAP)
    │                           │
    └─► Taint Simulator ────────► SimulationResult (confirmed?)
                                │
                         ScanResult.findings[]
                                │
                         ReportGenerator
                                │
                    ┌───────────┼───────────┐
                    ▼           ▼           ▼
                 HTML         SARIF       JSON
```

## OWASP Top 10 (2025) Coverage Matrix

| ID  | Category                              | Pattern | ML | Simulation | SCA |
|-----|---------------------------------------|---------|----|------------|-----|
| A01 | Broken Access Control                 | ✅      | ✅ | ✅         | —   |
| A02 | Cryptographic Failures                | ✅      | ✅ | —          | —   |
| A03 | Injection (SQLi, XSS, CMDi, LDAP)    | ✅      | ✅ | ✅         | —   |
| A04 | Insecure Design                       | ✅      | ✅ | —          | —   |
| A05 | Security Misconfiguration             | ✅      | ✅ | —          | —   |
| A06 | Vulnerable & Outdated Components      | —       | —  | —          | ✅  |
| A07 | Auth & Session Failures               | ✅      | ✅ | —          | —   |
| A08 | Software & Data Integrity Failures    | ✅      | ✅ | —          | —   |
| A09 | Security Logging & Monitoring         | ✅      | ✅ | —          | —   |
| A10 | SSRF                                  | ✅      | ✅ | ✅         | —   |

## Security Design Principles

1. **Safe by design**: No destructive payloads. Probes use unique markers detectable in responses.
2. **Least privilege**: Docker container runs as non-root user.
3. **No data exfiltration**: Scanner never sends code to external services (except OSV API for package names/versions only).
4. **Ethical use enforcement**: CLI displays mandatory ethical disclaimer for URL/GitHub scans.
5. **Exit codes**: Returns non-zero exit codes for CI/CD pipeline integration (2=critical, 1=high).
