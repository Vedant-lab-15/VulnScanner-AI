#!/usr/bin/env bash
# =============================================================================
#  VulnScanner AI — One-click launcher
#  Works on Linux, macOS, and WSL (Windows Subsystem for Linux)
#
#  Usage:
#    chmod +x run.sh
#    ./run.sh              → interactive menu
#    ./run.sh setup        → install dependencies only
#    ./run.sh demo         → scan built-in vulnerable samples
#    ./run.sh scan PATH    → scan a custom directory
#    ./run.sh train        → train the ML model
#    ./run.sh test         → run the test suite
#    ./run.sh url URL      → scan a web application
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
step()    { echo -e "\n${BOLD}${BLUE}▶ $*${RESET}"; }
die()     { error "$*"; exit 1; }

banner() {
    echo -e "${CYAN}"
    echo "  ╔══════════════════════════════════════════════════════╗"
    echo "  ║          🛡️  VulnScanner AI  v1.0.0                  ║"
    echo "  ║   ML-powered OWASP Top 10 Vulnerability Scanner      ║"
    echo "  ╚══════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

# ── Detect Python ─────────────────────────────────────────────────────────────
detect_python() {
    for cmd in python3.11 python3.12 python3.10 python3 python; do
        if command -v "$cmd" &>/dev/null; then
            local ver
            ver=$("$cmd" -c "import sys; print(sys.version_info[:2])" 2>/dev/null)
            # Require >= 3.10
            if "$cmd" -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)" 2>/dev/null; then
                PYTHON="$cmd"
                return 0
            fi
        fi
    done
    die "Python 3.10+ is required but not found.\nInstall it from https://python.org/downloads/"
}

# ── Detect pip ────────────────────────────────────────────────────────────────
detect_pip() {
    if "$PYTHON" -m pip --version &>/dev/null; then
        PIP="$PYTHON -m pip"
    else
        die "pip not found. Install it with: $PYTHON -m ensurepip --upgrade"
    fi
}

# ── Check if we're inside a venv ──────────────────────────────────────────────
in_venv() {
    "$PYTHON" -c "import sys; sys.exit(0 if sys.prefix != sys.base_prefix else 1)" 2>/dev/null
}

# ── Setup virtual environment ─────────────────────────────────────────────────
setup_venv() {
    if [ ! -d ".venv" ]; then
        step "Creating virtual environment (.venv)"
        "$PYTHON" -m venv .venv
        success "Virtual environment created"
    fi

    # Activate
    if [ -f ".venv/bin/activate" ]; then
        # shellcheck disable=SC1091
        source .venv/bin/activate
        PYTHON="python"
        PIP="pip"
        success "Virtual environment activated"
    elif [ -f ".venv/Scripts/activate" ]; then
        # Windows / WSL
        # shellcheck disable=SC1091
        source .venv/Scripts/activate
        PYTHON="python"
        PIP="pip"
        success "Virtual environment activated (Windows)"
    fi
}

# ── Install dependencies ──────────────────────────────────────────────────────
install_deps() {
    step "Installing dependencies (this may take 1–3 minutes on first run)"

    $PIP install --upgrade pip --quiet

    if [ -f "requirements.txt" ]; then
        $PIP install -r requirements.txt --quiet \
            || $PIP install -r requirements.txt  # retry with output on failure
    else
        die "requirements.txt not found. Are you in the vulnscanner-ai directory?"
    fi

    # Install the package itself in editable mode
    $PIP install -e . --quiet --no-deps 2>/dev/null || true

    success "All dependencies installed"
}

# ── Check if vulnscanner is available ────────────────────────────────────────
check_installed() {
    if ! "$PYTHON" -c "import vulnscanner" &>/dev/null; then
        warn "VulnScanner AI not installed yet. Running setup first..."
        cmd_setup
    fi
}

# ── Train model if not present ────────────────────────────────────────────────
ensure_model() {
    if [ ! -f "models/vuln_classifier.joblib" ]; then
        step "No trained model found — training now (takes ~10 seconds)"
        "$PYTHON" -c "
import sys; sys.path.insert(0, '.')
from vulnscanner.ml.trainer import train
m = train()
print(f'  CV ROC-AUC: {m[\"cv_roc_auc_mean\"]:.3f}  |  Samples: {m[\"n_samples\"]}')
"
        success "Model trained and saved to models/"
    fi
}

# ── Open report in browser ────────────────────────────────────────────────────
open_report() {
    local file="$1"
    if [ ! -f "$file" ]; then
        warn "Report file not found: $file"
        return
    fi

    local abs_path
    abs_path="$(realpath "$file" 2>/dev/null || readlink -f "$file" 2>/dev/null || echo "$file")"

    echo ""
    success "Report saved → ${BOLD}$abs_path${RESET}"
    echo -e "  ${DIM}Open in browser:${RESET}"
    echo -e "  ${CYAN}file://$abs_path${RESET}"

    # Try to auto-open
    if command -v xdg-open &>/dev/null; then
        xdg-open "$abs_path" 2>/dev/null &
    elif command -v open &>/dev/null; then
        open "$abs_path" 2>/dev/null &
    fi
}

# =============================================================================
#  COMMANDS
# =============================================================================

cmd_setup() {
    step "Setting up VulnScanner AI"
    detect_python
    detect_pip

    if ! in_venv; then
        setup_venv
    else
        info "Already inside a virtual environment"
    fi

    install_deps
    ensure_model

    echo ""
    echo -e "${GREEN}${BOLD}✓ Setup complete!${RESET}"
    echo -e "  Run ${CYAN}./run.sh demo${RESET} to scan the built-in vulnerable samples"
    echo -e "  Run ${CYAN}./run.sh scan /path/to/code${RESET} to scan your own project"
    echo -e "  Run ${CYAN}./run.sh${RESET} for the interactive menu"
}

cmd_demo() {
    check_installed
    ensure_model

    step "Running demo scan on built-in vulnerable samples"
    echo -e "  ${DIM}Scanning: samples/ (Python, JavaScript, Java, PHP)${RESET}"
    echo ""

    mkdir -p reports

    "$PYTHON" -c "
import sys; sys.path.insert(0, '.')
from vulnscanner.scanner.core import Scanner
from vulnscanner.report.generator import ReportGenerator
from pathlib import Path

scanner = Scanner(enable_ml=True, enable_simulation=True, enable_sca=True)
result = scanner.scan_directory(Path('samples'))

s = result.summary
print(f'  Findings: {s.total_findings} total')
print(f'  Critical: {s.critical}  High: {s.high}  Medium: {s.medium}  Low: {s.low}')
print(f'  Risk Score: {s.overall_risk_score:.0f}/100')
print(f'  Files scanned: {result.metadata.files_scanned}')
print(f'  Languages: {', '.join(result.metadata.languages_detected)}')

gen = ReportGenerator()
gen.generate_html(result,  Path('reports/demo_report.html'))
gen.generate_sarif(result, Path('reports/demo_report.sarif.json'))
gen.generate_json(result,  Path('reports/demo_report.json'))
print()
print('Reports generated:')
print('  reports/demo_report.html')
print('  reports/demo_report.sarif.json')
print('  reports/demo_report.json')
"
    open_report "reports/demo_report.html"
}

cmd_scan() {
    local target="${1:-}"
    if [ -z "$target" ]; then
        echo -e "${YELLOW}Enter the path to scan:${RESET} "
        read -r target
    fi

    if [ ! -e "$target" ]; then
        die "Path not found: $target"
    fi

    check_installed
    ensure_model

    step "Scanning: $target"
    mkdir -p reports

    local report_base="reports/scan_$(date +%Y%m%d_%H%M%S)"

    "$PYTHON" -c "
import sys; sys.path.insert(0, '.')
from vulnscanner.scanner.core import Scanner
from vulnscanner.report.generator import ReportGenerator
from pathlib import Path

target = Path('$target')
scanner = Scanner(enable_ml=True, enable_simulation=True, enable_sca=True)
result = scanner.scan_directory(target)

s = result.summary
print(f'  Findings: {s.total_findings} total')
print(f'  Critical: {s.critical}  High: {s.high}  Medium: {s.medium}  Low: {s.low}')
print(f'  Risk Score: {s.overall_risk_score:.0f}/100')
print(f'  Files scanned: {result.metadata.files_scanned}')

gen = ReportGenerator()
gen.generate_html(result,  Path('$report_base.html'))
gen.generate_sarif(result, Path('$report_base.sarif.json'))
gen.generate_json(result,  Path('$report_base.json'))
print()
print('Reports:')
print(f'  $report_base.html')
print(f'  $report_base.sarif.json')
print(f'  $report_base.json')
"
    open_report "${report_base}.html"
}

cmd_url() {
    local target="${1:-}"
    if [ -z "$target" ]; then
        echo -e "${YELLOW}Enter the URL to scan (only scan systems you own):${RESET} "
        read -r target
    fi

    check_installed

    echo ""
    echo -e "${YELLOW}${BOLD}⚠  ETHICAL USE REMINDER${RESET}"
    echo -e "  Only scan systems you ${BOLD}own${RESET} or have ${BOLD}explicit written permission${RESET} to test."
    echo -e "  Unauthorised scanning may be illegal in your jurisdiction."
    echo ""
    echo -n "  I confirm I am authorised to scan this target [y/N]: "
    read -r confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        info "Scan cancelled."
        exit 0
    fi

    step "Scanning URL: $target"
    mkdir -p reports

    local report_base="reports/url_scan_$(date +%Y%m%d_%H%M%S)"

    "$PYTHON" -c "
import sys, datetime; sys.path.insert(0, '.')
from vulnscanner.scanner.url_scanner import URLScanner
from vulnscanner.scanner.core import Scanner
from vulnscanner.report.generator import ReportGenerator
from vulnscanner.utils.models import ScanResult, ScanMetadata, ScanTarget, RiskSummary
from vulnscanner.utils.helpers import generate_scan_id
from pathlib import Path

url_scanner = URLScanner(max_pages=20)
findings = url_scanner.scan('$target')
url_scanner.close()

scanner = Scanner(enable_ml=False, enable_simulation=False, enable_sca=False)
now = datetime.datetime.utcnow().isoformat()
result = ScanResult(
    metadata=ScanMetadata(
        scanner_version='1.0.0', scan_id=generate_scan_id(),
        started_at=now, finished_at=now,
        target=ScanTarget(kind='url', value='$target'),
    ),
    summary=scanner._compute_summary(findings, []),
    findings=findings,
)

print(f'  Findings: {result.summary.total_findings}')
print(f'  Critical: {result.summary.critical}  High: {result.summary.high}')

gen = ReportGenerator()
gen.generate_html(result, Path('$report_base.html'))
gen.generate_sarif(result, Path('$report_base.sarif.json'))
print()
print('Reports:')
print(f'  $report_base.html')
print(f'  $report_base.sarif.json')
"
    open_report "${report_base}.html"
}

cmd_github() {
    local repo="${1:-}"
    if [ -z "$repo" ]; then
        echo -e "${YELLOW}Enter the GitHub repository URL:${RESET} "
        read -r repo
    fi

    check_installed
    ensure_model

    step "Cloning and scanning: $repo"
    mkdir -p reports

    local report_base="reports/github_scan_$(date +%Y%m%d_%H%M%S)"

    "$PYTHON" -c "
import sys; sys.path.insert(0, '.')
from vulnscanner.scanner.core import Scanner
from vulnscanner.report.generator import ReportGenerator
from pathlib import Path

scanner = Scanner(enable_ml=True, enable_simulation=True, enable_sca=True)
result = scanner.scan_github('$repo')

s = result.summary
print(f'  Findings: {s.total_findings}  Critical: {s.critical}  High: {s.high}')
print(f'  Risk Score: {s.overall_risk_score:.0f}/100')

gen = ReportGenerator()
gen.generate_html(result,  Path('$report_base.html'))
gen.generate_sarif(result, Path('$report_base.sarif.json'))
gen.generate_json(result,  Path('$report_base.json'))
print()
print('Reports:')
print(f'  $report_base.html')
print(f'  $report_base.sarif.json')
"
    open_report "${report_base}.html"
}

cmd_train() {
    check_installed

    step "Training ML model"
    echo -e "  ${DIM}Generating synthetic dataset and training XGBoost classifier...${RESET}"
    echo ""

    "$PYTHON" -c "
import sys; sys.path.insert(0, '.')
from vulnscanner.ml.trainer import train
m = train()
print(f'  CV ROC-AUC:  {m[\"cv_roc_auc_mean\"]:.4f} ± {m[\"cv_roc_auc_std\"]:.4f}')
print(f'  Train AUC:   {m[\"train_roc_auc\"]:.4f}')
print(f'  Samples:     {m[\"n_samples\"]}')
print(f'  Features:    {m[\"n_features\"]}')
"
    success "Model saved to models/vuln_classifier.joblib"
    echo -e "  ${DIM}Open notebooks/model_training.ipynb for full training analysis${RESET}"
}

cmd_test() {
    check_installed

    step "Running test suite (103 tests)"
    echo ""

    if ! "$PYTHON" -m pytest --version &>/dev/null; then
        info "Installing pytest..."
        $PIP install pytest pytest-cov --quiet
    fi

    "$PYTHON" -m pytest tests/ -v --tb=short --no-header \
        --cov=vulnscanner --cov-report=term-missing 2>&1 \
        | grep -v "^$" \
        | grep -v "^--" \
        | head -80

    echo ""
    "$PYTHON" -m pytest tests/ -q --no-header --tb=no 2>&1 | tail -3
}

cmd_notebook() {
    check_installed

    step "Launching Jupyter notebook"

    if ! "$PYTHON" -m jupyter --version &>/dev/null; then
        info "Installing Jupyter..."
        $PIP install jupyter --quiet
    fi

    if ! "$PYTHON" -m pip show matplotlib &>/dev/null; then
        info "Installing matplotlib for notebook charts..."
        $PIP install matplotlib --quiet
    fi

    info "Opening notebooks/model_training.ipynb"
    "$PYTHON" -m jupyter notebook notebooks/model_training.ipynb
}

cmd_docker() {
    if ! command -v docker &>/dev/null; then
        die "Docker not found. Install from https://docs.docker.com/get-docker/"
    fi

    step "Building Docker image"
    docker build -t vulnscanner-ai . --quiet
    success "Image built: vulnscanner-ai"

    echo ""
    echo -e "  ${DIM}To scan a directory with Docker:${RESET}"
    echo -e "  ${CYAN}docker run --rm -v \$(pwd)/my-project:/scan-target:ro -v \$(pwd)/reports:/reports vulnscanner-ai scan /scan-target --output /reports/report --sarif${RESET}"
    echo ""
    echo -e "  ${DIM}Or use docker-compose:${RESET}"
    echo -e "  ${CYAN}docker-compose up vulnscanner${RESET}"
}

# ── Interactive menu ──────────────────────────────────────────────────────────
show_menu() {
    banner
    echo -e "  ${BOLD}What would you like to do?${RESET}"
    echo ""
    echo -e "  ${CYAN}1)${RESET} ${BOLD}Setup${RESET}          — Install dependencies & train ML model"
    echo -e "  ${CYAN}2)${RESET} ${BOLD}Demo scan${RESET}      — Scan built-in vulnerable samples (recommended first run)"
    echo -e "  ${CYAN}3)${RESET} ${BOLD}Scan directory${RESET} — Scan your own source code"
    echo -e "  ${CYAN}4)${RESET} ${BOLD}Scan URL${RESET}       — Scan a live web application (authorised targets only)"
    echo -e "  ${CYAN}5)${RESET} ${BOLD}Scan GitHub repo${RESET}— Clone and scan a GitHub repository"
    echo -e "  ${CYAN}6)${RESET} ${BOLD}Train model${RESET}    — Retrain the ML classifier"
    echo -e "  ${CYAN}7)${RESET} ${BOLD}Run tests${RESET}      — Run the full pytest suite (103 tests)"
    echo -e "  ${CYAN}8)${RESET} ${BOLD}Open notebook${RESET}  — Launch Jupyter training notebook"
    echo -e "  ${CYAN}9)${RESET} ${BOLD}Build Docker${RESET}   — Build the Docker image"
    echo -e "  ${CYAN}0)${RESET} ${BOLD}Exit${RESET}"
    echo ""
    echo -n "  Enter choice [0-9]: "
    read -r choice

    case "$choice" in
        1) cmd_setup ;;
        2) cmd_demo ;;
        3)
            echo -n "  Path to scan: "
            read -r path
            cmd_scan "$path"
            ;;
        4)
            echo -n "  URL to scan: "
            read -r url
            cmd_url "$url"
            ;;
        5)
            echo -n "  GitHub repo URL: "
            read -r repo
            cmd_github "$repo"
            ;;
        6) cmd_train ;;
        7) cmd_test ;;
        8) cmd_notebook ;;
        9) cmd_docker ;;
        0) echo -e "\n  ${DIM}Goodbye!${RESET}\n"; exit 0 ;;
        *) warn "Invalid choice: $choice"; show_menu ;;
    esac
}

# =============================================================================
#  ENTRY POINT
# =============================================================================

# Change to the script's directory so relative paths work
cd "$(dirname "${BASH_SOURCE[0]}")"

# Detect Python early (needed for most commands)
detect_python 2>/dev/null || true
detect_pip    2>/dev/null || true

# Activate venv if it exists
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
    PYTHON="python"
    PIP="pip"
elif [ -f ".venv/Scripts/activate" ]; then
    source .venv/Scripts/activate
    PYTHON="python"
    PIP="pip"
fi

# Route to command or show menu
case "${1:-menu}" in
    menu)           banner; show_menu ;;
    setup)          banner; cmd_setup ;;
    demo)           banner; cmd_demo ;;
    scan)           banner; cmd_scan "${2:-}" ;;
    url)            banner; cmd_url "${2:-}" ;;
    github)         banner; cmd_github "${2:-}" ;;
    train)          banner; cmd_train ;;
    test|tests)     banner; cmd_test ;;
    notebook)       banner; cmd_notebook ;;
    docker)         banner; cmd_docker ;;
    help|-h|--help)
        banner
        echo -e "  ${BOLD}Usage:${RESET}"
        echo -e "    ${CYAN}./run.sh${RESET}              Interactive menu"
        echo -e "    ${CYAN}./run.sh setup${RESET}        Install everything"
        echo -e "    ${CYAN}./run.sh demo${RESET}         Scan built-in samples"
        echo -e "    ${CYAN}./run.sh scan PATH${RESET}    Scan a directory"
        echo -e "    ${CYAN}./run.sh url URL${RESET}      Scan a web app"
        echo -e "    ${CYAN}./run.sh github URL${RESET}   Scan a GitHub repo"
        echo -e "    ${CYAN}./run.sh train${RESET}        Train ML model"
        echo -e "    ${CYAN}./run.sh test${RESET}         Run test suite"
        echo -e "    ${CYAN}./run.sh notebook${RESET}     Open Jupyter notebook"
        echo -e "    ${CYAN}./run.sh docker${RESET}       Build Docker image"
        echo ""
        ;;
    *)
        error "Unknown command: ${1}"
        echo -e "  Run ${CYAN}./run.sh help${RESET} for usage"
        exit 1
        ;;
esac
