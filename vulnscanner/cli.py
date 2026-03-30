"""
VulnScanner AI — CLI entry point.

Commands:
  vulnscanner scan PATH        Scan a local directory
  vulnscanner url URL          Scan a web application
  vulnscanner github URL       Scan a GitHub repository
  vulnscanner train            Train the ML model
  vulnscanner report PATH      Re-render a report from a JSON result
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import print as rprint

from vulnscanner.utils.logging import get_logger, setup_file_logging
from vulnscanner.utils.models import Severity

app = typer.Typer(
    name="vulnscanner",
    help="🛡️  VulnScanner AI — ML-powered OWASP Top 10 vulnerability scanner",
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console()
logger = get_logger("vulnscanner.cli")

# ---------------------------------------------------------------------------
# Shared options
# ---------------------------------------------------------------------------

def _output_option(default: str = "vulnscanner_report") -> typer.Option:
    return typer.Option(default, "--output", "-o", help="Output file base name (no extension)")


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------

@app.command()
def scan(
    path: Path = typer.Argument(..., help="Directory to scan", exists=True, file_okay=False),
    output: str = typer.Option("vulnscanner_report", "--output", "-o", help="Output base name"),
    no_ml: bool = typer.Option(False, "--no-ml", help="Disable ML classification"),
    no_sim: bool = typer.Option(False, "--no-sim", help="Disable taint simulation"),
    no_sca: bool = typer.Option(False, "--no-sca", help="Disable dependency scanning"),
    sarif: bool = typer.Option(False, "--sarif", help="Also export SARIF file"),
    pdf: bool = typer.Option(False, "--pdf", help="Also export PDF report"),
    json_out: bool = typer.Option(False, "--json", help="Also export JSON result"),
    log_file: Optional[Path] = typer.Option(None, "--log-file", help="Write logs to file"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Scan a local source code directory for OWASP Top 10 vulnerabilities."""
    _banner()

    if log_file:
        setup_file_logging(log_file)
    if verbose:
        import logging
        logging.getLogger("vulnscanner").setLevel(logging.DEBUG)

    from vulnscanner.scanner.core import Scanner
    from vulnscanner.report.generator import ReportGenerator

    console.print(f"[bold cyan]Target:[/] {path.resolve()}")
    console.print(f"[bold cyan]ML:[/] {'disabled' if no_ml else 'enabled'}  "
                  f"[bold cyan]Simulation:[/] {'disabled' if no_sim else 'enabled'}  "
                  f"[bold cyan]SCA:[/] {'disabled' if no_sca else 'enabled'}\n")

    scanner = Scanner(
        enable_ml=not no_ml,
        enable_simulation=not no_sim,
        enable_sca=not no_sca,
    )

    with console.status("[bold green]Scanning...", spinner="dots"):
        result = scanner.scan_directory(path)

    _print_summary(result)

    gen = ReportGenerator()
    html_path = Path(f"{output}.html")
    gen.generate_html(result, html_path)
    console.print(f"\n[bold green]✓[/] HTML report → [link={html_path}]{html_path}[/link]")

    if sarif:
        sarif_path = Path(f"{output}.sarif.json")
        gen.generate_sarif(result, sarif_path)
        console.print(f"[bold green]✓[/] SARIF report → {sarif_path}")

    if json_out:
        json_path = Path(f"{output}.json")
        gen.generate_json(result, json_path)
        console.print(f"[bold green]✓[/] JSON result → {json_path}")

    if pdf:
        pdf_path = Path(f"{output}.pdf")
        gen.generate_pdf(result, pdf_path)
        console.print(f"[bold green]✓[/] PDF report → {pdf_path}")

    _exit_code(result)


# ---------------------------------------------------------------------------
# url command
# ---------------------------------------------------------------------------

@app.command()
def url(
    target_url: str = typer.Argument(..., help="Web application URL to scan"),
    output: str = typer.Option("vulnscanner_report", "--output", "-o"),
    max_pages: int = typer.Option(20, "--max-pages", help="Max pages to crawl"),
    sarif: bool = typer.Option(False, "--sarif"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Scan a live web application via URL (safe probe simulation)."""
    _banner()
    _ethical_warning()

    from vulnscanner.scanner.url_scanner import URLScanner
    from vulnscanner.scanner.core import Scanner
    from vulnscanner.report.generator import ReportGenerator
    from vulnscanner.utils.models import (
        ScanTarget, ScanMetadata, RiskSummary, ScanResult
    )
    from vulnscanner.utils.helpers import generate_scan_id
    import datetime

    console.print(f"[bold cyan]Target URL:[/] {target_url}\n")

    url_scanner = URLScanner(max_pages=max_pages)
    with console.status("[bold green]Crawling and probing...", spinner="dots"):
        findings = url_scanner.scan(target_url)
    url_scanner.close()

    # Build a minimal ScanResult for the URL scan
    scanner = Scanner(enable_ml=False, enable_simulation=False, enable_sca=False)
    now = datetime.datetime.utcnow().isoformat()
    result = ScanResult(
        metadata=ScanMetadata(
            scanner_version="1.0.0",
            scan_id=generate_scan_id(),
            started_at=now,
            finished_at=now,
            target=ScanTarget(kind="url", value=target_url),
            files_scanned=0,
        ),
        summary=scanner._compute_summary(findings, []),
        findings=findings,
    )

    _print_summary(result)

    gen = ReportGenerator()
    html_path = Path(f"{output}.html")
    gen.generate_html(result, html_path)
    console.print(f"\n[bold green]✓[/] HTML report → {html_path}")

    if sarif:
        gen.generate_sarif(result, Path(f"{output}.sarif.json"))
    if json_out:
        gen.generate_json(result, Path(f"{output}.json"))

    _exit_code(result)


# ---------------------------------------------------------------------------
# github command
# ---------------------------------------------------------------------------

@app.command()
def github(
    repo_url: str = typer.Argument(..., help="GitHub repository URL"),
    output: str = typer.Option("vulnscanner_report", "--output", "-o"),
    no_ml: bool = typer.Option(False, "--no-ml"),
    sarif: bool = typer.Option(False, "--sarif"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Clone and scan a GitHub repository."""
    _banner()

    from vulnscanner.scanner.core import Scanner
    from vulnscanner.report.generator import ReportGenerator

    console.print(f"[bold cyan]Repository:[/] {repo_url}\n")

    scanner = Scanner(enable_ml=not no_ml)
    with console.status("[bold green]Cloning and scanning...", spinner="dots"):
        result = scanner.scan_github(repo_url)

    _print_summary(result)

    gen = ReportGenerator()
    html_path = Path(f"{output}.html")
    gen.generate_html(result, html_path)
    console.print(f"\n[bold green]✓[/] HTML report → {html_path}")

    if sarif:
        gen.generate_sarif(result, Path(f"{output}.sarif.json"))
    if json_out:
        gen.generate_json(result, Path(f"{output}.json"))

    _exit_code(result)


# ---------------------------------------------------------------------------
# train command
# ---------------------------------------------------------------------------

@app.command()
def train(
    data: Optional[Path] = typer.Option(None, "--data", "-d", help="Path to training CSV"),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir", help="Model output directory"),
) -> None:
    """Train the ML vulnerability classifier."""
    _banner()
    console.print("[bold cyan]Starting ML training pipeline...[/]\n")

    from vulnscanner.ml.trainer import train as run_training

    with console.status("[bold green]Training...", spinner="dots"):
        metrics = run_training(data_path=data, output_dir=output_dir)

    table = Table(title="Training Results", style="cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Value", style="green")
    table.add_row("CV ROC-AUC (mean)", f"{metrics['cv_roc_auc_mean']:.4f}")
    table.add_row("CV ROC-AUC (std)", f"{metrics['cv_roc_auc_std']:.4f}")
    table.add_row("Train ROC-AUC", f"{metrics['train_roc_auc']:.4f}")
    table.add_row("Samples", str(metrics["n_samples"]))
    table.add_row("Features", str(metrics["n_features"]))
    console.print(table)
    console.print("\n[bold green]✓[/] Model saved to models/vuln_classifier.joblib")


# ---------------------------------------------------------------------------
# report command (re-render from JSON)
# ---------------------------------------------------------------------------

@app.command()
def report(
    json_path: Path = typer.Argument(..., help="Path to a vulnscanner JSON result file"),
    output: str = typer.Option("vulnscanner_report", "--output", "-o"),
    sarif: bool = typer.Option(False, "--sarif"),
    pdf: bool = typer.Option(False, "--pdf"),
) -> None:
    """Re-render reports from a saved JSON scan result."""
    from vulnscanner.utils.models import ScanResult
    from vulnscanner.report.generator import ReportGenerator

    result = ScanResult.model_validate_json(json_path.read_text())
    gen = ReportGenerator()
    gen.generate_html(result, Path(f"{output}.html"))
    console.print(f"[bold green]✓[/] HTML report → {output}.html")
    if sarif:
        gen.generate_sarif(result, Path(f"{output}.sarif.json"))
    if pdf:
        gen.generate_pdf(result, Path(f"{output}.pdf"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _banner() -> None:
    console.print(Panel.fit(
        "[bold cyan]VulnScanner AI[/] [dim]v1.0.0[/]\n"
        "[dim]ML-powered OWASP Top 10 vulnerability scanner[/]",
        border_style="cyan",
    ))


def _ethical_warning() -> None:
    console.print(Panel(
        "[bold yellow]⚠  ETHICAL USE ONLY[/]\n"
        "Only scan systems you own or have [bold]explicit written permission[/] to test.\n"
        "Unauthorised scanning may be illegal in your jurisdiction.",
        border_style="yellow",
        title="Disclaimer",
    ))


def _print_summary(result) -> None:
    """Print a Rich summary table after scanning."""
    s = result.summary
    table = Table(title=f"Scan Summary — ID: {result.metadata.scan_id}", style="cyan")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")

    sev_styles = {
        "CRITICAL": "bold red",
        "HIGH": "bold orange1",
        "MEDIUM": "bold yellow",
        "LOW": "bold green",
        "INFO": "bold blue",
    }
    for sev, count in [
        ("CRITICAL", s.critical), ("HIGH", s.high),
        ("MEDIUM", s.medium), ("LOW", s.low), ("INFO", s.info),
    ]:
        table.add_row(f"[{sev_styles[sev]}]{sev}[/]", str(count))

    table.add_section()
    table.add_row("[bold]Total Findings[/]", str(s.total_findings))
    table.add_row("[bold]Risk Score[/]", f"{s.overall_risk_score:.0f}/100")
    table.add_row("[bold]Files Scanned[/]", str(result.metadata.files_scanned))

    console.print(table)


def _exit_code(result) -> None:
    """Exit with non-zero code if critical/high findings exist."""
    if result.summary.critical > 0:
        raise typer.Exit(code=2)
    if result.summary.high > 0:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
