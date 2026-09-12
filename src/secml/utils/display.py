"""Terminal display utilities for SecML.

Centralises all Rich formatting so that cli.py stays thin and presentation
logic can be tested or updated independently.
"""

from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich import box

console = Console()

# Severity / level colour mapping
_LEVEL_COLOURS: Dict[str, str] = {
    "SAFE": "bright_green",
    "LOW": "green",
    "MEDIUM": "yellow",
    "HIGH": "red",
    "CRITICAL": "bold red",
}

_SEVERITY_COLOURS: Dict[str, str] = {
    "LOW": "green",
    "MEDIUM": "yellow",
    "HIGH": "red",
}


def print_scan_header() -> None:
    """Print the SecML scan banner."""
    console.print(Rule("[bold cyan]SecML Security Scan[/bold cyan]"))


def print_scan_footer() -> None:
    """Print the scan completion rule."""
    console.print(Rule("[dim]Scan complete[/dim]"))


def print_collection_summary(
    platform: Optional[str],
    process_count: int,
    connection_count: int,
) -> None:
    """Print a brief summary of what was collected.

    Args:
        platform: OS platform string (e.g. 'Darwin'), or None if unavailable.
        process_count: Number of processes collected.
        connection_count: Number of network connections collected.
    """
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Key", style="bold cyan", no_wrap=True)
    table.add_column("Value")

    table.add_row("Platform", platform or "Unknown")
    table.add_row("Processes analysed", str(process_count))
    table.add_row("Network connections", str(connection_count))

    console.print(Panel(table, title="[bold]Collection Summary[/bold]", border_style="blue"))


def print_risk_score(score: int, level: str, rule_score: int, anomaly_score: int) -> None:
    """Print the final risk score and breakdown.

    Args:
        score: Final combined risk score (0–100).
        level: Risk level label (SAFE / LOW / MEDIUM / HIGH / CRITICAL).
        rule_score: Points contributed by rule detections.
        anomaly_score: Points contributed by ML anomaly detection.
    """
    colour = _LEVEL_COLOURS.get(level, "white")

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Key", style="bold cyan", no_wrap=True)
    table.add_column("Value")

    table.add_row("Risk Score", f"[{colour}]{score} / 100[/{colour}]")
    table.add_row("Risk Level", f"[{colour}]{level}[/{colour}]")
    table.add_row("  Rule contribution", str(rule_score))
    table.add_row("  ML contribution",   str(anomaly_score))

    console.print(Panel(table, title="[bold]Risk Assessment[/bold]", border_style=colour))


def print_rule_detections(detections: List[Dict[str, Any]]) -> None:
    """Print a table of rule-based detections.

    Args:
        detections: List of detection dicts from evaluate_rules().
    """
    if not detections:
        console.print(
            Panel(
                "[green]No suspicious patterns detected.[/green]",
                title="[bold]Rule Detections[/bold]",
                border_style="green",
            )
        )
        return

    table = Table(box=box.SIMPLE_HEAD, show_lines=False)
    table.add_column("Rule ID", style="bold", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Message")

    for d in detections:
        if not isinstance(d, dict):
            continue
        rule_id = str(d.get("rule_id", "UNKNOWN"))
        severity = str(d.get("severity", ""))
        message = str(d.get("message", ""))
        colour = _SEVERITY_COLOURS.get(severity, "white")
        table.add_row(rule_id, f"[{colour}]{severity}[/{colour}]", message)

    console.print(Panel(table, title="[bold]Rule Detections[/bold]", border_style="yellow"))


def print_anomaly_results(anomaly_results: List[Dict[str, Any]]) -> None:
    """Print a summary of ML anomaly detection results.

    Args:
        anomaly_results: List of result dicts from detect_anomalies().
    """
    if not anomaly_results:
        console.print(
            Panel(
                "[dim]ML analysis not available (baseline required).[/dim]",
                title="[bold]ML Anomaly Analysis[/bold]",
                border_style="dim",
            )
        )
        return

    anomalous = [r for r in anomaly_results if isinstance(r, dict) and r.get("is_anomaly")]
    total = len(anomaly_results)
    anomalous_count = len(anomalous)

    if anomalous_count == 0:
        body = f"[green]All {total} observation(s) appear NORMAL.[/green]"
        border = "green"
    else:
        body = (
            f"[red]{anomalous_count} of {total} observation(s) flagged as ANOMALY.[/red]\n"
            "[dim]The ML engine identified potentially suspicious behavior that differs from the training data.[/dim]\n"
            "[dim]Further investigation recommended.[/dim]"
        )
        border = "red"

    console.print(Panel(body, title="[bold]ML Anomaly Analysis[/bold]", border_style=border))


def print_baseline_unavailable() -> None:
    """Print a friendly notice that ML analysis was skipped (no baseline)."""
    console.print(
        Panel(
            "[yellow]ML anomaly detection skipped — no baseline available.\n"
            "A behavioral baseline must be generated programmatically before ML scanning can occur.[/yellow]",
            title="[bold]ML Anomaly Analysis[/bold]",
            border_style="yellow",
        )
    )


def print_error(message: str) -> None:
    """Print a formatted error message.

    Args:
        message: Human-readable error description.
    """
    console.print(f"[bold red]Error:[/bold red] {message}")
