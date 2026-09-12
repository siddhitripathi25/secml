"""SecML CLI Application."""

import time
from datetime import datetime
from typing import Optional

import typer
from rich.console import Console

from secml import __version__

# Pipeline components — imported at module level so tests can patch them
# via  patch("secml.cli.<name>", ...)
from secml.collectors.system import get_system_info
from secml.collectors.process import get_processes
from secml.collectors.network import get_network_connections
from secml.detection.features import extract_features
from secml.detection.rules import evaluate_rules
from secml.detection.anomaly import train_anomaly_model, detect_anomalies
from secml.detection.baseline import load_baseline
from secml.scoring.risk import calculate_risk_score

app = typer.Typer(
    name="secml",
    help="AI/ML-Powered Behavioral Security Analyzer for the Terminal",
    add_completion=False,
)
console = Console()


def version_callback(value: bool) -> None:
    if value:
        console.print(f"0.1.0")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """AI/ML-Powered Behavioral Security Analyzer for the Terminal."""
    if ctx.invoked_subcommand is None and not version:
        console.print(
            "[bold blue]SecML[/bold blue] - AI/ML-Powered Behavioral Security Analyzer for the Terminal"
        )
        console.print("Use [bold cyan]secml --help[/bold cyan] for available options.")


def _run_core_pipeline() -> dict:
    """Run a single iteration of telemetry collection, detection, and scoring.
    
    Returns:
        dict: The calculated risk score dictionary.
    """
    from secml.utils.display import (
        print_anomaly_results,
        print_baseline_unavailable,
        print_collection_summary,
        print_error,
        print_rule_detections,
        print_risk_score,
    )

    # ------------------------------------------------------------------
    # 1. Collect telemetry
    # ------------------------------------------------------------------
    try:
        system_info = get_system_info()
    except OSError as exc:
        print_error(f"Could not collect system information: {exc}")
        system_info = {}

    try:
        processes = get_processes()
    except OSError as exc:
        print_error(f"Could not collect process list: {exc}")
        processes = []

    try:
        network_connections = get_network_connections()
    except (OSError, PermissionError) as exc:
        print_error(f"Could not collect network connections: {exc}")
        network_connections = []

    platform = system_info.get("platform") if isinstance(system_info, dict) else None
    print_collection_summary(
        platform=platform,
        process_count=len(processes),
        connection_count=len(network_connections),
    )

    # ------------------------------------------------------------------
    # 2. Extract features
    # ------------------------------------------------------------------
    features = extract_features(
        system_info=system_info,
        processes=processes,
        network_connections=network_connections,
    )

    # ------------------------------------------------------------------
    # 3. Rule-based detection
    # ------------------------------------------------------------------
    rule_detections = evaluate_rules(features)
    print_rule_detections(rule_detections)

    # ------------------------------------------------------------------
    # 4. ML anomaly detection (requires a saved baseline for training)
    # ------------------------------------------------------------------
    anomaly_results: list = []

    try:
        baseline = load_baseline()
    except FileNotFoundError:
        print_baseline_unavailable()
        baseline = None
    except ValueError as exc:
        print_error(f"Baseline file is invalid: {exc}")
        baseline = None

    if baseline is not None:
        try:
            feat_stats = baseline.get("features", {})
            n_obs = baseline.get("n_observations", 0)

            if feat_stats and n_obs >= 2:
                keys = list(feat_stats.keys())
                means = [feat_stats[k].get("mean", 0.0) for k in keys]
                mins  = [feat_stats[k].get("min",  0.0) for k in keys]
                maxs  = [feat_stats[k].get("max",  0.0) for k in keys]

                training_data = [means, mins, maxs]
                for alpha in (0.25, 0.5, 0.75):
                    point = [
                        mins[i] + alpha * (maxs[i] - mins[i])
                        for i in range(len(keys))
                    ]
                    training_data.append(point)

                model = train_anomaly_model(training_data, contamination=0.05)

                current_vector = [[
                    (float(features[k])
                     if isinstance(features.get(k), (int, float))
                     else float(feat_stats[k].get("mean", 0.0)))
                    for k in keys
                ]]

                anomaly_results = detect_anomalies(model, current_vector)
                print_anomaly_results(anomaly_results)
            else:
                print_baseline_unavailable()

        except ValueError as exc:
            print_error(f"ML analysis failed: {exc}")
        except Exception as exc:  # noqa: BLE001
            print_error(f"ML analysis encountered an unexpected error: {exc}")

    # ------------------------------------------------------------------
    # 5. Risk scoring
    # ------------------------------------------------------------------
    risk = calculate_risk_score(
        rule_results=rule_detections,
        anomaly_results=anomaly_results,
    )

    print_risk_score(
        score=risk["score"],
        level=risk["level"],
        rule_score=risk["rule_score"],
        anomaly_score=risk["anomaly_score"],
    )
    
    return risk


@app.command()
def scan() -> None:
    """Run a one-time behavioral security scan of the local machine."""
    from secml.utils.display import print_scan_footer, print_scan_header

    print_scan_header()
    risk = _run_core_pipeline()
    print_scan_footer()

    if risk["level"] in ("HIGH", "CRITICAL"):
        raise typer.Exit(code=1)


@app.command()
def monitor(
    interval: int = typer.Option(
        5,
        "--interval",
        "-i",
        help="Monitoring interval in seconds",
        min=1,
    )
) -> None:
    """Run a continuous behavioral security scan in the terminal."""
    from rich.rule import Rule
    from rich.panel import Panel

    console.print(Rule("[bold magenta]SecML Monitor Mode Started[/bold magenta]"))
    console.print(f"[dim]Interval: {interval} seconds. Press Ctrl+C to stop.[/dim]")
    
    try:
        while True:
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            console.print()
            console.print(Rule(f"[bold cyan]Scan Cycle - {now_str}[/bold cyan]"))
            
            _run_core_pipeline()
            
            # Wait for next cycle
            time.sleep(interval)
            
    except KeyboardInterrupt:
        console.print()
        console.print(Panel("[bold green]Monitor mode stopped successfully by user.[/bold green]", border_style="green"))
        raise typer.Exit(code=0)


if __name__ == "__main__":
    app()
