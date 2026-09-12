"""SecML CLI Application."""

from typing import Optional
import typer
from rich.console import Console

from secml import __version__

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


@app.command()
def scan() -> None:
    """Run a one-time behavioral security scan of the local machine."""
    from secml.utils.display import (
        print_anomaly_results,
        print_baseline_unavailable,
        print_collection_summary,
        print_error,
        print_rule_detections,
        print_risk_score,
        print_scan_footer,
        print_scan_header,
    )
    from secml.collectors.system import get_system_info
    from secml.collectors.process import get_processes
    from secml.collectors.network import get_network_connections
    from secml.detection.features import extract_features
    from secml.detection.rules import evaluate_rules
    from secml.detection.anomaly import train_anomaly_model, detect_anomalies
    from secml.detection.baseline import load_baseline
    from secml.scoring.risk import calculate_risk_score

    print_scan_header()

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
        # No baseline yet — inform the user, skip ML
        print_baseline_unavailable()
        baseline = None
    except ValueError as exc:
        print_error(f"Baseline file is invalid: {exc}")
        baseline = None

    if baseline is not None:
        try:
            # Reconstruct training observations from baseline statistics.
            # We synthesise two observations per feature using the stored min/max
            # so that the model has something to train on without needing raw data.
            n_obs = baseline.get("n_observations", 0)
            feat_stats = baseline.get("features", {})

            if feat_stats and n_obs >= 2:
                # Build a minimal representative dataset from baseline stats:
                # one observation at the mean, one at ±1 std for each feature.
                keys = list(feat_stats.keys())
                means  = [feat_stats[k].get("mean", 0.0) for k in keys]
                mins   = [feat_stats[k].get("min",  0.0) for k in keys]
                maxs   = [feat_stats[k].get("max",  0.0) for k in keys]

                training_data = [means, mins, maxs]
                # Add a few interpolated points so Isolation Forest has enough data
                for alpha in (0.25, 0.5, 0.75):
                    point = [
                        mins[i] + alpha * (maxs[i] - mins[i])
                        for i in range(len(keys))
                    ]
                    training_data.append(point)

                model = train_anomaly_model(training_data, contamination=0.05)

                # Build a single feature vector for the current observation
                current_vector = [[
                    float(feat_stats[k].get("mean", 0.0)) if k not in features else
                    (float(features[k]) if isinstance(features.get(k), (int, float)) else
                     float(feat_stats[k].get("mean", 0.0)))
                    for k in keys
                ]]

                anomaly_results = detect_anomalies(model, current_vector)
                print_anomaly_results(anomaly_results)
            else:
                print_baseline_unavailable()

        except ValueError as exc:
            print_error(f"ML analysis failed: {exc}")
        except Exception as exc:  # noqa: BLE001 — unexpected ML failures should not crash the scan
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

    print_scan_footer()

    # Exit with non-zero code when risk level is HIGH or CRITICAL
    if risk["level"] in ("HIGH", "CRITICAL"):
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
