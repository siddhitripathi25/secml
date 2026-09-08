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


if __name__ == "__main__":
    app()
