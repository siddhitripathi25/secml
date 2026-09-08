"""Tests for SecML CLI."""

from typer.testing import CliRunner
from secml.cli import app

runner = CliRunner()


def test_cli_starts():
    """Verify that the CLI starts successfully."""
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert "SecML" in result.stdout


def test_cli_help():
    """Verify that --help displays help and CLI description."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "AI/ML-Powered Behavioral Security Analyzer for the Terminal" in result.stdout


def test_cli_version():
    """Verify that --version returns 0.1.0."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.stdout
