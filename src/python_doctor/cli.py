"""CLI entry point for py-doctor."""

from __future__ import annotations

import sys

import click

from python_doctor import __version__
from python_doctor.config import load_config
from python_doctor.output import output_json, print_scan_result
from python_doctor.scan import scan_project
from python_doctor.types import Severity
from python_doctor.utils.fixer import run_ruff_fix


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-v", "--version", prog_name="Py Doctor")
@click.argument("directory", default=".", type=click.Path(exists=True))
@click.option("--lint/--no-lint", default=True, help="Enable/disable lint checks.")
@click.option(
    "--dead-code/--no-dead-code", default=True, help="Enable/disable dead code detection."
)
@click.option("--verbose", is_flag=True, help="Show file details per rule.")
@click.option("--score", "score_only", is_flag=True, help="Output only the numeric score.")
@click.option("--json", "json_output", is_flag=True, help="Output results as JSON.")
@click.option(
    "--diff",
    "diff_base",
    default=None,
    type=str,
    help="Scan only files changed vs base branch.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["error", "warning", "none"]),
    default="none",
    help="Exit with code 1 on this severity level.",
)
@click.option("--fix", "fix", is_flag=True, default=False, help="Auto-fix issues via ruff before scanning.")
def main(
    directory: str,
    lint: bool,
    dead_code: bool,
    verbose: bool,
    score_only: bool,
    json_output: bool,
    diff_base: str | None,
    fail_on: str,
    fix: bool,
) -> None:
    """Py Doctor — Diagnose your Python project's health."""
    if fix:
        fixes = run_ruff_fix(directory)
        if fixes == -1:
            click.echo("ruff not found, skipping auto-fix")
        else:
            click.echo(f"Fixed {fixes} issues via ruff")

    config = load_config(directory)
    config.lint = lint
    config.dead_code = dead_code
    config.verbose = verbose
    config.fail_on = fail_on

    result = scan_project(directory, config, diff_base=diff_base)

    if json_output:
        output_json(result)
    elif score_only:
        click.echo(str(result.score.value))
    else:
        print_scan_result(result, verbose=verbose)

    # Exit code based on --fail-on
    has_errors = any(d.severity == Severity.ERROR for d in result.diagnostics)
    if (fail_on == "error" and has_errors) or (fail_on == "warning" and result.diagnostics):
        sys.exit(1)
