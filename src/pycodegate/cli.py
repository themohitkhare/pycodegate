"""CLI entry point for pycodegate."""

from __future__ import annotations

import sys
from dataclasses import dataclass

import click

from pycodegate import __version__
from pycodegate.config import load_config
from pycodegate.output import output_json, output_sarif, print_scan_result
from pycodegate.scan import scan_project
from pycodegate.types import Severity
from pycodegate.utils.badge import generate_badge, generate_ci_workflow
from pycodegate.utils.fixer import run_ruff_fix
from pycodegate.utils.precommit import install_precommit_hook


@dataclass
class CliOptions:
    """Bundle of all CLI flags passed to main()."""

    directory: str
    lint: bool
    dead_code: bool
    verbose: bool
    score_only: bool
    json_output: bool
    diff_base: str | None
    fail_on: str
    fix: bool
    profile_override: str | None
    badge: bool
    ci_workflow: bool
    precommit: bool
    min_score: int | None
    sarif_output: bool


def _handle_early_exits(opts: CliOptions) -> bool:
    """Handle flags that exit before scanning. Returns True if handled."""
    if opts.ci_workflow:
        click.echo(generate_ci_workflow(), nl=False)
        return True

    if opts.precommit:
        effective_min = opts.min_score if opts.min_score is not None else 50
        msg = install_precommit_hook(opts.directory, min_score=effective_min)
        click.echo(msg)
        return True

    return False


def _maybe_run_fix(opts: CliOptions) -> None:
    """Apply ruff auto-fix if --fix was passed."""
    if not opts.fix:
        return
    fixes = run_ruff_fix(opts.directory)
    if fixes == -1:
        click.echo("ruff not found, skipping auto-fix")
    else:
        click.echo(f"Fixed {fixes} issues via ruff")


def _build_config(opts: CliOptions):
    """Load config and apply CLI overrides."""
    config = load_config(opts.directory)
    config.lint = opts.lint
    config.dead_code = opts.dead_code
    config.verbose = opts.verbose
    config.fail_on = opts.fail_on
    if opts.profile_override is not None:
        config.profile = opts.profile_override
    return config


def _output_result(opts: CliOptions, result) -> None:
    """Write scan result to stdout in the requested format."""
    if opts.badge:
        click.echo(generate_badge(result.score.value, result.score.label))
        return

    if opts.sarif_output:
        output_sarif(result)
    elif opts.json_output:
        output_json(result)
    elif opts.score_only:
        click.echo(str(result.score.value))
    else:
        print_scan_result(result, verbose=opts.verbose)


def _apply_exit_codes(opts: CliOptions, result) -> None:
    """Exit with non-zero code based on --fail-on and --min-score."""
    has_errors = any(d.severity == Severity.ERROR for d in result.diagnostics)
    if (opts.fail_on == "error" and has_errors) or (
        opts.fail_on == "warning" and result.diagnostics
    ):
        sys.exit(1)

    if opts.min_score is not None and result.score.value < opts.min_score:
        click.echo(
            f"pycodegate: score {result.score.value} is below minimum {opts.min_score}",
            err=True,
        )
        sys.exit(1)


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-v", "--version", prog_name="PyCodeGate")
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
@click.option("--fix", "fix", is_flag=True, default=False, help="Auto-fix issues via ruff.")
@click.option(
    "--profile",
    "profile_override",
    type=click.Choice(["cli", "web", "library", "script"]),
    default=None,
    help="Override auto-detected project profile.",
)
@click.option(
    "--badge", "badge", is_flag=True, default=False, help="Output shields.io badge markdown."
)
@click.option(
    "--ci", "ci_workflow", is_flag=True, default=False, help="Output GitHub Actions workflow YAML."
)
@click.option(
    "--pre-commit", "precommit", is_flag=True, default=False, help="Install git pre-commit hook."
)
@click.option(
    "--min-score",
    "min_score",
    type=int,
    default=None,
    help="Minimum score threshold (exit 1 if below).",
)
@click.option(
    "--sarif",
    "sarif_output",
    is_flag=True,
    default=False,
    help="Output in SARIF format for GitHub Code Scanning.",
)
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
    profile_override: str | None,
    badge: bool,
    ci_workflow: bool,
    precommit: bool,
    min_score: int | None,
    sarif_output: bool,
) -> None:
    """PyCodeGate — Diagnose your Python project's health."""
    opts = CliOptions(
        directory=directory,
        lint=lint,
        dead_code=dead_code,
        verbose=verbose,
        score_only=score_only,
        json_output=json_output,
        diff_base=diff_base,
        fail_on=fail_on,
        fix=fix,
        profile_override=profile_override,
        badge=badge,
        ci_workflow=ci_workflow,
        precommit=precommit,
        min_score=min_score,
        sarif_output=sarif_output,
    )

    if _handle_early_exits(opts):
        return

    _maybe_run_fix(opts)

    config = _build_config(opts)
    result = scan_project(directory, config, diff_base=diff_base)

    _output_result(opts, result)
    _apply_exit_codes(opts, result)
