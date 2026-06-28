"""Rich terminal output: score bar, doctor face, framed summary, category-grouped diagnostics."""

from __future__ import annotations

import json
import sys
from collections import defaultdict

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from pycodegate import __version__
from pycodegate.constants import CATEGORY_WEIGHTS, FRAMEWORK_CATEGORY_MAP
from pycodegate.score import category_breakdown
from pycodegate.types import Category, Diagnostic, ScanResult, Severity

BAR_WIDTH = 50

# Doctor ASCII faces
_HAPPY = r"""
  ┌─────┐
  │ ◕ ◕ │
  │  ◡  │
  └─────┘
"""

_NEUTRAL = r"""
  ┌─────┐
  │ ◑ ◑ │
  │  ━  │
  └─────┘
"""

_SAD = r"""
  ┌─────┐
  │ ◔ ◔ │
  │  ◠  │
  └─────┘
"""

# Display metadata for each category
CATEGORY_DISPLAY: dict[Category, tuple[str, str]] = {
    Category.SECURITY: ("🔒", "Security"),
    Category.CORRECTNESS: ("✓", "Correctness"),
    Category.COMPLEXITY: ("⚡", "Complexity"),
    Category.ARCHITECTURE: ("🏗", "Architecture"),
    Category.PERFORMANCE: ("🐎", "Performance"),
    Category.STRUCTURE: ("📁", "Structure"),
    Category.IMPORTS: ("📦", "Imports"),
    Category.DEAD_CODE: ("💀", "Dead Code"),
    Category.DEPENDENCIES: ("🛡", "Dependencies"),
}


def format_score_bar(score: int) -> str:
    """Return a text-based score bar."""
    filled = round(score / 100 * BAR_WIDTH)
    empty = BAR_WIDTH - filled
    bar = "█" * filled + "░" * empty
    return f"  {bar} {score}"


def format_doctor_face(score: int) -> str:
    """Return doctor ASCII art based on score."""
    if score >= 75:
        return _HAPPY
    elif score >= 50:
        return _NEUTRAL
    else:
        return _SAD


def _score_color(score: int) -> str:
    if score >= 75:
        return "green"
    elif score >= 50:
        return "yellow"
    return "red"


def format_summary(result: ScanResult) -> str:
    """Format the full scan summary as a string (for testing)."""
    lines: list[str] = []
    lines.append(format_doctor_face(result.score.value))
    lines.append(f"  Score: {result.score.value}/100 — {result.score.label}")
    lines.append(format_score_bar(result.score.value))
    lines.append("")

    errors = sum(1 for d in result.diagnostics if d.severity == Severity.ERROR)
    warnings = sum(1 for d in result.diagnostics if d.severity == Severity.WARNING)
    files = len({d.file_path for d in result.diagnostics})

    lines.append(f"  {errors} errors, {warnings} warnings across {files} files")
    lines.append(f"  Completed in {result.elapsed_ms}ms")
    return "\n".join(lines)


def print_scan_result(result: ScanResult, verbose: bool = False) -> None:
    """Print the full scan result to terminal using Rich."""
    console = Console()

    # Project info header
    p = result.project
    console.print()
    console.print(f"  [bold]PyCodeGate[/bold] — v{__version__}")
    console.print()
    console.print(f"  [dim]Path:[/dim]            {p.path}")
    if p.python_version:
        console.print(f"  [dim]Python:[/dim]          {p.python_version}")
    if p.package_manager:
        console.print(f"  [dim]Package manager:[/dim] {p.package_manager}")
    if p.test_framework:
        console.print(f"  [dim]Test framework:[/dim]  {p.test_framework}")
    if result.profile:
        console.print(f"  [dim]Profile:[/dim]         {result.profile}")
    console.print(f"  [dim]Source files:[/dim]    {p.source_file_count}")
    console.print()

    # Category-grouped diagnostics with sub-scores (single source of truth from scoring)
    breakdown = result.category_scores or category_breakdown(result.diagnostics)
    _print_category_groups(console, result.diagnostics, breakdown, verbose)

    # Summary panel
    color = _score_color(result.score.value)
    face = format_doctor_face(result.score.value).strip()

    errors = sum(1 for d in result.diagnostics if d.severity == Severity.ERROR)
    warnings = sum(1 for d in result.diagnostics if d.severity == Severity.WARNING)
    files = len({d.file_path for d in result.diagnostics})

    summary = Text()
    summary.append(f"\n{face}\n\n", style="bold")
    summary.append("  Score: ", style="dim")
    summary.append(f"{result.score.value}/100", style=f"bold {color}")
    summary.append(f" — {result.score.label}\n", style=color)
    summary.append(f"{format_score_bar(result.score.value)}\n\n")
    summary.append(f"  {errors} errors, {warnings} warnings across {files} files\n", style="dim")
    summary.append(f"  Completed in {result.elapsed_ms}ms\n", style="dim")

    console.print(Panel(summary, title="[bold]Results[/bold]", border_style=color))
    console.print()


def output_json(result: ScanResult) -> None:
    """Output the scan result as structured JSON to stdout."""
    p = result.project
    errors = sum(1 for d in result.diagnostics if d.severity == Severity.ERROR)
    warnings = sum(1 for d in result.diagnostics if d.severity == Severity.WARNING)

    payload = {
        "version": __version__,
        "path": p.path,
        "score": result.score.value,
        "label": result.score.label,
        "profile": result.profile,
        "errors": errors,
        "warnings": warnings,
        "elapsed_ms": result.elapsed_ms,
        "project": {
            "framework": p.framework,
            "python_version": p.python_version,
            "package_manager": p.package_manager,
            "test_framework": p.test_framework,
            "source_file_count": p.source_file_count,
        },
        "diagnostics": [
            {
                "rule": d.rule,
                "severity": d.severity.value,
                "category": d.category.value,
                "message": d.message,
                "help": d.help,
                "file_path": d.file_path,
                "line": d.line,
            }
            for d in result.diagnostics
        ],
    }
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")


def _sarif_rules(diagnostics: list[Diagnostic]) -> list[dict]:
    """Build SARIF rules registry from unique diagnostic rules."""
    seen: dict[str, Diagnostic] = {}
    for d in diagnostics:
        if d.rule not in seen:
            seen[d.rule] = d
    return [
        {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": diag.message},
            "helpUri": "",
            "help": {"text": diag.help},
        }
        for rule_id, diag in seen.items()
    ]


def _sarif_location(diag: Diagnostic) -> dict:
    """Build a SARIF physicalLocation, omitting the region for project-level findings.

    SARIF 2.1.0 requires region.startLine >= 1, so a line of 0 (project-level
    diagnostics) points at the artifact only rather than an invalid line 0.
    """
    physical: dict = {"artifactLocation": {"uri": diag.file_path}}
    if diag.line and diag.line >= 1:
        physical["region"] = {"startLine": diag.line, "startColumn": (diag.column or 0) + 1}
    return {"physicalLocation": physical}


def _sarif_results(diagnostics: list[Diagnostic]) -> list[dict]:
    """Build SARIF results array from diagnostics."""
    return [
        {
            "ruleId": d.rule,
            "level": "error" if d.severity == Severity.ERROR else "warning",
            "message": {"text": d.message},
            "locations": [_sarif_location(d)],
        }
        for d in diagnostics
    ]


def output_sarif(result: ScanResult) -> None:
    """Output the scan result in SARIF 2.1.0 format for GitHub Code Scanning."""
    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PyCodeGate",
                        "version": __version__,
                        "rules": _sarif_rules(result.diagnostics),
                    }
                },
                "results": _sarif_results(result.diagnostics),
            }
        ],
    }
    sys.stdout.write(json.dumps(sarif, indent=2) + "\n")


def _print_rule_details(
    console: Console,
    rule_diags: list[Diagnostic],
    verbose: bool,
) -> None:
    """Print a single rule line and, in verbose mode, the file locations."""
    rule = rule_diags[0].rule
    count = len(rule_diags)
    sev = rule_diags[0].severity
    icon = "[red]✗[/red]" if sev == Severity.ERROR else "[yellow]⚠[/yellow]"
    console.print(f"    {icon} {rule} × {count}")
    if not verbose:
        return
    for d in rule_diags[:10]:
        console.print(f"      [dim]{d.file_path}:{d.line}[/dim]")
    if count > 10:
        console.print(f"      [dim]... and {count - 10} more[/dim]")


def _print_category_with_issues(
    console: Console,
    emoji: str,
    name: str,
    earned: int,
    maximum: int,
    cat_diags: list[Diagnostic],
    verbose: bool,
) -> None:
    """Print a category header and its grouped rule findings."""
    console.print(f"  [bold]{emoji} {name}[/bold] [yellow]({earned}/{maximum})[/yellow]")
    by_rule: dict[str, list[Diagnostic]] = defaultdict(list)
    for d in cat_diags:
        by_rule[d.rule].append(d)
    sorted_rules = sorted(
        by_rule.keys(),
        key=lambda r: (0 if by_rule[r][0].severity == Severity.ERROR else 1, r),
    )
    for rule in sorted_rules:
        _print_rule_details(console, by_rule[rule], verbose)


def _print_category_groups(
    console: Console,
    diagnostics: list[Diagnostic],
    sub_scores: dict[Category, tuple[int, int]],
    verbose: bool,
) -> None:
    """Print diagnostics grouped by category with sub-scores."""
    # Build rule-grouped diagnostics per resolved category
    by_category: dict[Category, list[Diagnostic]] = defaultdict(list)
    for d in diagnostics:
        resolved = FRAMEWORK_CATEGORY_MAP.get(d.category, d.category)
        by_category[resolved].append(d)

    # Iterate in canonical order (CATEGORY_WEIGHTS order)
    for cat in CATEGORY_WEIGHTS:
        if cat not in CATEGORY_DISPLAY:
            continue
        emoji, name = CATEGORY_DISPLAY[cat]
        earned, maximum = sub_scores.get(cat, (CATEGORY_WEIGHTS[cat], CATEGORY_WEIGHTS[cat]))
        cat_diags = by_category.get(cat, [])

        if not cat_diags:
            console.print(
                f"  [bold]{emoji} {name}[/bold] "
                f"[green]({earned}/{maximum})[/green] [green]✓[/green]"
            )
            console.print("    [green]✓ All clear.[/green]")
        else:
            _print_category_with_issues(console, emoji, name, earned, maximum, cat_diags, verbose)

        console.print()
