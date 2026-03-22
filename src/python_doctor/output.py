"""Rich terminal output: score bar, doctor face, framed summary, category-grouped diagnostics."""

from __future__ import annotations

import json
import sys
from collections import defaultdict

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from python_doctor import __version__
from python_doctor.constants import CATEGORY_WEIGHTS, FRAMEWORK_CATEGORY_MAP
from python_doctor.types import Category, Diagnostic, ScanResult, Severity

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


def _compute_category_sub_scores(
    diagnostics: list[Diagnostic],
) -> dict[Category, tuple[int, int]]:
    """Return {resolved_category: (earned, max)} for each category in CATEGORY_WEIGHTS."""
    total_weight = sum(CATEGORY_WEIGHTS.values())
    max_deductions = {cat: round(w / total_weight * 100) for cat, w in CATEGORY_WEIGHTS.items()}
    # Fix rounding to ensure sum == 100
    diff = 100 - sum(max_deductions.values())
    if diff != 0:
        highest = max(CATEGORY_WEIGHTS, key=lambda k: CATEGORY_WEIGHTS[k])
        max_deductions[highest] += diff

    # Group diagnostics by resolved category
    by_category: dict[Category, list[Diagnostic]] = defaultdict(list)
    for d in diagnostics:
        resolved = FRAMEWORK_CATEGORY_MAP.get(d.category, d.category)
        by_category[resolved].append(d)

    # Compute actual deduction per category (same logic as score.py)
    actual_deductions: dict[Category, float] = {}
    for cat, diags in by_category.items():
        costs = sorted([d.cost for d in diags], reverse=True)
        cat_total = sum(c if i < 3 else c * 0.1 for i, c in enumerate(costs))
        cap = max_deductions.get(cat, 10)
        actual_deductions[cat] = min(cat_total, cap)

    # Build (earned, max) per category
    result: dict[Category, tuple[int, int]] = {}
    for cat, max_ded in max_deductions.items():
        deducted = round(actual_deductions.get(cat, 0.0))
        earned = max_ded - deducted
        result[cat] = (earned, max_ded)

    return result


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
    console.print("  [bold]Py Gate[/bold] — v0.1.0")
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

    # Category-grouped diagnostics with sub-scores
    _print_category_groups(console, result.diagnostics, verbose)

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


def _print_category_groups(
    console: Console,
    diagnostics: list[Diagnostic],
    verbose: bool,
) -> None:
    """Print diagnostics grouped by category with sub-scores."""
    sub_scores = _compute_category_sub_scores(diagnostics)

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
        # Recompute max from sub_scores (already normalised to 100-point scale)
        cat_diags = by_category.get(cat, [])

        if earned == maximum:
            # Perfect score for this category
            console.print(
                f"  [bold]{emoji} {name}[/bold] "
                f"[green]({earned}/{maximum})[/green] [green]✓[/green]"
            )
            console.print("    [green]✓ All clear.[/green]")
        else:
            console.print(f"  [bold]{emoji} {name}[/bold] [yellow]({earned}/{maximum})[/yellow]")
            # Group by rule within this category
            by_rule: dict[str, list[Diagnostic]] = defaultdict(list)
            for d in cat_diags:
                by_rule[d.rule].append(d)

            # Sort: errors first, then by rule name
            sorted_rules = sorted(
                by_rule.keys(),
                key=lambda r: (0 if by_rule[r][0].severity == Severity.ERROR else 1, r),
            )
            for rule in sorted_rules:
                rule_diags = by_rule[rule]
                count = len(rule_diags)
                sev = rule_diags[0].severity
                icon = "[red]✗[/red]" if sev == Severity.ERROR else "[yellow]⚠[/yellow]"
                console.print(f"    {icon} {rule} × {count}")
                if verbose:
                    for d in rule_diags[:10]:
                        console.print(f"      [dim]{d.file_path}:{d.line}[/dim]")
                    if count > 10:
                        console.print(f"      [dim]... and {count - 10} more[/dim]")

        console.print()
