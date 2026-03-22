"""Rich terminal output: score bar, doctor face, framed summary, diagnostic groups."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from python_doctor.types import Diagnostic, ScanResult, Severity

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


def format_score_bar(score: int) -> str:
    """Return a text-based score bar."""
    filled = round(score / 100 * BAR_WIDTH)
    empty = BAR_WIDTH - filled
    bar = "█" * filled + "░" * empty
    return f"  {bar} {score}/100"


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

    # Project info
    p = result.project
    console.print()
    console.print("  [bold]Python Doctor[/bold] — v0.1.0")
    console.print()
    console.print(f"  [dim]Path:[/dim]            {p.path}")
    if p.framework:
        console.print(f"  [dim]Framework:[/dim]       {p.framework}")
    if p.python_version:
        console.print(f"  [dim]Python:[/dim]          {p.python_version}")
    if p.package_manager:
        console.print(f"  [dim]Package manager:[/dim] {p.package_manager}")
    if p.test_framework:
        console.print(f"  [dim]Test framework:[/dim]  {p.test_framework}")
    console.print(f"  [dim]Source files:[/dim]    {p.source_file_count}")
    console.print()

    # Diagnostics grouped by rule
    if result.diagnostics:
        _print_diagnostics(console, result.diagnostics, verbose)

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


def _print_diagnostics(console: Console, diagnostics: list[Diagnostic], verbose: bool) -> None:
    """Print diagnostics grouped by rule, sorted by severity."""
    groups: dict[str, list[Diagnostic]] = {}
    for d in diagnostics:
        groups.setdefault(d.rule, []).append(d)

    sorted_rules = sorted(
        groups.keys(),
        key=lambda r: (0 if groups[r][0].severity == Severity.ERROR else 1, r),
    )

    for rule in sorted_rules:
        diags = groups[rule]
        first = diags[0]
        icon = "[red]✗[/red]" if first.severity == Severity.ERROR else "[yellow]⚠[/yellow]"
        count = len(diags)

        console.print(f"  {icon} [bold]{first.message}[/bold]  [dim]({rule} × {count})[/dim]")
        if first.help:
            console.print(f"    [dim]{first.help}[/dim]")

        if verbose:
            for d in diags[:10]:
                console.print(f"    [dim]{d.file_path}:{d.line}[/dim]")
            if count > 10:
                console.print(f"    [dim]... and {count - 10} more[/dim]")

        console.print()
