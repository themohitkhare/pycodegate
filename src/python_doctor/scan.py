"""Scan orchestration: runs lint + dead code in parallel, produces ScanResult."""

from __future__ import annotations

import fnmatch
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING

from python_doctor.discover import discover_project
from python_doctor.rules import get_all_rule_sets, get_framework_rules
from python_doctor.rules.dead_code import DeadCodeRules
from python_doctor.score import calculate_score
from python_doctor.types import Diagnostic, ScanResult
from python_doctor.utils.diff import get_changed_files
from python_doctor.utils.file_discovery import find_python_files

if TYPE_CHECKING:
    from python_doctor.config import Config


def scan_project(
    project_path: str,
    config: Config,
    diff_base: str | None = None,
) -> ScanResult:
    """Run full scan and return results."""
    start = time.monotonic()
    project = discover_project(project_path)
    files = _resolve_files(project_path, diff_base)
    all_diags = _run_checks(files, project.framework, project_path, config)
    all_diags = _apply_filters(all_diags, config, project_path)
    score = calculate_score(all_diags)
    elapsed = int((time.monotonic() - start) * 1000)

    return ScanResult(
        score=score,
        diagnostics=all_diags,
        project=project,
        elapsed_ms=elapsed,
    )


def _resolve_files(project_path: str, diff_base: str | None) -> list[Path]:
    """Determine which files to scan."""
    if diff_base:
        files = get_changed_files(project_path, diff_base)
        if files is not None:
            return files
    return find_python_files(project_path)


def _run_checks(
    files: list[Path],
    framework: str | None,
    project_path: str,
    config: Config,
) -> list[Diagnostic]:
    """Run lint + dead code in parallel."""
    with ThreadPoolExecutor(max_workers=2) as executor:
        lint_future = executor.submit(_run_lint, files, framework, config) if config.lint else None
        dead_code_future = (
            executor.submit(_run_dead_code, project_path, config) if config.dead_code else None
        )

        lint_diags = lint_future.result() if lint_future else []
        dead_code_diags = dead_code_future.result() if dead_code_future else []

    return lint_diags + dead_code_diags


def _apply_filters(
    diags: list[Diagnostic],
    config: Config,
    project_path: str = ".",
) -> list[Diagnostic]:
    """Apply ignore_rules and ignore_files filters."""
    if config.ignore_rules:
        diags = [d for d in diags if d.rule not in config.ignore_rules]
    if config.ignore_files:
        root = Path(project_path).resolve()
        diags = [d for d in diags if not _matches_ignore(d.file_path, config.ignore_files, root)]
    return diags


def _matches_ignore(file_path: str, patterns: list[str], root: Path) -> bool:
    """Check if a file path matches any ignore pattern (absolute or relative)."""
    p = Path(file_path)
    # Try relative path from project root
    try:
        rel = str(p.resolve().relative_to(root))
    except ValueError:
        rel = file_path
    return any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(file_path, pat) for pat in patterns)


def _run_lint(
    files: list[Path],
    framework: str | None,
    config: Config,
) -> list[Diagnostic]:
    """Run all rule sets against all files."""
    rule_sets = get_all_rule_sets() + get_framework_rules(framework)
    diags: list[Diagnostic] = []

    for file_path in files:
        try:
            source = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue

        for rules in rule_sets:
            diags.extend(rules.check(source, str(file_path)))

    return diags


def _run_dead_code(project_path: str, config: Config) -> list[Diagnostic]:
    """Run dead code detection."""
    return DeadCodeRules().check_project(project_path)
