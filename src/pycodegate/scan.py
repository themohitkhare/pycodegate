"""Scan orchestration: runs lint + dead code in parallel, produces ScanResult."""

from __future__ import annotations

import ast
import fnmatch
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING

from pycodegate.constants import RULES_SUPPRESSED_IN_TESTS
from pycodegate.discover import discover_project
from pycodegate.profile import PROFILES, detect_profile
from pycodegate.rules import get_all_rule_sets, get_import_gated_rules
from pycodegate.rules.dead_code import DeadCodeRules
from pycodegate.rules.dependencies import DependencyRules
from pycodegate.rules.imports import ImportsRules
from pycodegate.rules.structure import StructureRules
from pycodegate.score import calculate_score, category_breakdown
from pycodegate.types import Diagnostic, ScanResult
from pycodegate.utils.ast_helpers import imported_modules
from pycodegate.utils.diff import get_changed_files
from pycodegate.utils.file_discovery import find_python_files
from pycodegate.utils.is_test_file import is_test_file

if TYPE_CHECKING:
    from pycodegate.config import Config


def scan_project(
    project_path: str,
    config: Config,
    diff_base: str | None = None,
) -> ScanResult:
    """Run full scan and return results."""
    start = time.monotonic()
    project = discover_project(project_path)

    # Resolve profile: config/CLI override takes precedence over auto-detection
    if config.profile and config.profile in PROFILES:
        profile = PROFILES[config.profile]
    else:
        profile = detect_profile(project_path)

    files = _resolve_files(project_path, diff_base)
    all_diags = _run_checks(files, project_path, config)
    all_diags = _suppress_test_noise(all_diags, project_path)
    all_diags = _apply_filters(all_diags, config, project_path, profile.suppressed_rules)
    max_deduction_overrides = _build_max_deduction_overrides(
        profile.max_deduction_overrides, config.max_deduction
    )
    score = calculate_score(all_diags, max_deduction_overrides=max_deduction_overrides)
    category_scores = category_breakdown(all_diags, max_deduction_overrides=max_deduction_overrides)
    elapsed = int((time.monotonic() - start) * 1000)

    return ScanResult(
        score=score,
        diagnostics=all_diags,
        project=project,
        elapsed_ms=elapsed,
        profile=profile.name,
        category_scores=category_scores,
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
    project_path: str,
    config: Config,
) -> list[Diagnostic]:
    """Run lint + dead code + imports + structure + dependency checks in parallel."""
    str_files = [str(f) for f in files]
    with ThreadPoolExecutor(max_workers=5) as executor:
        lint_future = executor.submit(_run_lint, files, config) if config.lint else None
        dead_code_future = (
            executor.submit(_run_dead_code, project_path, config) if config.dead_code else None
        )
        imports_future = (
            executor.submit(_run_imports, project_path, str_files) if str_files else None
        )
        structure_future = (
            executor.submit(_run_structure, project_path, str_files)
            if config.lint and str_files
            else None
        )
        dependencies_future = executor.submit(_run_dependencies, project_path)

        lint_diags = lint_future.result() if lint_future else []
        dead_code_diags = dead_code_future.result() if dead_code_future else []
        imports_diags = imports_future.result() if imports_future else []
        structure_diags = structure_future.result() if structure_future else []
        dependencies_diags = dependencies_future.result()

    return lint_diags + dead_code_diags + imports_diags + structure_diags + dependencies_diags


def _suppress_test_noise(diags: list[Diagnostic], project_path: str) -> list[Diagnostic]:
    """Drop findings that are idiomatic in test files (asserts, long tests, fixtures).

    Test detection runs on the project-relative path so a project that merely lives
    under a directory named ``tests`` is not mistaken for test code wholesale.
    """
    root = Path(project_path).resolve()

    def relative(file_path: str) -> str:
        try:
            return str(Path(file_path).resolve().relative_to(root))
        except ValueError:
            return file_path

    return [
        d
        for d in diags
        if not (d.rule in RULES_SUPPRESSED_IN_TESTS and is_test_file(relative(d.file_path)))
    ]


def _apply_filters(
    diags: list[Diagnostic],
    config: Config,
    project_path: str = ".",
    suppressed_rules: frozenset[str] | None = None,
) -> list[Diagnostic]:
    """Apply ignore_rules, profile suppressed_rules, ignore_files, and per_file_suppress filters."""
    combined_ignore = set(config.ignore_rules)
    if suppressed_rules:
        combined_ignore |= suppressed_rules
    if combined_ignore:
        diags = [d for d in diags if d.rule not in combined_ignore]
    root = Path(project_path).resolve()
    if config.ignore_files:
        diags = [d for d in diags if not _matches_ignore(d.file_path, config.ignore_files, root)]
    if config.per_file_suppress:
        diags = [
            d for d in diags if not _matches_per_file_suppress(d, config.per_file_suppress, root)
        ]
    return diags


def _matches_per_file_suppress(
    d: Diagnostic, per_file_suppress: dict[str, list[str]], root: Path
) -> bool:
    """Check if a diagnostic is suppressed by per_file_suppress config."""
    p = Path(d.file_path)
    try:
        rel = str(p.resolve().relative_to(root))
    except ValueError:
        rel = d.file_path
    return any(
        d.rule in rules and (fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(d.file_path, pat))
        for pat, rules in per_file_suppress.items()
    )


def _build_max_deduction_overrides(
    profile_overrides: dict[str, int], config_overrides: dict[str, int]
) -> dict[str, int] | None:
    """Merge profile and config max_deduction overrides, config takes precedence.

    Profile overrides use title-case keys (e.g. "Security").
    Config overrides use lowercase keys (e.g. "security") which are title-cased here.
    """
    merged: dict[str, int] = dict(profile_overrides)
    for key, val in config_overrides.items():
        merged[key.title()] = val
    return merged or None


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
    config: Config,
) -> list[Diagnostic]:
    """Run core rules on every file; library rules only on files importing the library."""
    core_rules = get_all_rule_sets()
    gated_rules = get_import_gated_rules()
    diags: list[Diagnostic] = []

    for file_path in files:
        try:
            source = file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue

        filename = str(file_path)
        for rules in core_rules:
            diags.extend(rules.check(source, filename))

        try:
            file_imports = imported_modules(ast.parse(source))
        except (SyntaxError, ValueError):
            continue
        for rules, trigger in gated_rules:
            if trigger in file_imports:
                diags.extend(rules.check(source, filename))

    return diags


def _run_dead_code(project_path: str, config: Config) -> list[Diagnostic]:
    """Run dead code detection."""
    return DeadCodeRules().check_project(project_path)


def _run_imports(project_path: str, source_files: list[str]) -> list[Diagnostic]:
    """Run circular import detection."""
    return ImportsRules().check_project(project_path, source_files)


def _run_structure(project_path: str, source_files: list[str]) -> list[Diagnostic]:
    """Run project-level structure checks."""
    return StructureRules().check_project(project_path, source_files)


def _run_dependencies(project_path: str) -> list[Diagnostic]:
    """Run dependency vulnerability checks."""
    return DependencyRules().check_project(project_path)
