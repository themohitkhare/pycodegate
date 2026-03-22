"""Programmatic API for python-doctor."""

from __future__ import annotations

from typing import TYPE_CHECKING

from python_doctor.config import load_config
from python_doctor.scan import scan_project

if TYPE_CHECKING:
    from python_doctor.types import ScanResult


def diagnose(
    project_path: str = ".",
    *,
    lint: bool = True,
    dead_code: bool = True,
    diff_base: str | None = None,
) -> ScanResult:
    """Run python-doctor analysis programmatically."""
    config = load_config(project_path)
    config.lint = lint
    config.dead_code = dead_code

    return scan_project(project_path, config, diff_base=diff_base)
