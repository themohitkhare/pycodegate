"""Configuration loading for pycodegate."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from pycodegate._compat import tomllib


@dataclass
class Config:
    lint: bool = True
    dead_code: bool = True
    verbose: bool = False
    fail_on: str = "none"
    ignore_rules: list[str] = field(default_factory=list)
    ignore_files: list[str] = field(default_factory=list)
    profile: str | None = None
    per_file_suppress: dict[str, list[str]] = field(default_factory=dict)
    max_deduction: dict[str, int] = field(default_factory=dict)


def load_config(project_path: str) -> Config:
    """Load config from pycodegate.toml or pyproject.toml [tool.pycodegate]."""
    root = Path(project_path)

    # pycodegate.toml takes precedence
    doctor_toml = root / "pycodegate.toml"
    if doctor_toml.exists():
        return _parse_doctor_toml(doctor_toml)

    # Fall back to pyproject.toml
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        return _parse_pyproject_toml(pyproject)

    return Config()


def _parse_doctor_toml(path: Path) -> Config:
    with open(path, "rb") as f:
        data = tomllib.load(f)

    options = data.get("options", {})
    ignore = data.get("ignore", {})

    return Config(
        lint=options.get("lint", True),
        dead_code=options.get("dead_code", True),
        verbose=options.get("verbose", False),
        fail_on=options.get("fail_on", "none"),
        ignore_rules=ignore.get("rules", []),
        ignore_files=ignore.get("files", []),
        profile=options.get("profile", None),
        per_file_suppress=_read_per_file_suppress(data),
        max_deduction=_read_max_deduction(data),
    )


def _parse_pyproject_toml(path: Path) -> Config:
    with open(path, "rb") as f:
        data = tomllib.load(f)

    section = data.get("tool", {}).get("pycodegate", {})
    if not section:
        return Config()

    ignore = section.get("ignore", {})

    return Config(
        lint=section.get("lint", True),
        dead_code=section.get("dead_code", True),
        verbose=section.get("verbose", False),
        fail_on=section.get("fail_on", "none"),
        ignore_rules=ignore.get("rules", []),
        ignore_files=ignore.get("files", []),
        profile=section.get("profile", None),
        per_file_suppress=_read_per_file_suppress(section),
        max_deduction=_read_max_deduction(section),
    )


def _read_per_file_suppress(table: dict) -> dict:
    """Read per-file rule suppression, accepting the documented ``per-file-ignores`` alias."""
    return table.get("per-file-suppress") or table.get("per-file-ignores") or {}


def _read_max_deduction(table: dict) -> dict:
    """Read scoring max-deduction overrides.

    Documented location is the ``[scoring]`` table (``max-deduction.Security = 20``);
    the historical top-level ``[max-deduction]`` table is still accepted.
    """
    scoring = table.get("scoring", {})
    if isinstance(scoring, dict) and "max-deduction" in scoring:
        return scoring["max-deduction"]
    return table.get("max-deduction", {})
