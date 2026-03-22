"""Configuration loading for python-doctor."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    lint: bool = True
    dead_code: bool = True
    verbose: bool = False
    fail_on: str = "none"
    ignore_rules: list[str] = field(default_factory=list)
    ignore_files: list[str] = field(default_factory=list)


def load_config(project_path: str) -> Config:
    """Load config from python-doctor.toml or pyproject.toml [tool.python-doctor]."""
    root = Path(project_path)

    # python-doctor.toml takes precedence
    doctor_toml = root / "python-doctor.toml"
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
    )


def _parse_pyproject_toml(path: Path) -> Config:
    with open(path, "rb") as f:
        data = tomllib.load(f)

    section = data.get("tool", {}).get("python-doctor", {})
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
    )
