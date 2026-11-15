"""Configuration loading for pycodegate."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from pycodegate._compat import tomllib
from pycodegate.types import ImportBoundary


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
    import_boundaries: list[ImportBoundary] = field(default_factory=list)


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
        import_boundaries=_read_import_boundaries(data),
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
        import_boundaries=_read_import_boundaries(section),
    )


def _read_per_file_suppress(table: dict) -> dict:
    """Read per-file rule suppression, accepting the documented ``per-file-ignores`` alias."""
    return table.get("per-file-suppress") or table.get("per-file-ignores") or {}


def _read_import_boundaries(table: dict) -> list[ImportBoundary]:
    boundaries = table.get("import-boundaries", [])
    if not isinstance(boundaries, list):
        raise ValueError("import-boundaries must be an array of tables")
    result = []
    for boundary in boundaries:
        if not isinstance(boundary, dict):
            raise ValueError("Each import boundary must be a table")
        for key in ("files", "forbidden"):
            values = boundary.get(key)
            if not isinstance(values, list) or not values:
                raise ValueError(f"Import boundary {key} must be a nonempty array of strings")
            if any(not isinstance(value, str) or not value.strip() for value in values):
                raise ValueError(f"Import boundary {key} must contain nonempty strings")
        message = boundary.get("message", "Move shared code behind the allowed layer's API")
        if any(
            not all(part.isidentifier() for part in module.split("."))
            for module in boundary["forbidden"]
        ):
            raise ValueError("Import boundary forbidden entries must be dotted module names")
        if not isinstance(message, str) or not message.strip():
            raise ValueError("Import boundary message must be a nonempty string")
        result.append(
            ImportBoundary(tuple(boundary["files"]), tuple(boundary["forbidden"]), message)
        )
    return result


def _read_max_deduction(table: dict) -> dict:
    """Read scoring max-deduction overrides.

    Documented location is the ``[scoring]`` table (``max-deduction.Security = 20``);
    the historical top-level ``[max-deduction]`` table is still accepted.
    """
    scoring = table.get("scoring", {})
    if isinstance(scoring, dict) and "max-deduction" in scoring:
        return scoring["max-deduction"]
    return table.get("max-deduction", {})
