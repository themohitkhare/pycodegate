"""Project profile detection and rule/scoring adjustments."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from pycodegate._compat import tomllib


@dataclass(frozen=True)
class Profile:
    name: str  # "cli", "web", "library", "script"
    suppressed_rules: frozenset[str] = field(default_factory=frozenset)
    max_deduction_overrides: dict[str, int] = field(default_factory=dict)


# Profile definitions
PROFILES = {
    "web": Profile(name="web"),
    "cli": Profile(
        name="cli",
        suppressed_rules=frozenset({"no-os-system", "no-subprocess-shell"}),
        max_deduction_overrides={"Security": 15},
    ),
    "library": Profile(name="library"),
    "script": Profile(
        name="script",
        suppressed_rules=frozenset({"structure/no-tests", "structure/no-license"}),
        max_deduction_overrides={"Structure": 5},
    ),
}


def _normalise_dep(dep: str) -> str:
    """Strip version specifiers and extras from a dependency string."""
    return dep.split("[")[0].split(">")[0].split("<")[0].split("=")[0].split("!")[0].strip().lower()


def _deps_from_pyproject(pyproject: Path) -> tuple[set[str], bool, bool]:
    """Parse pyproject.toml and return (deps, has_build_system, has_scripts)."""
    deps: set[str] = set()
    has_build_system = False
    has_scripts = False
    try:
        with open(pyproject, "rb") as f:
            data = tomllib.load(f)
        for dep in data.get("project", {}).get("dependencies", []):
            deps.add(_normalise_dep(dep))
        has_build_system = "build-system" in data
        has_scripts = bool(data.get("project", {}).get("scripts"))
    except (OSError, ValueError, KeyError):
        pass
    return deps, has_build_system, has_scripts


def _deps_from_requirements(path: Path) -> set[str]:
    """Parse requirements files and return the set of normalised dep names."""
    deps: set[str] = set()
    for req_file in ["requirements.txt", "requirements-dev.txt"]:
        req_path = path / req_file
        if not req_path.exists():
            continue
        try:
            for line in req_path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("-"):
                    deps.add(_normalise_dep(line))
        except (OSError, ValueError):
            pass
    return deps


def _classify_by_deps(deps: set[str], has_scripts: bool) -> str | None:
    """Return a profile name based on dependencies, or None if undetermined."""
    web_deps = {"flask", "django", "fastapi", "starlette", "tornado", "aiohttp", "sanic", "bottle"}
    if deps & web_deps:
        return "web"
    cli_deps = {"click", "typer", "fire", "cement", "cliff", "argparse"}
    if (deps & cli_deps) or has_scripts:
        return "cli"
    return None


def detect_profile(project_path: str) -> Profile:
    """Auto-detect project profile from project structure and dependencies."""
    path = Path(project_path)
    pyproject = path / "pyproject.toml"

    deps: set[str] = set()
    has_build_system = False
    has_scripts = False

    if pyproject.exists():
        pyproject_deps, has_build_system, has_scripts = _deps_from_pyproject(pyproject)
        deps |= pyproject_deps

    deps |= _deps_from_requirements(path)

    profile_name = _classify_by_deps(deps, has_scripts)
    if profile_name is not None:
        return PROFILES[profile_name]

    if has_build_system and not has_scripts:
        return PROFILES["library"]

    # Script: no __init__.py and few .py files
    py_files = list(path.glob("*.py"))
    has_init = (path / "__init__.py").exists() or any(
        (path / d / "__init__.py").exists() for d in ["src", "lib"]
    )
    if not has_init and len(py_files) <= 5:
        return PROFILES["script"]

    return PROFILES["library"]
