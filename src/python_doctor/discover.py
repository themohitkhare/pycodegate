"""Project discovery: detect framework, Python version, package manager, etc."""

from __future__ import annotations

import re
from pathlib import Path

from python_doctor._compat import tomllib

from python_doctor.types import ProjectInfo
from python_doctor.utils.file_discovery import find_python_files


def discover_project(project_path: str) -> ProjectInfo:
    """Auto-detect project characteristics."""
    root = Path(project_path)
    deps = _collect_all_deps(root)

    return ProjectInfo(
        path=project_path,
        python_version=_detect_python_version(root),
        framework=_detect_framework(deps),
        package_manager=_detect_package_manager(root),
        test_framework=_detect_test_framework(deps),
        has_type_hints=_detect_type_hints(root),
        source_file_count=len(find_python_files(project_path)),
    )


def _collect_all_deps(root: Path) -> set[str]:
    """Collect dependency names from all sources."""
    deps: set[str] = set()

    # pyproject.toml
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        with open(pyproject, "rb") as f:
            data = tomllib.load(f)
        project = data.get("project", {})
        for dep in project.get("dependencies", []):
            deps.add(_parse_dep_name(dep))
        for group_deps in project.get("optional-dependencies", {}).values():
            for dep in group_deps:
                deps.add(_parse_dep_name(dep))
        # Poetry format
        poetry = data.get("tool", {}).get("poetry", {})
        for dep in poetry.get("dependencies", {}):
            deps.add(dep.lower())
        for group in poetry.get("group", {}).values():
            for dep in group.get("dependencies", {}):
                deps.add(dep.lower())

    # requirements.txt
    for req_file in ["requirements.txt", "requirements-dev.txt", "requirements_dev.txt"]:
        req_path = root / req_file
        if req_path.exists():
            for line in req_path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith(("#", "-")):
                    deps.add(_parse_dep_name(line))

    return deps


def _parse_dep_name(dep_str: str) -> str:
    """Extract package name from a dependency specifier like 'django>=4.2'."""
    return re.split(r"[><=!~\[;@\s]", dep_str)[0].strip().lower()


def _detect_framework(deps: set[str]) -> str | None:
    if "django" in deps or "django-rest-framework" in deps or "djangorestframework" in deps:
        return "django"
    if "fastapi" in deps:
        return "fastapi"
    if "flask" in deps:
        return "flask"
    return None


def _detect_package_manager(root: Path) -> str | None:
    if (root / "uv.lock").exists():
        return "uv"
    if (root / "poetry.lock").exists():
        return "poetry"
    if (root / "Pipfile.lock").exists():
        return "pipenv"
    if (root / "requirements.txt").exists():
        return "pip"
    if (root / "pyproject.toml").exists():
        return "pip"
    return None


def _detect_test_framework(deps: set[str]) -> str | None:
    if "pytest" in deps:
        return "pytest"
    if "unittest" in deps:
        return "unittest"
    return None


def _detect_python_version(root: Path) -> str | None:
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        with open(pyproject, "rb") as f:
            data = tomllib.load(f)
        requires = data.get("project", {}).get("requires-python", "")
        match = re.search(r"(\d+\.\d+)", requires)
        if match:
            return match.group(1)
    return None


def _detect_type_hints(root: Path) -> bool:
    return (root / "py.typed").exists() or (root / "mypy.ini").exists()
