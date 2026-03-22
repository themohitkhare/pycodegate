"""File discovery utilities."""

from __future__ import annotations

import subprocess
from pathlib import Path

IGNORE_DIRS = {
    ".venv",
    "venv",
    "env",
    ".env",
    "node_modules",
    "__pycache__",
    ".git",
    ".hg",
    ".svn",
    "dist",
    "build",
    ".eggs",
    "*.egg-info",
    ".tox",
    ".nox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "htmlcov",
    "site-packages",
}


def find_python_files(project_path: str) -> list[Path]:
    """Find all Python files in the project, respecting gitignore."""
    root = Path(project_path)

    # Try git ls-files first
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "*.py"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return [root / f for f in result.stdout.strip().splitlines() if f.endswith(".py")]
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    # Fallback: walk filesystem
    return _walk_for_python_files(root)


def _walk_for_python_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*.py"):
        if not any(
            part in IGNORE_DIRS or part.endswith(".egg-info")
            for part in path.relative_to(root).parts
        ):
            files.append(path)
    return files
