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
    # Not the project's own production code — generated, illustrative, or vendored.
    "migrations",
    "examples",
    "example",
    "docs",
    "docs_src",
    "vendor",
    "vendored",
    "_vendor",
    "third_party",
}


def _is_excluded(relative_parts: tuple[str, ...]) -> bool:
    """True if any path component is an ignored directory."""
    return any(part in IGNORE_DIRS or part.endswith(".egg-info") for part in relative_parts)


def find_python_files(project_path: str) -> list[Path]:
    """Find all Python files in the project, respecting gitignore and excluded dirs."""
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
            return [
                root / f
                for f in result.stdout.strip().splitlines()
                if f.endswith(".py") and not _is_excluded(Path(f).parts)
            ]
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    # Fallback: walk filesystem
    return _walk_for_python_files(root)


def _walk_for_python_files(root: Path) -> list[Path]:
    return [path for path in root.rglob("*.py") if not _is_excluded(path.relative_to(root).parts)]
