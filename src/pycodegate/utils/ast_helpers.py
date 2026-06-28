"""Common AST traversal utilities."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def parse_file(file_path: Path) -> tuple[str, ast.Module | None]:
    """Read and parse a Python file. Returns (source, tree) or (source, None) on error."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(source)
        return source, tree
    except (SyntaxError, UnicodeDecodeError):
        return "", None


def imported_modules(tree: ast.Module) -> set[str]:
    """Return the set of top-level module roots imported anywhere in *tree*.

    ``import pandas as pd`` and ``from pandas import X`` both yield ``"pandas"``.
    """
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots
