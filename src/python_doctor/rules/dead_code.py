"""Dead code detection via vulture."""

from __future__ import annotations

import io
import contextlib
from pathlib import Path

from python_doctor.types import Category, Diagnostic, Severity


class DeadCodeRules:
    """Detect unused code using vulture."""

    def check_project(self, project_path: str) -> list[Diagnostic]:
        """Run vulture on the entire project and return diagnostics."""
        try:
            import vulture
        except ImportError:
            return []

        v = vulture.Vulture()

        py_files = list(Path(project_path).rglob("*.py"))
        ignore = {".venv", "venv", "node_modules", "__pycache__", ".git", "dist", "build"}
        py_files = [
            f for f in py_files
            if not any(part in ignore for part in f.relative_to(project_path).parts)
        ]

        if not py_files:
            return []

        v.scavenge([str(f) for f in py_files])

        diags: list[Diagnostic] = []
        for item in v.get_unused_code():
            diags.append(Diagnostic(
                file_path=str(item.filename),
                rule="dead-code",
                severity=Severity.WARNING,
                category=Category.DEAD_CODE,
                message=f"Unused {item.typ}: '{item.name}' ({item.confidence}% confidence)",
                help="Remove this dead code or add it to a vulture whitelist",
                line=item.first_lineno,
            ))
        return diags
