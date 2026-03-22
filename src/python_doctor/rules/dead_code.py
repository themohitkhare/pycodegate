"""Dead code detection via vulture."""

from __future__ import annotations

from pathlib import Path

try:
    import vulture
except ImportError:
    vulture = None  # type: ignore[assignment]

from python_doctor.types import Category, Diagnostic, Severity


class DeadCodeRules:
    """Detect unused code using vulture."""

    def check_project(self, project_path: str) -> list[Diagnostic]:
        """Run vulture on the entire project and return diagnostics."""
        if vulture is None:
            return []

        v = vulture.Vulture()

        py_files = list(Path(project_path).rglob("*.py"))
        ignore = {".venv", "venv", "node_modules", "__pycache__", ".git", "dist", "build"}
        py_files = [
            f
            for f in py_files
            if not any(part in ignore for part in f.relative_to(project_path).parts)
        ]

        if not py_files:
            return []

        # Include whitelist if present
        whitelist = Path(project_path) / "whitelist.py"
        scan_paths = [str(f) for f in py_files]
        if whitelist.exists():
            scan_paths.append(str(whitelist))

        v.scavenge(scan_paths)

        diags: list[Diagnostic] = []
        for item in v.get_unused_code(min_confidence=60):
            diags.append(
                Diagnostic(
                    file_path=str(item.filename),
                    rule="dead-code",
                    severity=Severity.WARNING,
                    category=Category.DEAD_CODE,
                    message=f"Unused {item.typ}: '{item.name}' ({item.confidence}% confidence)",
                    help="Remove this dead code or add it to a vulture whitelist",
                    line=item.first_lineno,
                )
            )
        return diags
