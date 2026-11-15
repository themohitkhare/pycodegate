from __future__ import annotations

import ast
import fnmatch
from pathlib import Path

from pycodegate.rules.base import BaseRules
from pycodegate.types import Category, Diagnostic, ImportBoundary, Severity


class ImportBoundaryRules(BaseRules):
    def __init__(self, project_path: str, boundaries: list[ImportBoundary]) -> None:
        self.root = Path(project_path).resolve()
        self.boundaries = boundaries

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []
        try:
            relative = Path(filename).resolve().relative_to(self.root)
        except ValueError:
            return []
        boundaries = [
            boundary
            for boundary in self.boundaries
            if any(fnmatch.fnmatchcase(relative.as_posix(), pattern) for pattern in boundary.files)
        ]
        diagnostics = []
        for node in ast.walk(tree):
            modules = self._imported_names(node, relative)
            for boundary in boundaries:
                forbidden = next(
                    (name for name in modules if self._forbidden(name, boundary.forbidden)), None
                )
                if forbidden is not None:
                    diagnostics.append(
                        Diagnostic(
                            file_path=filename,
                            rule="imports/boundary",
                            severity=Severity.ERROR,
                            category=Category.IMPORTS,
                            message=f"Import '{forbidden}' violates an import boundary",
                            help=boundary.message,
                            line=node.lineno,
                            column=node.col_offset,
                        )
                    )
        return diagnostics

    @staticmethod
    def _forbidden(module: str, forbidden: tuple[str, ...]) -> bool:
        return any(module == prefix or module.startswith(f"{prefix}.") for prefix in forbidden)

    @staticmethod
    def _imported_names(node: ast.AST, relative: Path) -> list[str]:
        if isinstance(node, ast.Import):
            return [alias.name for alias in node.names]
        if not isinstance(node, ast.ImportFrom):
            return []
        module = node.module or ""
        if node.level:
            package = list(relative.parent.parts)
            if package and package[0] == "src":
                package = package[1:]
            if node.level > len(package):
                return []
            parent = package[: len(package) - node.level + 1]
            module = ".".join([*parent, *([module] if module else [])])
        return [module, *(f"{module}.{alias.name}" for alias in node.names)]
