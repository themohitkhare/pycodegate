"""Performance rules: string concat in loops, imports in functions, star imports."""

from __future__ import annotations

import ast

from python_doctor.rules.base import BaseRules
from python_doctor.types import Category, Diagnostic, Severity


class PerformanceRules(BaseRules):
    """Performance-related checks."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []
        diags.extend(self._check_string_concat_in_loop(tree, filename))
        diags.extend(self._check_import_in_function(tree, filename))
        diags.extend(self._check_star_imports(tree, filename))
        return diags

    def _check_string_concat_in_loop(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        string_vars = self._find_string_vars(tree)

        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.For, ast.While)):
                for child in ast.walk(node):
                    if (
                        isinstance(child, ast.AugAssign)
                        and isinstance(child.op, ast.Add)
                        and isinstance(child.target, ast.Name)
                        and child.target.id in string_vars
                    ):
                        diags.append(
                            Diagnostic(
                                file_path=filename,
                                rule="no-string-concat-in-loop",
                                severity=Severity.WARNING,
                                category=Category.PERFORMANCE,
                                message="String concatenation in a loop — O(n^2) memory",
                                help="Collect items in a list and use ''.join() at the end",
                                line=child.lineno,
                                column=child.col_offset,
                            )
                        )
        return diags

    @staticmethod
    def _find_string_vars(tree: ast.Module) -> set[str]:
        names: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not (isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        return names

    def _check_import_in_function(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    if isinstance(child, (ast.Import, ast.ImportFrom)):
                        diags.append(
                            Diagnostic(
                                file_path=filename,
                                rule="no-import-in-function",
                                severity=Severity.WARNING,
                                category=Category.PERFORMANCE,
                                message="Import inside function body — re-imported on every call",
                                help="Move imports to the top of the module",
                                line=child.lineno,
                                column=child.col_offset,
                            )
                        )
        return diags

    def _check_star_imports(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names):
                diags.append(
                    Diagnostic(
                        file_path=filename,
                        rule="no-star-import",
                        severity=Severity.WARNING,
                        category=Category.PERFORMANCE,
                        message=f"Star import from {node.module} pollutes namespace and hides dependencies",
                        help="Import specific names instead",
                        line=node.lineno,
                        column=node.col_offset,
                    )
                )
        return diags
