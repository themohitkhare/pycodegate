"""Performance rules: string concat in loops, star imports."""

from __future__ import annotations

import ast

from pycodegate.rules.base import BaseRules
from pycodegate.types import Category, Diagnostic, Severity


class PerformanceRules(BaseRules):
    """Performance-related checks."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []
        diags.extend(self._check_string_concat_in_loop(tree, filename))
        diags.extend(self._check_star_imports(tree, filename))
        return diags

    def _check_string_concat_in_loop(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for scope in self._iter_scopes(tree):
            string_vars = self._string_vars_in_scope(scope)
            if string_vars:
                self._flag_concats(scope.body, string_vars, False, filename, diags)
        return diags

    @staticmethod
    def _iter_scopes(tree: ast.Module):
        """Yield the module and every function — each is an independent variable scope."""
        yield tree
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                yield node

    @staticmethod
    def _string_vars_in_scope(scope: ast.AST) -> set[str]:
        """Names assigned a string literal directly in *scope* (not in nested functions)."""
        names: set[str] = set()
        for node in PerformanceRules._walk_scope(scope.body):
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        names.add(target.id)
        return names

    @staticmethod
    def _walk_scope(nodes):
        """Walk *nodes* without descending into nested function scopes."""
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            yield node
            yield from PerformanceRules._walk_scope(ast.iter_child_nodes(node))

    def _flag_concats(
        self,
        nodes,
        string_vars: set[str],
        in_loop: bool,
        filename: str,
        diags: list[Diagnostic],
    ) -> None:
        for node in nodes:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue  # handled by its own scope pass
            if (
                in_loop
                and isinstance(node, ast.AugAssign)
                and isinstance(node.op, ast.Add)
                and isinstance(node.target, ast.Name)
                and node.target.id in string_vars
            ):
                diags.append(
                    Diagnostic(
                        file_path=filename,
                        rule="no-string-concat-in-loop",
                        severity=Severity.WARNING,
                        category=Category.PERFORMANCE,
                        message="String concatenation in a loop — O(n^2) memory",
                        help="Collect items in a list and use ''.join() at the end",
                        line=node.lineno,
                        column=node.col_offset,
                        cost=0.5,
                    )
                )
            child_in_loop = in_loop or isinstance(node, (ast.For, ast.While))
            self._flag_concats(
                ast.iter_child_nodes(node), string_vars, child_in_loop, filename, diags
            )

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
                        cost=0.5,
                    )
                )
        return diags
