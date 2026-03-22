"""Architecture rules: giant modules, deep nesting, god functions, too many args."""

from __future__ import annotations

import ast

from python_doctor.rules.base import BaseRules
from python_doctor.types import Category, Diagnostic, Severity

MAX_MODULE_LINES = 500
MAX_FUNCTION_LINES = 50
MAX_NESTING_DEPTH = 5
MAX_ARGUMENTS = 7


class ArchitectureRules(BaseRules):
    """Architecture-level checks."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []
        diags.extend(self._check_giant_module(source, filename))
        diags.extend(self._check_deep_nesting(tree, filename))
        diags.extend(self._check_god_functions(tree, filename))
        diags.extend(self._check_too_many_args(tree, filename))
        return diags

    def _check_giant_module(self, source: str, filename: str) -> list[Diagnostic]:
        lines = source.count("\n") + 1
        if lines > MAX_MODULE_LINES:
            return [
                Diagnostic(
                    file_path=filename,
                    rule="no-giant-module",
                    severity=Severity.WARNING,
                    category=Category.ARCHITECTURE,
                    message=f"Module has {lines} lines (max {MAX_MODULE_LINES}) — consider splitting",
                    help="Extract related functions into separate modules",
                    line=1,
                    cost=1.0,
                )
            ]
        return []

    def _check_deep_nesting(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        self._walk_nesting(tree, 0, filename, diags)
        return diags

    def _walk_nesting(
        self, node: ast.AST, depth: int, filename: str, diags: list[Diagnostic]
    ) -> None:
        nesting_nodes = (ast.If, ast.For, ast.While, ast.With, ast.Try)
        if isinstance(node, nesting_nodes):
            depth += 1
            if depth >= MAX_NESTING_DEPTH:
                diags.append(
                    Diagnostic(
                        file_path=filename,
                        rule="no-deep-nesting",
                        severity=Severity.WARNING,
                        category=Category.ARCHITECTURE,
                        message=f"Nesting depth {depth} exceeds max {MAX_NESTING_DEPTH}",
                        help="Extract nested logic into helper functions or use early returns",
                        line=node.lineno,
                        column=node.col_offset,
                        cost=1.0,
                    )
                )
        for child in ast.iter_child_nodes(node):
            self._walk_nesting(child, depth, filename, diags)

    def _check_god_functions(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                end = getattr(node, "end_lineno", None)
                if end is not None:
                    length = end - node.lineno + 1
                    if length > MAX_FUNCTION_LINES:
                        diags.append(
                            Diagnostic(
                                file_path=filename,
                                rule="no-god-function",
                                severity=Severity.WARNING,
                                category=Category.ARCHITECTURE,
                                message=f"Function '{node.name}' is {length} lines (max {MAX_FUNCTION_LINES})",
                                help="Break into smaller functions with single responsibilities",
                                line=node.lineno,
                                column=node.col_offset,
                                cost=1.0,
                            )
                        )
        return diags

    def _check_too_many_args(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = node.args
                total = len(args.posonlyargs) + len(args.args) + len(args.kwonlyargs)
                if total > 0 and args.args and args.args[0].arg in ("self", "cls"):
                    total -= 1
                if total > MAX_ARGUMENTS:
                    diags.append(
                        Diagnostic(
                            file_path=filename,
                            rule="too-many-arguments",
                            severity=Severity.WARNING,
                            category=Category.ARCHITECTURE,
                            message=f"Function '{node.name}' has {total} arguments (max {MAX_ARGUMENTS})",
                            help="Group related arguments into a dataclass or TypedDict",
                            line=node.lineno,
                            column=node.col_offset,
                            cost=1.0,
                        )
                    )
        return diags
