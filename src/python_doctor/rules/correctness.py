"""Correctness rules: mutable defaults, bare except, broad exception, assert in prod, return in __init__."""

from __future__ import annotations

import ast

from python_doctor.rules.base import BaseRules
from python_doctor.types import Category, Diagnostic, Severity


class CorrectnessRules(BaseRules):
    """Correctness-related checks."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []
        diags.extend(self._check_mutable_defaults(tree, filename))
        diags.extend(self._check_bare_except(tree, filename))
        diags.extend(self._check_broad_exception(tree, filename))
        diags.extend(self._check_assert_in_production(tree, filename))
        diags.extend(self._check_return_in_init(tree, filename))
        return diags

    def _check_mutable_defaults(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for default in node.args.defaults + node.args.kw_defaults:
                    if default is not None and isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        diags.append(
                            Diagnostic(
                                file_path=filename,
                                rule="no-mutable-default",
                                severity=Severity.ERROR,
                                category=Category.CORRECTNESS,
                                message="Mutable default argument — shared across all calls",
                                help="Use None as default and create the mutable inside the function body",
                                line=node.lineno,
                                column=node.col_offset,
                                cost=2.0,
                            )
                        )
        return diags

    def _check_bare_except(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                diags.append(
                    Diagnostic(
                        file_path=filename,
                        rule="no-bare-except",
                        severity=Severity.ERROR,
                        category=Category.CORRECTNESS,
                        message="Bare except catches all exceptions including SystemExit and KeyboardInterrupt",
                        help="Catch a specific exception type, or at minimum use 'except Exception'",
                        line=node.lineno,
                        column=node.col_offset,
                        cost=2.0,
                    )
                )
        return diags

    def _check_broad_exception(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is not None:
                if isinstance(node.type, ast.Name) and node.type.id in (
                    "Exception",
                    "BaseException",
                ):
                    diags.append(
                        Diagnostic(
                            file_path=filename,
                            rule="no-broad-exception",
                            severity=Severity.WARNING,
                            category=Category.CORRECTNESS,
                            message=f"Catching '{node.type.id}' is too broad — masks real errors",
                            help="Catch specific exception types (ValueError, TypeError, etc.)",
                            line=node.lineno,
                            column=node.col_offset,
                            cost=1.0,
                        )
                    )
        return diags

    def _check_assert_in_production(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        if filename.startswith("test_") or "/test_" in filename or filename.endswith("_test.py"):
            return []

        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert):
                diags.append(
                    Diagnostic(
                        file_path=filename,
                        rule="no-assert-in-production",
                        severity=Severity.WARNING,
                        category=Category.CORRECTNESS,
                        message="assert statements are stripped with python -O flag",
                        help="Use explicit if/raise for production validation",
                        line=node.lineno,
                        column=node.col_offset,
                        cost=1.0,
                    )
                )
        return diags

    def _check_return_in_init(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "__init__":
                for child in ast.walk(node):
                    if isinstance(child, ast.Return) and child.value is not None:
                        diags.append(
                            Diagnostic(
                                file_path=filename,
                                rule="no-return-in-init",
                                severity=Severity.ERROR,
                                category=Category.CORRECTNESS,
                                message="__init__ should not return a value",
                                help="Remove the return value — __init__ must return None",
                                line=child.lineno,
                                column=child.col_offset,
                                cost=2.0,
                            )
                        )
        return diags
