"""Pytest rules: assert-tuple trap, raises-instead-of-try, float equality."""

from __future__ import annotations

import ast

from pycodegate.rules.base import BaseRules
from pycodegate.types import Category, Diagnostic, Severity


class PytestRules(BaseRules):
    """Pytest-specific checks."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []
        diags.extend(self._check_assert_tuple(tree, filename))
        diags.extend(self._check_raises_instead_of_try(tree, filename))
        diags.extend(self._check_float_equality(tree, filename))
        return diags

    # ------------------------------------------------------------------
    # Rule 1: pytest-assert-tuple
    # ------------------------------------------------------------------

    def _check_assert_tuple(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        """Detect ``assert(condition, msg)`` which is always True (non-empty tuple)."""
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assert) and isinstance(node.test, ast.Tuple):
                diags.append(
                    Diagnostic(
                        file_path=filename,
                        rule="pytest-assert-tuple",
                        severity=Severity.ERROR,
                        category=Category.PYTEST,
                        message="assert(x, msg) always passes \u2014 asserts a non-empty tuple, not the condition",
                        help="Remove parentheses: assert x, msg",
                        line=node.lineno,
                        column=node.col_offset,
                        cost=2.0,
                    )
                )
        return diags

    # ------------------------------------------------------------------
    # Rule 2: pytest-raises-instead-of-try
    # ------------------------------------------------------------------

    def _check_raises_instead_of_try(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        """Detect try/except anti-patterns in test functions."""
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.name.startswith("test_"):
                continue
            for child in ast.walk(node):
                if not isinstance(child, ast.Try):
                    continue
                if self._has_suspect_except(child) or self._has_assert_false_else(child):
                    diags.append(
                        Diagnostic(
                            file_path=filename,
                            rule="pytest-raises-instead-of-try",
                            severity=Severity.WARNING,
                            category=Category.PYTEST,
                            message="Using try/except pattern instead of pytest.raises",
                            help="Use 'with pytest.raises(ExceptionType):' instead",
                            line=child.lineno,
                            column=child.col_offset,
                            cost=0.5,
                        )
                    )
        return diags

    @staticmethod
    def _is_pass(stmt: ast.stmt) -> bool:
        return isinstance(stmt, ast.Pass)

    @staticmethod
    def _is_assert_true(stmt: ast.stmt) -> bool:
        return (
            isinstance(stmt, ast.Assert)
            and isinstance(stmt.test, ast.Constant)
            and stmt.test.value is True
        )

    @staticmethod
    def _is_assert_false(stmt: ast.stmt) -> bool:
        return (
            isinstance(stmt, ast.Assert)
            and isinstance(stmt.test, ast.Constant)
            and stmt.test.value is False
        )

    def _has_suspect_except(self, try_node: ast.Try) -> bool:
        for handler in try_node.handlers:
            body = handler.body
            if len(body) == 1 and (self._is_pass(body[0]) or self._is_assert_true(body[0])):
                return True
        return False

    def _has_assert_false_else(self, try_node: ast.Try) -> bool:
        return any(self._is_assert_false(stmt) for stmt in try_node.orelse)

    # ------------------------------------------------------------------
    # Rule 3: pytest-float-equality
    # ------------------------------------------------------------------

    def _check_float_equality(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        """Detect exact float comparisons inside test functions."""
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.name.startswith("test_"):
                continue
            for child in ast.walk(node):
                if not isinstance(child, ast.Assert):
                    continue
                if self._has_float_eq(child.test):
                    diags.append(
                        Diagnostic(
                            file_path=filename,
                            rule="pytest-float-equality",
                            severity=Severity.WARNING,
                            category=Category.PYTEST,
                            message="Exact float comparison in test \u2014 fragile due to floating-point imprecision",
                            help="Use assert x == pytest.approx(expected) instead",
                            line=child.lineno,
                            column=child.col_offset,
                            cost=0.5,
                        )
                    )
        return diags

    @staticmethod
    def _has_float_eq(node: ast.expr | None) -> bool:
        if node is None:
            return False
        if not isinstance(node, ast.Compare):
            return False
        for op, comparator in zip(node.ops, node.comparators):  # noqa: B905
            if (
                isinstance(op, ast.Eq)
                and isinstance(comparator, ast.Constant)
                and isinstance(comparator.value, float)
            ):
                return True
        return False
