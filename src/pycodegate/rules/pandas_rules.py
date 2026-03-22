"""Pandas-specific rules: chained indexing, inplace assignment, NaN comparison."""

from __future__ import annotations

import ast

from pycodegate.rules.base import BaseRules
from pycodegate.types import Category, Diagnostic, Severity


class PandasRules(BaseRules):
    """Pandas framework-specific checks."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []
        diags.extend(self._check_chained_indexing(tree, filename))
        diags.extend(self._check_inplace_assignment(tree, filename))
        diags.extend(self._check_nan_comparison(tree, filename))
        return diags

    # ------------------------------------------------------------------
    # pandas-chained-indexing
    # ------------------------------------------------------------------
    def _check_chained_indexing(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        results: list[Diagnostic] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Subscript):
                    results.append(
                        Diagnostic(
                            file_path=filename,
                            rule="pandas-chained-indexing",
                            severity=Severity.ERROR,
                            category=Category.PANDAS,
                            message="Chained indexing for assignment — may silently fail (SettingWithCopyWarning)",
                            help="Use df.loc[mask, 'A'] = val instead",
                            line=node.lineno,
                            column=node.col_offset,
                            cost=2.0,
                        )
                    )
        return results

    # ------------------------------------------------------------------
    # pandas-inplace-assignment
    # ------------------------------------------------------------------
    def _check_inplace_assignment(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        results: list[Diagnostic] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            value = node.value
            if not isinstance(value, ast.Call):
                continue
            for kw in value.keywords:
                if (
                    kw.arg == "inplace"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                ):
                    results.append(
                        Diagnostic(
                            file_path=filename,
                            rule="pandas-inplace-assignment",
                            severity=Severity.ERROR,
                            category=Category.PANDAS,
                            message="Assignment from method with inplace=True — result is always None",
                            help="Either use inplace=True without assignment, or remove inplace=True and assign the result",
                            line=node.lineno,
                            column=node.col_offset,
                            cost=2.0,
                        )
                    )
                    break
        return results

    # ------------------------------------------------------------------
    # pandas-nan-comparison
    # ------------------------------------------------------------------
    def _check_nan_comparison(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        results: list[Diagnostic] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            # Only care about == or != operators
            if not any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
                continue

            sides = [node.left, *node.comparators]
            has_nan_or_none = any(self._is_nan_or_none(s) for s in sides)
            has_subscript = any(isinstance(s, ast.Subscript) for s in sides)

            if has_nan_or_none and has_subscript:
                results.append(
                    Diagnostic(
                        file_path=filename,
                        rule="pandas-nan-comparison",
                        severity=Severity.ERROR,
                        category=Category.PANDAS,
                        message="Comparing with None/NaN using == — always False for NaN",
                        help="Use .isna() or .notna() instead",
                        line=node.lineno,
                        column=node.col_offset,
                        cost=2.0,
                    )
                )
        return results

    @staticmethod
    def _is_nan_or_none(node: ast.expr) -> bool:
        """Return True if node is None, np.nan, or float('nan')."""
        # Constant None
        if isinstance(node, ast.Constant) and node.value is None:
            return True
        # np.nan
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "nan"
            and isinstance(node.value, ast.Name)
            and node.value.id == "np"
        ):
            return True
        # float('nan')
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "float"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "nan"
        )
