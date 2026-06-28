"""SQLAlchemy-specific rules: SQL injection, identity compare, mutable defaults, len(all())."""

from __future__ import annotations

import ast

from pycodegate.rules.base import BaseRules
from pycodegate.types import Category, Diagnostic, Severity


def _is_str_const(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _is_dynamic_string(node: ast.expr) -> bool:
    """Return True if *node* builds a string dynamically (f-string, concat, %-format, .format())."""
    if isinstance(node, ast.JoinedStr):
        # An f-string with no interpolation is a static string, not injection.
        return any(isinstance(value, ast.FormattedValue) for value in node.values)
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Add) and (_is_str_const(node.left) or _is_str_const(node.right)):
            return True
        if isinstance(node.op, ast.Mod) and _is_str_const(node.left):
            return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format" and _is_str_const(node.func.value):
            return True
    return False


class SQLAlchemyRules(BaseRules):
    """SQLAlchemy ORM / Core checks."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                diags.extend(self._check_sql_injection(node, filename))
                diags.extend(self._check_identity_compare(node, filename))
                diags.extend(self._check_mutable_default(node, filename))
                diags.extend(self._check_len_all(node, filename))
        return diags

    def _check_sql_injection(self, node: ast.Call, filename: str) -> list[Diagnostic]:
        # Match .execute() or text()
        is_execute = isinstance(node.func, ast.Attribute) and node.func.attr == "execute"
        is_text = isinstance(node.func, ast.Name) and node.func.id == "text"
        if not (is_execute or is_text):
            return []
        if not node.args:
            return []
        if not _is_dynamic_string(node.args[0]):
            return []
        return [
            Diagnostic(
                file_path=filename,
                rule="sqla-sql-injection",
                severity=Severity.ERROR,
                category=Category.SQLALCHEMY,
                message="SQL query built from dynamic string — potential SQL injection",
                help="Use bound parameters (e.g. text(':param')) instead of string interpolation",
                line=node.lineno,
                column=node.col_offset,
                cost=3.0,
            )
        ]

    def _check_identity_compare(self, node: ast.Call, filename: str) -> list[Diagnostic]:
        if not (isinstance(node.func, ast.Attribute) and node.func.attr in {"filter", "where"}):
            return []
        diags: list[Diagnostic] = []
        for arg in node.args:
            diags.extend(self._find_identity_ops(arg, filename))
        return diags

    def _find_identity_ops(self, arg: ast.expr, filename: str) -> list[Diagnostic]:
        results: list[Diagnostic] = []
        for child in ast.walk(arg):
            if not isinstance(child, ast.Compare):
                continue
            if any(isinstance(op, (ast.Is, ast.IsNot)) for op in child.ops):
                results.append(
                    Diagnostic(
                        file_path=filename,
                        rule="sqla-identity-compare",
                        severity=Severity.ERROR,
                        category=Category.SQLALCHEMY,
                        message="'is'/'is not' in filter/where evaluates in Python, not SQL",
                        help="Use '== None' or '.is_(None)' for proper SQL IS NULL",
                        line=child.lineno,
                        column=child.col_offset,
                        cost=2.0,
                    )
                )
        return results

    def _check_mutable_default(self, node: ast.Call, filename: str) -> list[Diagnostic]:
        if not (isinstance(node.func, ast.Name) and node.func.id in {"Column", "mapped_column"}):
            return []
        for kw in node.keywords:
            if kw.arg == "default" and isinstance(kw.value, (ast.List, ast.Dict)):
                return [
                    Diagnostic(
                        file_path=filename,
                        rule="sqla-mutable-default",
                        severity=Severity.ERROR,
                        category=Category.SQLALCHEMY,
                        message="Mutable default in Column/mapped_column is shared across rows",
                        help="Use 'default=list' (callable) instead of a literal",
                        line=node.lineno,
                        column=node.col_offset,
                        cost=2.0,
                    )
                ]
        return []

    def _check_len_all(self, node: ast.Call, filename: str) -> list[Diagnostic]:
        if not (isinstance(node.func, ast.Name) and node.func.id == "len"):
            return []
        if len(node.args) != 1:
            return []
        arg = node.args[0]
        if (
            isinstance(arg, ast.Call)
            and isinstance(arg.func, ast.Attribute)
            and arg.func.attr == "all"
        ):
            return [
                Diagnostic(
                    file_path=filename,
                    rule="sqla-len-all",
                    severity=Severity.WARNING,
                    category=Category.SQLALCHEMY,
                    message="len(.all()) loads every row into memory just to count",
                    help="Use .count() or func.count() for an efficient SQL COUNT query",
                    line=node.lineno,
                    column=node.col_offset,
                    cost=1.0,
                )
            ]
        return []
