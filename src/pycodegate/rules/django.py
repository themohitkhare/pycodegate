"""Django-specific rules: raw SQL, DEBUG=True, N+1 queries, secret key exposure."""

from __future__ import annotations

import ast
import re

from pycodegate.rules.base import BaseRules
from pycodegate.types import Category, Diagnostic, Severity

_SQL_PATTERN = re.compile(
    r"(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s",
    re.IGNORECASE,
)


def _binop_has_sql_literal(node: ast.AST) -> bool:
    """True if any string literal inside a BinOp tree looks like SQL."""
    return any(
        isinstance(child, ast.Constant)
        and isinstance(child.value, str)
        and _SQL_PATTERN.search(child.value)
        for child in ast.walk(node)
    )


class DjangoRules(BaseRules):
    """Django framework-specific checks."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []
        diags.extend(self._check_raw_sql(tree, filename))
        diags.extend(self._check_debug_true(tree, filename))
        diags.extend(self._check_n_plus_one(tree, source, filename))
        diags.extend(self._check_secret_key(tree, filename))
        return diags

    def _check_raw_sql(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "execute" and node.args:
                    arg = node.args[0]
                    if (
                        isinstance(arg, ast.BinOp)
                        and isinstance(arg.op, ast.Add)
                        and _binop_has_sql_literal(arg)
                    ):
                        diags.append(
                            Diagnostic(
                                file_path=filename,
                                rule="no-raw-sql-injection",
                                severity=Severity.ERROR,
                                category=Category.DJANGO,
                                message="SQL query built with string concatenation — SQL injection risk",
                                help="Use parameterized queries: cursor.execute('SELECT ... WHERE id = %s', [user_id])",
                                line=node.lineno,
                                column=node.col_offset,
                                cost=3.0,
                            )
                        )
        return diags

    def _check_debug_true(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        if "settings" not in filename:
            return []
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (
                        isinstance(target, ast.Name)
                        and target.id == "DEBUG"
                        and isinstance(node.value, ast.Constant)
                        and node.value.value is True
                    ):
                        diags.append(
                            Diagnostic(
                                file_path=filename,
                                rule="no-debug-true",
                                severity=Severity.ERROR,
                                category=Category.DJANGO,
                                message="DEBUG = True should not be hardcoded in settings",
                                help="Use environment variable: DEBUG = os.environ.get('DEBUG', 'False') == 'True'",
                                line=node.lineno,
                                column=node.col_offset,
                                cost=3.0,
                            )
                        )
        return diags

    def _check_n_plus_one(self, tree: ast.Module, source: str, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.For) or not self._is_queryset_iter(node.iter):
                continue
            if self._uses_eager_loading(node.iter):
                continue  # select_related/prefetch_related already prevents the N+1
            if not isinstance(node.target, ast.Name):
                continue
            var_name = node.target.id
            if self._has_related_access(node, var_name):
                diags.append(
                    Diagnostic(
                        file_path=filename,
                        rule="no-n-plus-one-query",
                        severity=Severity.WARNING,
                        category=Category.DJANGO,
                        message="Potential N+1 query — accessing related object in a loop",
                        help="Use select_related() or prefetch_related() on the queryset",
                        line=node.lineno,
                        column=node.col_offset,
                        cost=1.0,
                    )
                )
        return diags

    @staticmethod
    def _uses_eager_loading(node: ast.expr) -> bool:
        """True if any call in the queryset chain is select_related/prefetch_related."""
        current = node
        while isinstance(current, ast.Call) and isinstance(current.func, ast.Attribute):
            if current.func.attr in ("select_related", "prefetch_related"):
                return True
            current = current.func.value
        return False

    @staticmethod
    def _has_related_access(loop_node: ast.For, var_name: str) -> bool:
        for child in ast.walk(loop_node):
            if (
                isinstance(child, ast.Attribute)
                and isinstance(child.value, ast.Attribute)
                and isinstance(child.value.value, ast.Name)
                and child.value.value.id == var_name
            ):
                return True
        return False

    def _is_queryset_iter(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("all", "filter", "exclude", "values", "values_list"):
                return True
        return False

    def _check_secret_key(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        if "settings" not in filename:
            return []
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (
                        isinstance(target, ast.Name)
                        and target.id == "SECRET_KEY"
                        and isinstance(node.value, ast.Constant)
                        and isinstance(node.value.value, str)
                    ):
                        diags.append(
                            Diagnostic(
                                file_path=filename,
                                rule="no-secret-key-in-source",
                                severity=Severity.ERROR,
                                category=Category.DJANGO,
                                message="SECRET_KEY hardcoded in settings — use environment variable",
                                help="Use os.environ['SECRET_KEY'] or django-environ",
                                line=node.lineno,
                                column=node.col_offset,
                                cost=3.0,
                            )
                        )
        return diags
