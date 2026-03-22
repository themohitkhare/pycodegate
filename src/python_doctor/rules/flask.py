"""Flask-specific rules: secret key in source, debug mode, SQL via string format."""

from __future__ import annotations

import ast
import re

from python_doctor.rules.base import BaseRules
from python_doctor.types import Category, Diagnostic, Severity

_SQL_PATTERN = re.compile(
    r"(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+",
    re.IGNORECASE,
)


class FlaskRules(BaseRules):
    """Flask framework-specific checks."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []
        diags.extend(self._check_secret_key(tree, filename))
        diags.extend(self._check_debug_mode(tree, filename))
        diags.extend(self._check_sql_string_format(tree, filename))
        return diags

    def _check_secret_key(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and target.attr == "secret_key"
                        and isinstance(node.value, ast.Constant)
                        and isinstance(node.value.value, str)
                    ):
                        diags.append(
                            Diagnostic(
                                file_path=filename,
                                rule="no-flask-secret-in-source",
                                severity=Severity.ERROR,
                                category=Category.FLASK,
                                message="Flask secret_key hardcoded in source",
                                help="Use os.environ['SECRET_KEY'] or a config file",
                                line=node.lineno,
                                column=node.col_offset,
                            )
                        )
        return diags

    def _check_debug_mode(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            if node.func.attr != "run":
                continue
            if self._has_debug_true(node):
                diags.append(
                    Diagnostic(
                        file_path=filename,
                        rule="no-flask-debug-mode",
                        severity=Severity.ERROR,
                        category=Category.FLASK,
                        message="Debug mode enabled — exposes debugger and reloader in production",
                        help="Use environment variable: app.run(debug=os.environ.get('FLASK_DEBUG'))",
                        line=node.lineno,
                        column=node.col_offset,
                    )
                )
        return diags

    @staticmethod
    def _has_debug_true(call_node: ast.Call) -> bool:
        return any(
            kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in call_node.keywords
        )

    def _check_sql_string_format(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.JoinedStr):
                continue
            if self._fstring_contains_sql(node.value):
                diags.append(
                    Diagnostic(
                        file_path=filename,
                        rule="no-sql-string-format",
                        severity=Severity.ERROR,
                        category=Category.FLASK,
                        message="SQL query built with f-string — SQL injection risk",
                        help="Use parameterized queries with placeholders",
                        line=node.lineno,
                        column=node.col_offset,
                    )
                )
        return diags

    @staticmethod
    def _fstring_contains_sql(joined_str: ast.JoinedStr) -> bool:
        return any(
            isinstance(val, ast.Constant)
            and isinstance(val.value, str)
            and _SQL_PATTERN.search(val.value)
            for val in joined_str.values
        )
