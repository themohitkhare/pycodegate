"""Requests rules: missing timeout, SSL verification disabled."""

from __future__ import annotations

import ast

from pycodegate.rules.base import BaseRules
from pycodegate.types import Category, Diagnostic, Severity

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "request"}


class RequestsRules(BaseRules):
    """Checks for requests misuse."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                diags.extend(self._check_missing_timeout(node, filename))
                diags.extend(self._check_verify_disabled(node, filename))
        return diags

    @staticmethod
    def _is_requests_call(node: ast.Call) -> bool:
        """Return True for a module-qualified ``requests.<method>(...)`` call.

        Scoped to the ``requests`` module on purpose: ``requests`` has no default
        timeout, whereas object/dict ``.get()`` and ``httpx`` (which *does* default
        a timeout) would only produce false positives.
        """
        return (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in _HTTP_METHODS
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "requests"
        )

    def _check_missing_timeout(self, node: ast.Call, filename: str) -> list[Diagnostic]:
        if not self._is_requests_call(node):
            return []
        if any(kw.arg == "timeout" for kw in node.keywords):
            return []
        return [
            Diagnostic(
                file_path=filename,
                rule="http-missing-timeout",
                severity=Severity.WARNING,
                category=Category.REQUESTS,
                message="requests call without an explicit timeout — may hang indefinitely",
                help="Add a timeout parameter (e.g. timeout=10)",
                line=node.lineno,
                column=node.col_offset,
                cost=1.0,
            )
        ]

    def _check_verify_disabled(self, node: ast.Call, filename: str) -> list[Diagnostic]:
        if not self._is_requests_call(node):
            return []
        for kw in node.keywords:
            if (
                kw.arg == "verify"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is False
            ):
                return [
                    Diagnostic(
                        file_path=filename,
                        rule="http-verify-disabled",
                        severity=Severity.ERROR,
                        category=Category.REQUESTS,
                        message="SSL verification disabled with verify=False — vulnerable to MITM attacks",
                        help="Remove verify=False or use a custom CA bundle",
                        line=node.lineno,
                        column=node.col_offset,
                        cost=3.0,
                    )
                ]
        return []
