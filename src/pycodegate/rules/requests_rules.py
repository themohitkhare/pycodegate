"""Requests/httpx rules: missing timeout, no status check, verify disabled."""

from __future__ import annotations

import ast

from pycodegate.rules.base import BaseRules
from pycodegate.types import Category, Diagnostic, Severity

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
_HTTP_LIBS = {"requests", "httpx", "client", "session"}
_CONSTRUCTORS = {
    ("requests", "Session"),
    ("httpx", "Client"),
    ("httpx", "AsyncClient"),
}


class RequestsRules(BaseRules):
    """Checks for requests/httpx misuse."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                diags.extend(self._check_missing_timeout(node, filename))
                diags.extend(self._check_verify_disabled(node, filename))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                diags.extend(self._check_no_status_check(node, filename))
        return diags

    # ------------------------------------------------------------------
    # Rule 1: http-missing-timeout
    # ------------------------------------------------------------------

    def _is_http_call(self, node: ast.Call) -> bool:
        """Return True if the call is an HTTP method call (requests.get, etc.)."""
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.attr in _HTTP_METHODS and node.func.value.id in _HTTP_LIBS:
                return True
        return False

    def _is_constructor_call(self, node: ast.Call) -> bool:
        """Return True if the call is a Session/Client constructor."""
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if (node.func.value.id, node.func.attr) in _CONSTRUCTORS:
                return True
        return False

    def _check_missing_timeout(self, node: ast.Call, filename: str) -> list[Diagnostic]:
        if not (self._is_http_call(node) or self._is_constructor_call(node)):
            return []
        has_timeout = any(kw.arg == "timeout" for kw in node.keywords)
        if has_timeout:
            return []
        return [
            Diagnostic(
                file_path=filename,
                rule="http-missing-timeout",
                severity=Severity.WARNING,
                category=Category.REQUESTS,
                message="HTTP call without explicit timeout — may hang indefinitely",
                help="Add a timeout parameter (e.g. timeout=10)",
                line=node.lineno,
                column=node.col_offset,
                cost=1.0,
            )
        ]

    # ------------------------------------------------------------------
    # Rule 2: http-no-status-check
    # ------------------------------------------------------------------

    def _check_no_status_check(
        self, func_node: ast.FunctionDef | ast.AsyncFunctionDef, filename: str
    ) -> list[Diagnostic]:
        """Check if a response variable has .json()/.text/.content accessed without raise_for_status()."""
        response_vars: set[str] = set()
        has_raise: set[str] = set()
        access_nodes: list[tuple[str, ast.AST]] = []

        for node in ast.walk(func_node):
            self._collect_response_info(node, response_vars, has_raise, access_nodes)

        return [
            Diagnostic(
                file_path=filename,
                rule="http-no-status-check",
                severity=Severity.WARNING,
                category=Category.REQUESTS,
                message=f"Response '{var}' used without raise_for_status()",
                help="Call response.raise_for_status() before accessing the body",
                line=access.lineno,
                column=access.col_offset,
                cost=1.0,
            )
            for var, access in access_nodes
            if var in response_vars and var not in has_raise
        ]

    def _collect_response_info(
        self,
        node: ast.AST,
        response_vars: set[str],
        has_raise: set[str],
        access_nodes: list[tuple[str, ast.AST]],
    ) -> None:
        """Populate tracking sets from a single AST node."""
        # Track assignments from HTTP calls
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            if self._is_http_call(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        response_vars.add(target.id)
            return

        if not isinstance(node, (ast.Call, ast.Attribute)):
            return

        # Track raise_for_status() calls
        if isinstance(node, ast.Call) and self._is_attr_call(node, "raise_for_status"):
            has_raise.add(node.func.value.id)
        # Track .json() calls
        elif isinstance(node, ast.Call) and self._is_attr_call(node, "json"):
            access_nodes.append((node.func.value.id, node))
        # Track .text / .content access
        elif isinstance(node, ast.Attribute) and node.attr in ("text", "content"):
            if isinstance(node.value, ast.Name):
                access_nodes.append((node.value.id, node))

    @staticmethod
    def _is_attr_call(node: ast.Call, attr: str) -> bool:
        """Check if node is a method call like var.attr()."""
        return (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == attr
            and isinstance(node.func.value, ast.Name)
        )

    # ------------------------------------------------------------------
    # Rule 3: http-verify-disabled
    # ------------------------------------------------------------------

    def _check_verify_disabled(self, node: ast.Call, filename: str) -> list[Diagnostic]:
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
