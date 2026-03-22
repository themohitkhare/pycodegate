"""FastAPI-specific rules: sync endpoints, missing response_model."""

from __future__ import annotations

import ast

from python_doctor.rules.base import BaseRules
from python_doctor.types import Category, Diagnostic, Severity

_ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


class FastAPIRules(BaseRules):
    """FastAPI framework-specific checks."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                route_decorator = self._get_route_decorator(node)
                if route_decorator is not None:
                    diags.extend(self._check_sync_endpoint(node, route_decorator, filename))
                    diags.extend(self._check_response_model(node, route_decorator, filename))
        return diags

    def _get_route_decorator(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.Call | None:
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                if dec.func.attr in _ROUTE_METHODS:
                    return dec
        return None

    def _check_sync_endpoint(self, node, decorator, filename):
        if isinstance(node, ast.FunctionDef):
            return [
                Diagnostic(
                    file_path=filename,
                    rule="prefer-async-endpoint",
                    severity=Severity.WARNING,
                    category=Category.FASTAPI,
                    message=f"Endpoint '{node.name}' is synchronous — blocks the event loop",
                    help="Use 'async def' for I/O-bound endpoints",
                    line=node.lineno,
                    column=node.col_offset,
                    cost=1.0,
                )
            ]
        return []

    def _check_response_model(self, node, decorator, filename):
        has_response_model = any(kw.arg == "response_model" for kw in decorator.keywords)
        if not has_response_model:
            return [
                Diagnostic(
                    file_path=filename,
                    rule="missing-response-model",
                    severity=Severity.WARNING,
                    category=Category.FASTAPI,
                    message=f"Endpoint '{node.name}' missing response_model — no response validation",
                    help="Add response_model parameter to the route decorator",
                    line=node.lineno,
                    column=node.col_offset,
                    cost=1.0,
                )
            ]
        return []
