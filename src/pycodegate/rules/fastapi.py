"""FastAPI-specific rules: sync endpoints, missing response_model."""

from __future__ import annotations

import ast

from pycodegate.rules.base import BaseRules
from pycodegate.types import Category, Diagnostic, Severity

_ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


class FastAPIRules(BaseRules):
    """FastAPI framework-specific checks."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        router_names = self._router_names(tree)
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                route_decorator = self._get_route_decorator(node, router_names)
                if route_decorator is not None:
                    diags.extend(self._check_sync_endpoint(node, route_decorator, filename))
                    diags.extend(self._check_response_model(node, route_decorator, filename))
        return diags

    @staticmethod
    def _router_names(tree: ast.Module) -> set[str]:
        """Names bound to a FastAPI()/APIRouter() instance (plus app/router by convention)."""
        names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                func = node.value.func
                ctor = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                if ctor in ("FastAPI", "APIRouter"):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            names.add(target.id)
        return names

    def _get_route_decorator(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, router_names: set[str]
    ) -> ast.Call | None:
        for dec in node.decorator_list:
            if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)):
                continue
            if dec.func.attr not in _ROUTE_METHODS:
                continue
            receiver = dec.func.value
            if not isinstance(receiver, ast.Name):
                continue
            name = receiver.id
            if name in router_names or "app" in name.lower() or "router" in name.lower():
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
                    message=(
                        f"Endpoint '{node.name}' is synchronous — runs in a threadpool; "
                        "prefer 'async def' for I/O-bound work"
                    ),
                    help="Use 'async def' with async I/O, or keep sync for CPU-bound work",
                    line=node.lineno,
                    column=node.col_offset,
                    cost=1.0,
                )
            ]
        return []

    def _check_response_model(self, node, decorator, filename):
        has_response_model = any(kw.arg == "response_model" for kw in decorator.keywords)
        # A return-type annotation (other than `-> None`) IS the response model in modern FastAPI.
        has_return_annotation = node.returns is not None and not (
            isinstance(node.returns, ast.Constant) and node.returns.value is None
        )
        if not has_response_model and not has_return_annotation:
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
