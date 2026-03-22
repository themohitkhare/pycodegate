"""Celery-specific rules: missing bind, retry without exc, broad autoretry, direct call."""

from __future__ import annotations

import ast

from pycodegate.rules.base import BaseRules
from pycodegate.types import Category, Diagnostic, Severity

_TASK_DECORATOR_ATTRS = {"task"}
_TASK_DECORATOR_NAMES = {"shared_task"}
_TASK_CALLER_PREFIXES = {"app", "celery"}


def _is_task_decorator(dec: ast.expr) -> bool:
    """Return True if *dec* looks like @app.task, @celery.task, or @shared_task."""
    if isinstance(dec, ast.Attribute) and dec.attr in _TASK_DECORATOR_ATTRS:
        if isinstance(dec.value, ast.Name) and dec.value.id in _TASK_CALLER_PREFIXES:
            return True
    if isinstance(dec, ast.Name) and dec.id in _TASK_DECORATOR_NAMES:
        return True
    if isinstance(dec, ast.Call):
        return _is_task_decorator(dec.func)
    return False


def _decorator_call(dec: ast.expr) -> ast.Call | None:
    """Return the Call node if the decorator is called, else None."""
    if isinstance(dec, ast.Call):
        return dec
    return None


class CeleryRules(BaseRules):
    """Celery framework-specific checks."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []

        # First pass: collect task function names for direct-call detection.
        task_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    if _is_task_decorator(dec):
                        task_names.add(node.name)

        # Second pass: all checks.
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                diags.extend(self._check_task_func(node, filename))
            elif isinstance(node, ast.ExceptHandler):
                diags.extend(self._check_retry_no_exc(node, filename))
            elif isinstance(node, ast.Call):
                diags.extend(self._check_direct_call(node, task_names, filename))

        return diags

    def _check_task_func(self, node, filename) -> list[Diagnostic]:
        """Run task-decorator checks on a single function node."""
        diags: list[Diagnostic] = []
        for dec in node.decorator_list:
            if not _is_task_decorator(dec):
                continue
            diags.extend(self._check_missing_bind(node, dec, filename))
            call = _decorator_call(dec)
            if call is not None:
                diags.extend(self._check_broad_autoretry(node, call, filename))
        return diags

    # ------------------------------------------------------------------
    # Rule: celery-missing-bind
    # ------------------------------------------------------------------
    def _check_missing_bind(self, func_node, decorator, filename) -> list[Diagnostic]:
        args = func_node.args
        first_arg = args.args[0].arg if args.args else None
        if first_arg != "self":
            return []

        call = _decorator_call(decorator)
        if call is not None and any(
            kw.arg == "bind" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            for kw in call.keywords
        ):
            return []

        return [
            Diagnostic(
                file_path=filename,
                rule="celery-missing-bind",
                severity=Severity.ERROR,
                category=Category.CELERY,
                message=f"Task '{func_node.name}' uses 'self' but decorator is missing bind=True",
                help="Add bind=True to the task decorator",
                line=func_node.lineno,
                column=func_node.col_offset,
                cost=2.0,
            )
        ]

    # ------------------------------------------------------------------
    # Rule: celery-retry-no-exc
    # ------------------------------------------------------------------
    def _check_retry_no_exc(self, handler: ast.ExceptHandler, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(handler):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Attribute) and node.func.attr == "retry":
                if isinstance(node.func.value, ast.Name) and node.func.value.id == "self":
                    has_exc = any(kw.arg == "exc" for kw in node.keywords)
                    if not has_exc:
                        diags.append(
                            Diagnostic(
                                file_path=filename,
                                rule="celery-retry-no-exc",
                                severity=Severity.WARNING,
                                category=Category.CELERY,
                                message="self.retry() called without exc keyword — original traceback is lost",
                                help="Pass exc=exc to self.retry() to preserve the traceback",
                                line=node.lineno,
                                column=node.col_offset,
                                cost=1.0,
                            )
                        )
        return diags

    # ------------------------------------------------------------------
    # Rule: celery-broad-autoretry
    # ------------------------------------------------------------------
    def _check_broad_autoretry(self, func_node, call: ast.Call, filename: str) -> list[Diagnostic]:
        for kw in call.keywords:
            if kw.arg != "autoretry_for":
                continue
            if isinstance(kw.value, ast.Tuple):
                for elt in kw.value.elts:
                    if isinstance(elt, ast.Name) and elt.id in {"Exception", "BaseException"}:
                        return [
                            Diagnostic(
                                file_path=filename,
                                rule="celery-broad-autoretry",
                                severity=Severity.WARNING,
                                category=Category.CELERY,
                                message=f"Task '{func_node.name}' uses autoretry_for with broad {elt.id}",
                                help="Narrow autoretry_for to specific exception types",
                                line=kw.value.lineno,
                                column=kw.value.col_offset,
                                cost=1.0,
                            )
                        ]
        return []

    # ------------------------------------------------------------------
    # Rule: celery-direct-call
    # ------------------------------------------------------------------
    def _check_direct_call(
        self, node: ast.Call, task_names: set[str], filename: str
    ) -> list[Diagnostic]:
        if isinstance(node.func, ast.Name) and node.func.id in task_names:
            return [
                Diagnostic(
                    file_path=filename,
                    rule="celery-direct-call",
                    severity=Severity.WARNING,
                    category=Category.CELERY,
                    message=f"Task '{node.func.id}' called directly — runs synchronously, not via worker",
                    help="Use .delay() or .apply_async() to dispatch to a Celery worker",
                    line=node.lineno,
                    column=node.col_offset,
                    cost=0.5,
                )
            ]
        return []
