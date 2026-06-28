"""Logging rules: f-string formatting, root logger, missing exc_info."""

from __future__ import annotations

import ast

from pycodegate.rules.base import BaseRules
from pycodegate.types import Category, Diagnostic, Severity

_LOG_LEVELS = {"debug", "info", "warning", "error", "critical", "exception"}
# Names conventionally bound to loggers, so `x.info(...)` is a real logging call.
_LOGGER_NAMES = {"logger", "log", "_logger", "_log", "LOG", "LOGGER"}
_LOGGER_ATTRS = {"logger", "log"}


class LoggingRules(BaseRules):
    """Logging-related checks."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        logger_names = self._logger_names(tree)
        diags: list[Diagnostic] = []
        diags.extend(self._check_fstring(tree, filename, logger_names))
        diags.extend(self._check_root_logger(tree, filename))
        diags.extend(self._check_error_no_exc_info(tree, filename, logger_names))
        return diags

    @staticmethod
    def _logger_names(tree: ast.Module) -> set[str]:
        """Names bound via ``x = logging.getLogger(...)`` / ``x = getLogger(...)``."""
        names: set[str] = set()
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)):
                continue
            func = node.value.func
            is_getlogger = (isinstance(func, ast.Attribute) and func.attr == "getLogger") or (
                isinstance(func, ast.Name) and func.id == "getLogger"
            )
            if is_getlogger:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        names.add(target.id)
        return names

    @staticmethod
    def _is_logger_receiver(receiver: ast.expr, logger_names: set[str]) -> bool:
        """True if *receiver* is plausibly a logger (module, getLogger-bound, or convention)."""
        if isinstance(receiver, ast.Name):
            return (
                receiver.id == "logging"
                or receiver.id in logger_names
                or receiver.id in _LOGGER_NAMES
            )
        if isinstance(receiver, ast.Attribute):
            return receiver.attr in _LOGGER_ATTRS
        return False

    def _check_fstring(
        self, tree: ast.Module, filename: str, logger_names: set[str]
    ) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in _LOG_LEVELS:
                continue
            if not self._is_logger_receiver(node.func.value, logger_names):
                continue
            if not node.args:
                continue
            first_arg = node.args[0]
            is_fstring = isinstance(first_arg, ast.JoinedStr)
            is_format_call = (
                isinstance(first_arg, ast.Call)
                and isinstance(first_arg.func, ast.Attribute)
                and first_arg.func.attr == "format"
                and isinstance(first_arg.func.value, (ast.Constant, ast.JoinedStr))
            )
            if is_fstring or is_format_call:
                diags.append(
                    Diagnostic(
                        file_path=filename,
                        rule="logging-fstring",
                        severity=Severity.WARNING,
                        category=Category.LOGGING,
                        message="f-string in logging call defeats lazy evaluation and breaks log aggregation",
                        help="Use %-style: logger.info('User %s logged in', user_id)",
                        line=node.lineno,
                        column=node.col_offset,
                        cost=1.0,
                    )
                )
        return diags

    def _check_root_logger(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in _LOG_LEVELS:
                continue
            if not isinstance(node.func.value, ast.Name):
                continue
            if node.func.value.id != "logging":
                continue
            diags.append(
                Diagnostic(
                    file_path=filename,
                    rule="logging-root-logger",
                    severity=Severity.WARNING,
                    category=Category.LOGGING,
                    message="Using root logger directly — cannot be independently configured",
                    help="Use logger = logging.getLogger(__name__) and call logger.info() instead",
                    line=node.lineno,
                    column=node.col_offset,
                    cost=0.5,
                )
            )
        return diags

    def _check_error_no_exc_info(
        self, tree: ast.Module, filename: str, logger_names: set[str]
    ) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue
                if not isinstance(child.func, ast.Attribute):
                    continue
                if child.func.attr not in ("error", "warning"):
                    continue
                if not self._is_logger_receiver(child.func.value, logger_names):
                    continue
                # Any truthy exc_info (True, a variable, an exception, a call) satisfies it;
                # only exc_info=False/None leaves the traceback out.
                has_exc_info = any(
                    kw.arg == "exc_info"
                    and not (isinstance(kw.value, ast.Constant) and kw.value.value in (False, None))
                    for kw in child.keywords
                )
                if not has_exc_info:
                    diags.append(
                        Diagnostic(
                            file_path=filename,
                            rule="logging-error-no-exc-info",
                            severity=Severity.WARNING,
                            category=Category.LOGGING,
                            message="logger.error() in except block without exc_info=True loses the traceback",
                            help="Use logger.exception() or add exc_info=True",
                            line=child.lineno,
                            column=child.col_offset,
                            cost=1.0,
                        )
                    )
        return diags
