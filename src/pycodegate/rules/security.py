"""Security rules: eval, exec, pickle, yaml, secrets, weak hashes."""

from __future__ import annotations

import ast
import re

from pycodegate.rules.base import BaseRules
from pycodegate.types import Category, Diagnostic, Severity

# Patterns that suggest a hardcoded secret
_SECRET_VAR_PATTERNS = re.compile(
    r"(api_key|apikey|secret|password|passwd|token|auth_token|private_key|"
    r"access_key|secret_key|credentials)",
    re.IGNORECASE,
)

# Patterns that look like actual secret values (not empty/placeholder)
_SECRET_VALUE_MIN_LENGTH = 7

# Substrings that mark a value as an obvious placeholder rather than a real secret
_PLACEHOLDER_MARKERS = (
    "your-",
    "your_",
    "changeme",
    "change-me",
    "example",
    "placeholder",
    "dummy",
    "xxxx",
    "<",
    "...",
    "insecure",
    "test",
    "fake",
    "sample",
)


def _is_marked_non_security(node: ast.Call) -> bool:
    """True if a hashlib call passes ``usedforsecurity=False``."""
    return any(
        kw.arg == "usedforsecurity"
        and isinstance(kw.value, ast.Constant)
        and kw.value.value is False
        for kw in node.keywords
    )


def _looks_like_placeholder(value: str) -> bool:
    """True if a string is an obvious non-secret placeholder."""
    lowered = value.lower()
    if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
        return True
    return len(set(value)) <= 2  # e.g. "xxxxxxxx", "00000000"


class SecurityRules(BaseRules):
    """Security-related checks."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []
        diags.extend(self._check_eval_exec(tree, filename))
        diags.extend(self._check_pickle(tree, filename))
        diags.extend(self._check_yaml(tree, filename))
        diags.extend(self._check_hardcoded_secrets(tree, filename))
        diags.extend(self._check_weak_hash(tree, filename))
        diags.extend(self._check_os_system(tree, filename))
        diags.extend(self._check_subprocess_shell(tree, filename))
        diags.extend(self._check_tempfile_mktemp(tree, filename))
        return diags

    def _check_eval_exec(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "eval":
                    diags.append(
                        Diagnostic(
                            file_path=filename,
                            rule="no-eval",
                            severity=Severity.ERROR,
                            category=Category.SECURITY,
                            message="Avoid eval() — it executes arbitrary code",
                            help="Use ast.literal_eval() for safe parsing of literals",
                            line=node.lineno,
                            column=node.col_offset,
                            cost=3.0,
                        )
                    )
                elif node.func.id == "exec":
                    diags.append(
                        Diagnostic(
                            file_path=filename,
                            rule="no-exec",
                            severity=Severity.ERROR,
                            category=Category.SECURITY,
                            message="Avoid exec() — it executes arbitrary code",
                            help="Refactor to avoid dynamic code execution",
                            line=node.lineno,
                            column=node.col_offset,
                            cost=3.0,
                        )
                    )
        return diags

    def _check_pickle(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in ("load", "loads") and isinstance(node.func.value, ast.Name):
                    if node.func.value.id == "pickle":
                        diags.append(
                            Diagnostic(
                                file_path=filename,
                                rule="no-pickle-load",
                                severity=Severity.ERROR,
                                category=Category.SECURITY,
                                message="pickle.load() can execute arbitrary code on untrusted data",
                                help="Use JSON or a safe serialization format for untrusted data",
                                line=node.lineno,
                                column=node.col_offset,
                                cost=3.0,
                            )
                        )
        return diags

    def _check_yaml(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if (
                    node.func.attr == "load"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "yaml"
                ):
                    has_loader = any(kw.arg == "Loader" for kw in node.keywords)
                    if not has_loader:
                        diags.append(
                            Diagnostic(
                                file_path=filename,
                                rule="no-unsafe-yaml-load",
                                severity=Severity.ERROR,
                                category=Category.SECURITY,
                                message="yaml.load() without Loader is unsafe — can execute arbitrary code",
                                help="Use yaml.safe_load() or pass Loader=yaml.SafeLoader",
                                line=node.lineno,
                                column=node.col_offset,
                                cost=3.0,
                            )
                        )
        return diags

    def _check_hardcoded_secrets(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
                continue
            if len(node.value.value) < _SECRET_VALUE_MIN_LENGTH:
                continue
            if _looks_like_placeholder(node.value.value):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and _SECRET_VAR_PATTERNS.search(target.id):
                    diags.append(
                        Diagnostic(
                            file_path=filename,
                            rule="no-hardcoded-secret",
                            severity=Severity.ERROR,
                            category=Category.SECURITY,
                            message=f"Hardcoded secret in '{target.id}' — use environment variables",
                            help="Use os.environ or a .env file via python-dotenv",
                            line=node.lineno,
                            column=node.col_offset,
                            cost=3.0,
                        )
                    )
        return diags

    def _check_os_system(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != "system":
                continue
            if not isinstance(node.func.value, ast.Name):
                continue
            if node.func.value.id != "os":
                continue
            diags.append(
                Diagnostic(
                    file_path=filename,
                    rule="no-os-system",
                    severity=Severity.ERROR,
                    category=Category.SECURITY,
                    message="os.system() is vulnerable to shell injection",
                    help="Use subprocess.run() with a list of arguments instead",
                    line=node.lineno,
                    column=node.col_offset,
                    cost=4.0,
                )
            )
        return diags

    def _check_subprocess_shell(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        _subprocess_funcs = {"run", "Popen", "call", "check_call", "check_output"}
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in _subprocess_funcs:
                continue
            if not isinstance(node.func.value, ast.Name):
                continue
            if node.func.value.id != "subprocess":
                continue
            shell_true = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            if not shell_true:
                continue
            diags.append(
                Diagnostic(
                    file_path=filename,
                    rule="no-subprocess-shell",
                    severity=Severity.ERROR,
                    category=Category.SECURITY,
                    message="subprocess called with shell=True is a security risk",
                    help="Pass arguments as a list and remove shell=True",
                    line=node.lineno,
                    column=node.col_offset,
                    cost=4.0,
                )
            )
        return diags

    def _check_tempfile_mktemp(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != "mktemp":
                continue
            if not isinstance(node.func.value, ast.Name):
                continue
            if node.func.value.id != "tempfile":
                continue
            diags.append(
                Diagnostic(
                    file_path=filename,
                    rule="no-tempfile-race",
                    severity=Severity.WARNING,
                    category=Category.SECURITY,
                    message="tempfile.mktemp() is deprecated and vulnerable to race conditions",
                    help="Use tempfile.mkstemp() or tempfile.NamedTemporaryFile()",
                    line=node.lineno,
                    column=node.col_offset,
                    cost=2.0,
                )
            )
        return diags

    def _check_weak_hash(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if (
                    node.func.attr in ("md5", "sha1")
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "hashlib"
                    and not _is_marked_non_security(node)
                ):
                    diags.append(
                        Diagnostic(
                            file_path=filename,
                            rule="no-weak-hash",
                            severity=Severity.WARNING,
                            category=Category.SECURITY,
                            message=f"hashlib.{node.func.attr}() is cryptographically weak",
                            help="Use hashlib.sha256() or hashlib.sha3_256() instead",
                            line=node.lineno,
                            column=node.col_offset,
                            cost=1.0,
                        )
                    )
        return diags
