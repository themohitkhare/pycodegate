"""Complexity rules: cyclomatic complexity analysis using pure AST."""

from __future__ import annotations

import ast

from python_doctor.rules.base import BaseRules
from python_doctor.types import Category, Diagnostic, Severity

MAX_COMPLEXITY = 15
CRITICAL_COMPLEXITY = 25


def _cyclomatic_complexity(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """Calculate cyclomatic complexity for a function node.

    Starts at 1 and adds 1 for each decision point:
      - if / elif statements
      - for / while loops
      - except handlers
      - and / or boolean operators
      - assert statements
      - ternary expressions (IfExp)
    """
    complexity = 1
    for node in ast.walk(func_node):
        # Skip nested function/class definitions to avoid double-counting
        if node is not func_node and isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            continue
        if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler)):
            complexity += 1
        elif isinstance(node, ast.BoolOp):
            complexity += len(node.values) - 1
        elif isinstance(node, (ast.Assert, ast.IfExp)):
            complexity += 1
    return complexity


class ComplexityRules(BaseRules):
    """Cyclomatic complexity checks."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                complexity = _cyclomatic_complexity(node)
                if complexity > CRITICAL_COMPLEXITY:
                    diags.append(
                        Diagnostic(
                            file_path=filename,
                            rule="critical-complexity",
                            severity=Severity.ERROR,
                            category=Category.COMPLEXITY,
                            message=(
                                f"Function '{node.name}' has cyclomatic complexity"
                                f" {complexity} (max {MAX_COMPLEXITY})"
                            ),
                            help="Break into smaller functions or simplify conditional logic",
                            line=node.lineno,
                            column=node.col_offset,
                            cost=3.0,
                        )
                    )
                elif complexity > MAX_COMPLEXITY:
                    diags.append(
                        Diagnostic(
                            file_path=filename,
                            rule="high-complexity",
                            severity=Severity.WARNING,
                            category=Category.COMPLEXITY,
                            message=(
                                f"Function '{node.name}' has cyclomatic complexity"
                                f" {complexity} (max {MAX_COMPLEXITY})"
                            ),
                            help="Break into smaller functions or simplify conditional logic",
                            line=node.lineno,
                            column=node.col_offset,
                            cost=1.5,
                        )
                    )
        return diags
