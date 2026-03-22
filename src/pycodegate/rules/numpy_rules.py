"""NumPy rules: array equality in boolean context, builtins on arrays, NaN in int arrays."""

from __future__ import annotations

import ast

from pycodegate.rules.base import BaseRules
from pycodegate.types import Category, Diagnostic, Severity

_NP_ARRAY_CONSTRUCTORS = {"array", "zeros", "ones", "empty", "arange", "linspace"}
_PYTHON_BUILTINS = {"sum", "max", "min", "any", "all"}


class NumpyRules(BaseRules):
    """Checks for common NumPy misuse."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.If, ast.While)):
                diags.extend(self._check_array_equality(node, filename))
            if isinstance(node, ast.Call):
                diags.extend(self._check_builtin_on_array(node, filename))
                diags.extend(self._check_nan_in_int_array(node, filename))
        return diags

    # ------------------------------------------------------------------
    # Rule 1: numpy-array-equality
    # ------------------------------------------------------------------

    def _is_np_array_call(self, node: ast.expr) -> bool:
        """Return True if the node is a call to an np array constructor."""
        if not isinstance(node, ast.Call):
            return False
        func = node.func
        return (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "np"
            and func.attr in _NP_ARRAY_CONSTRUCTORS
        )

    def _compare_has_array(self, node: ast.Compare) -> bool:
        """Return True if a Compare uses == or != with an np array call on either side."""
        for op in node.ops:
            if isinstance(op, (ast.Eq, ast.NotEq)):
                all_operands = [node.left, *node.comparators]
                if any(self._is_np_array_call(operand) for operand in all_operands):
                    return True
        return False

    def _check_array_equality(self, node: ast.If | ast.While, filename: str) -> list[Diagnostic]:
        test = node.test
        flagged: list[ast.AST] = []

        if isinstance(test, ast.Compare) and self._compare_has_array(test):
            flagged.append(test)
        elif isinstance(test, ast.BoolOp):
            for value in test.values:
                if isinstance(value, ast.Compare) and self._compare_has_array(value):
                    flagged.append(value)

        return [
            Diagnostic(
                file_path=filename,
                rule="numpy-array-equality",
                severity=Severity.ERROR,
                category=Category.NUMPY,
                message="Array comparison in boolean context — raises ValueError at runtime",
                help="Use np.array_equal(a, b) or np.allclose(a, b) for float arrays",
                line=cmp.lineno,
                column=cmp.col_offset,
                cost=2.0,
            )
            for cmp in flagged
        ]

    # ------------------------------------------------------------------
    # Rule 2: numpy-builtin-on-array
    # ------------------------------------------------------------------

    def _is_np_call(self, node: ast.expr) -> bool:
        """Return True if node is any call whose func involves 'np'."""
        if not isinstance(node, ast.Call):
            return False
        func = node.func
        return (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "np"
        )

    def _check_builtin_on_array(self, node: ast.Call, filename: str) -> list[Diagnostic]:
        if not (isinstance(node.func, ast.Name) and node.func.id in _PYTHON_BUILTINS):
            return []
        if not node.args:
            return []
        if not self._is_np_call(node.args[0]):
            return []
        name = node.func.id
        return [
            Diagnostic(
                file_path=filename,
                rule="numpy-builtin-on-array",
                severity=Severity.WARNING,
                category=Category.NUMPY,
                message=f"Python builtin '{name}()' on numpy array — use np.{name}() for correct results",
                help=f"Replace with np.{name}() or array.{name}()",
                line=node.lineno,
                column=node.col_offset,
                cost=1.0,
            )
        ]

    # ------------------------------------------------------------------
    # Rule 3: numpy-nan-in-int-array
    # ------------------------------------------------------------------

    def _check_nan_in_int_array(self, node: ast.Call, filename: str) -> list[Diagnostic]:
        if not self._is_np_array_literal(node):
            return []

        elements = node.args[0].elts
        has_int = any(self._is_int_literal(e) for e in elements)
        has_none_or_nan = any(self._is_none_or_nan(e) for e in elements)

        if not (has_int and has_none_or_nan):
            return []
        return [
            Diagnostic(
                file_path=filename,
                rule="numpy-nan-in-int-array",
                severity=Severity.WARNING,
                category=Category.NUMPY,
                message="Mixing integers with None/NaN in np.array() — silently coerces to object/float dtype",
                help="Use a masked array or pandas nullable integer type instead",
                line=node.lineno,
                column=node.col_offset,
                cost=1.0,
            )
        ]

    @staticmethod
    def _is_np_array_literal(node: ast.Call) -> bool:
        func = node.func
        return (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id == "np"
            and func.attr == "array"
            and bool(node.args)
            and isinstance(node.args[0], ast.List)
        )

    @staticmethod
    def _is_int_literal(elt: ast.expr) -> bool:
        return (
            isinstance(elt, ast.Constant)
            and isinstance(elt.value, int)
            and not isinstance(elt.value, bool)
        )

    @staticmethod
    def _is_none_or_nan(elt: ast.expr) -> bool:
        if isinstance(elt, ast.Constant) and elt.value is None:
            return True
        return (
            isinstance(elt, ast.Attribute)
            and isinstance(elt.value, ast.Name)
            and elt.value.id == "np"
            and elt.attr == "nan"
        )
