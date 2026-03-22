"""Pydantic-specific rules: optional fields, validators, V1 deprecations."""

from __future__ import annotations

import ast

from pycodegate.rules.base import BaseRules
from pycodegate.types import Category, Diagnostic, Severity


def _is_basemodel_subclass(node: ast.ClassDef) -> bool:
    """Check if any base in node.bases is a Name with id 'BaseModel'."""
    return any(isinstance(base, ast.Name) and base.id == "BaseModel" for base in node.bases)


class PydanticRules(BaseRules):
    """Pydantic framework-specific checks."""

    def check(self, source: str, filename: str) -> list[Diagnostic]:
        tree = self._parse(source)
        if tree is None:
            return []

        diags: list[Diagnostic] = []
        diags.extend(self._check_v1_validator_import(tree, filename))
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and _is_basemodel_subclass(node):
                diags.extend(self._check_optional_no_default(node, filename))
                diags.extend(self._check_validator_no_return(node, filename))
                diags.extend(self._check_v1_validator_decorator(node, filename))
                diags.extend(self._check_v1_config(node, filename))
                diags.extend(self._check_init_override(node, filename))
                diags.extend(self._check_validator_no_classmethod(node, filename))
        return diags

    # ------------------------------------------------------------------
    # Rule 1: pydantic-optional-no-default
    # ------------------------------------------------------------------

    def _check_optional_no_default(self, cls: ast.ClassDef, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in cls.body:
            if not isinstance(node, ast.AnnAssign):
                continue
            if node.value is not None:
                continue
            if not self._is_optional_annotation(node.annotation):
                continue
            name = node.target.id if isinstance(node.target, ast.Name) else "?"
            diags.append(
                Diagnostic(
                    file_path=filename,
                    rule="pydantic-optional-no-default",
                    severity=Severity.ERROR,
                    category=Category.PYDANTIC,
                    message=f"Optional field '{name}' has no default — will be required in Pydantic V2",
                    help="Add '= None' to make the field truly optional",
                    line=node.lineno,
                    column=node.col_offset,
                    cost=2.0,
                )
            )
        return diags

    @staticmethod
    def _is_optional_annotation(ann: ast.expr) -> bool:
        # Optional[X]
        if (
            isinstance(ann, ast.Subscript)
            and isinstance(ann.value, ast.Name)
            and ann.value.id == "Optional"
        ):
            return True
        # X | None
        if isinstance(ann, ast.BinOp) and isinstance(ann.op, ast.BitOr):
            if (isinstance(ann.right, ast.Constant) and ann.right.value is None) or (
                isinstance(ann.left, ast.Constant) and ann.left.value is None
            ):
                return True
        return False

    # ------------------------------------------------------------------
    # Rule 2: pydantic-validator-no-return
    # ------------------------------------------------------------------

    def _check_validator_no_return(self, cls: ast.ClassDef, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in cls.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not self._has_validator_decorator(node):
                continue
            if self._has_return_with_value(node):
                continue
            diags.append(
                Diagnostic(
                    file_path=filename,
                    rule="pydantic-validator-no-return",
                    severity=Severity.WARNING,
                    category=Category.PYDANTIC,
                    message=f"Validator '{node.name}' may not return a value — field will silently become None",
                    help="Add 'return v' (field_validator) or 'return self' (model_validator)",
                    line=node.lineno,
                    column=node.col_offset,
                    cost=1.0,
                )
            )
        return diags

    @staticmethod
    def _has_validator_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name) and dec.id in (
                "field_validator",
                "model_validator",
                "validator",
            ):
                return True
            if (
                isinstance(dec, ast.Call)
                and isinstance(dec.func, ast.Name)
                and dec.func.id in ("field_validator", "model_validator", "validator")
            ):
                return True
        return False

    @staticmethod
    def _has_return_with_value(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value is not None:
                return True
        return False

    # ------------------------------------------------------------------
    # Rule 3: pydantic-v1-validator (import form)
    # ------------------------------------------------------------------

    def _check_v1_validator_import(self, tree: ast.Module, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "pydantic":
                for alias in node.names:
                    if alias.name == "validator":
                        diags.append(
                            Diagnostic(
                                file_path=filename,
                                rule="pydantic-v1-validator",
                                severity=Severity.WARNING,
                                category=Category.PYDANTIC,
                                message="Using deprecated Pydantic V1 '@validator' — use '@field_validator' instead",
                                help="Replace @validator with @field_validator and update the signature",
                                line=node.lineno,
                                column=node.col_offset,
                                cost=1.0,
                            )
                        )
        return diags

    # ------------------------------------------------------------------
    # Rule 3 (decorator form): pydantic-v1-validator
    # ------------------------------------------------------------------

    def _check_v1_validator_decorator(self, cls: ast.ClassDef, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in cls.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                dec_name = None
                if isinstance(dec, ast.Name):
                    dec_name = dec.id
                elif isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name):
                    dec_name = dec.func.id
                if dec_name == "validator":
                    diags.append(
                        Diagnostic(
                            file_path=filename,
                            rule="pydantic-v1-validator",
                            severity=Severity.WARNING,
                            category=Category.PYDANTIC,
                            message="Using deprecated Pydantic V1 '@validator' — use '@field_validator' instead",
                            help="Replace @validator with @field_validator and update the signature",
                            line=dec.lineno,
                            column=dec.col_offset,
                            cost=1.0,
                        )
                    )
        return diags

    # ------------------------------------------------------------------
    # Rule 4: pydantic-v1-config
    # ------------------------------------------------------------------

    def _check_v1_config(self, cls: ast.ClassDef, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in cls.body:
            if isinstance(node, ast.ClassDef) and node.name == "Config":
                diags.append(
                    Diagnostic(
                        file_path=filename,
                        rule="pydantic-v1-config",
                        severity=Severity.WARNING,
                        category=Category.PYDANTIC,
                        message="Using deprecated 'class Config' — use 'model_config = ConfigDict(...)' instead",
                        help="Replace inner Config class with model_config = ConfigDict(...)",
                        line=node.lineno,
                        column=node.col_offset,
                        cost=1.0,
                    )
                )
        return diags

    # ------------------------------------------------------------------
    # Rule 5: pydantic-init-override
    # ------------------------------------------------------------------

    def _check_init_override(self, cls: ast.ClassDef, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in cls.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            if node.name != "__init__":
                continue
            if not self._calls_super_init(node):
                diags.append(
                    Diagnostic(
                        file_path=filename,
                        rule="pydantic-init-override",
                        severity=Severity.ERROR,
                        category=Category.PYDANTIC,
                        message="__init__ override without super().__init__() bypasses Pydantic validation",
                        help="Use model_post_init() for post-init logic, or call super().__init__(**kwargs)",
                        line=node.lineno,
                        column=node.col_offset,
                        cost=2.0,
                    )
                )
        return diags

    @staticmethod
    def _calls_super_init(node: ast.FunctionDef) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                if (
                    child.func.attr == "__init__"
                    and isinstance(child.func.value, ast.Call)
                    and isinstance(child.func.value.func, ast.Name)
                    and child.func.value.func.id == "super"
                ):
                    return True
        return False

    # ------------------------------------------------------------------
    # Rule 6: pydantic-validator-no-classmethod
    # ------------------------------------------------------------------

    def _check_validator_no_classmethod(self, cls: ast.ClassDef, filename: str) -> list[Diagnostic]:
        diags: list[Diagnostic] = []
        for node in cls.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not self._has_field_validator_decorator(node):
                continue
            if self._has_classmethod_decorator(node):
                continue
            diags.append(
                Diagnostic(
                    file_path=filename,
                    rule="pydantic-validator-no-classmethod",
                    severity=Severity.ERROR,
                    category=Category.PYDANTIC,
                    message=f"@field_validator '{node.name}' missing @classmethod decorator",
                    help="Add @classmethod below @field_validator",
                    line=node.lineno,
                    column=node.col_offset,
                    cost=2.0,
                )
            )
        return diags

    @staticmethod
    def _has_field_validator_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name) and dec.id == "field_validator":
                return True
            if (
                isinstance(dec, ast.Call)
                and isinstance(dec.func, ast.Name)
                and dec.func.id == "field_validator"
            ):
                return True
        return False

    @staticmethod
    def _has_classmethod_decorator(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name) and dec.id == "classmethod":
                return True
        return False
