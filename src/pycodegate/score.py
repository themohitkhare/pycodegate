"""Score calculation from diagnostics using weighted category-budget scoring."""

from __future__ import annotations

from collections import defaultdict

from pycodegate.constants import (
    CATEGORY_WEIGHTS,
    FRAMEWORK_CATEGORY_MAP,
    LABEL_CRITICAL,
    LABEL_EXCELLENT,
    LABEL_GREAT,
    LABEL_NEEDS_WORK,
)
from pycodegate.types import Diagnostic, Score


def _build_budget(
    max_deduction_overrides: dict | None,
) -> dict:
    """Return per-category maximum deduction budget normalised to sum to 100."""
    total_weight = sum(CATEGORY_WEIGHTS.values())
    max_deductions = {cat: round(w / total_weight * 100) for cat, w in CATEGORY_WEIGHTS.items()}

    # Fix rounding: adjust highest-weight category so sum == 100
    diff = 100 - sum(max_deductions.values())
    if diff != 0:
        highest = max(CATEGORY_WEIGHTS, key=CATEGORY_WEIGHTS.get)
        max_deductions[highest] += diff

    if max_deduction_overrides:
        for cat, val in max_deduction_overrides.items():
            if cat in max_deductions:
                max_deductions[cat] = max(0, min(100, val))

    return max_deductions


def _score_label(value: int) -> str:
    """Return a human-readable label for a numeric score."""
    if value >= 90:
        return LABEL_EXCELLENT
    if value >= 75:
        return LABEL_GREAT
    if value >= 50:
        return LABEL_NEEDS_WORK
    return LABEL_CRITICAL


def _category_deductions(diagnostics: list[Diagnostic], max_deductions: dict) -> dict:
    """Return the capped deduction per resolved category (diminishing returns applied).

    Within a category the top 3 findings count at full cost; additional findings
    apply diminishing returns (10% each) to reward fixing the worst issues first.
    """
    by_category: dict = defaultdict(list)
    for d in diagnostics:
        resolved = FRAMEWORK_CATEGORY_MAP.get(d.category, d.category)
        by_category[resolved].append(d)

    deductions: dict = {}
    for cat, diags in by_category.items():
        costs = sorted([d.cost for d in diags], reverse=True)
        cat_total = sum(c if i < 3 else c * 0.1 for i, c in enumerate(costs))
        cap = max_deductions.get(cat, 10)
        deductions[cat] = min(cat_total, cap)
    return deductions


def calculate_score(
    diagnostics: list[Diagnostic], max_deduction_overrides: dict | None = None
) -> Score:
    """Calculate a 0-100 health score from diagnostics using category budgets."""
    max_deductions = _build_budget(max_deduction_overrides)
    total_deduction = sum(_category_deductions(diagnostics, max_deductions).values())
    value = max(0, min(100, round(100 - total_deduction)))
    return Score(value=value, label=_score_label(value))


def category_breakdown(
    diagnostics: list[Diagnostic], max_deduction_overrides: dict | None = None
) -> dict:
    """Return {category: (earned, max)} using the SAME budget the score uses.

    Single source of truth so the displayed per-category sub-scores honour
    profile/config max-deduction overrides exactly as the headline score does.
    """
    max_deductions = _build_budget(max_deduction_overrides)
    deductions = _category_deductions(diagnostics, max_deductions)
    return {
        cat: (max_ded - round(deductions.get(cat, 0.0)), max_ded)
        for cat, max_ded in max_deductions.items()
    }
