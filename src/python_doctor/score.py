"""Score calculation from diagnostics using weighted category-budget scoring."""

from __future__ import annotations

from collections import defaultdict

from python_doctor.constants import (
    CATEGORY_WEIGHTS,
    FRAMEWORK_CATEGORY_MAP,
    LABEL_CRITICAL,
    LABEL_EXCELLENT,
    LABEL_GREAT,
    LABEL_NEEDS_WORK,
)
from python_doctor.types import Diagnostic, Score


def calculate_score(
    diagnostics: list[Diagnostic], max_deduction_overrides: dict | None = None
) -> Score:
    """Calculate a 0-100 health score from diagnostics using category budgets.

    Each category has a weight that determines its maximum deduction budget.
    Within a category, the top 3 findings are counted at full cost; additional
    findings apply diminishing returns (10% each) to reward fixing top issues.
    """
    # 1. Compute max_deduction per category from weights
    total_weight = sum(CATEGORY_WEIGHTS.values())
    max_deductions = {cat: round(w / total_weight * 100) for cat, w in CATEGORY_WEIGHTS.items()}

    # Fix rounding: adjust highest-weight category so sum == 100
    diff = 100 - sum(max_deductions.values())
    if diff != 0:
        highest = max(CATEGORY_WEIGHTS, key=CATEGORY_WEIGHTS.get)
        max_deductions[highest] += diff

    # Apply overrides
    if max_deduction_overrides:
        for cat, val in max_deduction_overrides.items():
            if cat in max_deductions:
                max_deductions[cat] = val

    # 2. Group diagnostics by resolved category
    by_category: dict = defaultdict(list)
    for d in diagnostics:
        resolved = FRAMEWORK_CATEGORY_MAP.get(d.category, d.category)
        by_category[resolved].append(d)

    # 3. Calculate deduction per category with diminishing returns
    total_deduction = 0.0
    for cat, diags in by_category.items():
        costs = sorted([d.cost for d in diags], reverse=True)
        # Top 3 at full cost, rest at 10%
        cat_total = sum(c if i < 3 else c * 0.1 for i, c in enumerate(costs))
        cap = max_deductions.get(cat, 10)
        total_deduction += min(cat_total, cap)

    value = max(0, round(100 - total_deduction))

    if value >= 90:
        label = LABEL_EXCELLENT
    elif value >= 75:
        label = LABEL_GREAT
    elif value >= 50:
        label = LABEL_NEEDS_WORK
    else:
        label = LABEL_CRITICAL

    return Score(value=value, label=label)
