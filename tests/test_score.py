from python_doctor.score import calculate_score
from python_doctor.types import Category, Diagnostic, Severity


def _make_diag(
    rule: str,
    severity: Severity = Severity.ERROR,
    category: Category = Category.SECURITY,
    cost: float = 1.0,
) -> Diagnostic:
    return Diagnostic(
        file_path="app.py",
        rule=rule,
        severity=severity,
        category=category,
        message="test",
        help="test",
        line=1,
        cost=cost,
    )


def test_perfect_score():
    """No diagnostics yields a perfect score of 100/Excellent."""
    score = calculate_score([])
    assert score.value == 100
    assert score.label == "Excellent"


def test_single_error_deduction():
    """One security error with cost=3.0 deducts 3 points from the security budget."""
    diag = _make_diag("no-eval", category=Category.SECURITY, cost=3.0)
    score = calculate_score([diag])
    # 100 - min(3.0, security_cap) = 97
    assert score.value == 97
    assert score.label == "Excellent"


def test_category_cap():
    """Many findings in one category don't exceed its max_deduction cap."""
    # Security cap is 23. 10 findings of cost=3.0 each = 30 > 23, capped at 23.
    diags = [_make_diag(f"sec-rule-{i}", category=Category.SECURITY, cost=3.0) for i in range(10)]
    score = calculate_score(diags)
    # Total deduction capped at security max (23), so score >= 77
    assert score.value >= 77
    # Verify it is capped and not 100 - (30) = 70
    assert score.value != 70


def test_diminishing_returns():
    """4+ findings in same category: first 3 at full cost, rest at 10%."""
    # 4 findings of cost=1.0 in DEAD_CODE:
    # cat_total = 1.0 + 1.0 + 1.0 + 0.1 = 3.1
    # dead_code cap = 5, so deduction = min(3.1, 5) = 3.1 -> round to 3
    diags = [
        _make_diag(f"dc-{i}", severity=Severity.WARNING, category=Category.DEAD_CODE, cost=1.0)
        for i in range(4)
    ]
    score = calculate_score(diags)
    # Without diminishing returns it would be 4.0, with it 3.1 -> score = 97
    assert score.value == 97


def test_multiple_categories():
    """Errors across categories sum correctly."""
    diags = [
        _make_diag("sec-1", category=Category.SECURITY, cost=3.0),
        _make_diag("corr-1", severity=Severity.ERROR, category=Category.CORRECTNESS, cost=2.0),
    ]
    score = calculate_score(diags)
    # security deduction: min(3.0, 23) = 3
    # correctness deduction: min(2.0, 19) = 2
    # total = 5, score = 95
    assert score.value == 95
    assert score.label == "Excellent"


def test_max_deduction_override():
    """Custom cap via max_deduction_overrides changes the capping behavior."""
    # Set security cap to 1 so even a cost=3.0 finding is capped at 1
    diag = _make_diag("no-eval", category=Category.SECURITY, cost=3.0)
    score = calculate_score([diag], max_deduction_overrides={Category.SECURITY: 1})
    assert score.value == 99


def test_framework_category_mapping():
    """Django diagnostics count under security budget (not a separate category)."""
    django_diag = _make_diag("no-debug-true", category=Category.DJANGO, cost=3.0)
    sec_diag = _make_diag("no-eval", category=Category.SECURITY, cost=3.0)
    # Both resolve to SECURITY category; top 3 at full cost
    score_combined = calculate_score([django_diag, sec_diag])
    # Both under SECURITY: sorted costs = [3.0, 3.0]; cat_total = 6.0; capped at 23
    # score = 100 - min(6, 23) = 94
    assert score_combined.value == 94

    # Verify Django alone deducts from security budget
    score_django_only = calculate_score([django_diag])
    assert score_django_only.value == 97  # 100 - 3


def test_score_floors_at_zero():
    """Extreme diagnostics never push the score below 0."""
    # Use overrides to make all budgets sum > 100 so score would go negative
    all_cats = [
        Category.SECURITY,
        Category.CORRECTNESS,
        Category.COMPLEXITY,
        Category.ARCHITECTURE,
        Category.PERFORMANCE,
        Category.DEAD_CODE,
    ]
    diags = [_make_diag(f"rule-{i}", category=cat, cost=100.0) for i, cat in enumerate(all_cats)]
    overrides = {cat: 20 for cat in all_cats}  # 6 * 20 = 120 total budget
    score = calculate_score(diags, max_deduction_overrides=overrides)
    assert score.value == 0
    assert score.label == "Critical"


def test_label_thresholds():
    """Score labels: 90+=Excellent, 75+=Great, 50+=Needs work, <50=Critical."""
    # Perfect score -> Excellent
    assert calculate_score([]).label == "Excellent"

    # Just below 90 -> Great: use override to craft exact deduction
    # Override security cap to 15 and add one cost=15 finding -> score=85
    diag_great = _make_diag("sec-1", category=Category.SECURITY, cost=15.0)
    score_great = calculate_score([diag_great], max_deduction_overrides={Category.SECURITY: 15})
    assert score_great.value == 85
    assert score_great.label == "Great"

    # Override security cap to 40 -> score=60 -> Needs work
    diag_needs_work = _make_diag("sec-1", category=Category.SECURITY, cost=40.0)
    score_needs_work = calculate_score(
        [diag_needs_work], max_deduction_overrides={Category.SECURITY: 40}
    )
    assert score_needs_work.value == 60
    assert score_needs_work.label == "Needs work"

    # Override security cap to 60 -> score=40 -> Critical
    diag_critical = _make_diag("sec-1", category=Category.SECURITY, cost=60.0)
    score_critical = calculate_score(
        [diag_critical], max_deduction_overrides={Category.SECURITY: 60}
    )
    assert score_critical.value == 40
    assert score_critical.label == "Critical"
