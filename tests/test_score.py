from python_doctor.score import calculate_score
from python_doctor.types import Category, Diagnostic, Severity


def _make_diag(rule: str, severity: Severity = Severity.ERROR) -> Diagnostic:
    return Diagnostic(
        file_path="app.py",
        rule=rule,
        severity=severity,
        category=Category.SECURITY,
        message="test",
        help="test",
        line=1,
    )


def test_perfect_score_no_diagnostics():
    score = calculate_score([])
    assert score.value == 100
    assert score.label == "Great"


def test_errors_reduce_score():
    diags = [_make_diag("rule-a"), _make_diag("rule-b")]
    score = calculate_score(diags)
    # 100 - 2 * 1.5 = 97
    assert score.value == 97


def test_warnings_reduce_score_less():
    diags = [_make_diag("rule-a", Severity.WARNING), _make_diag("rule-b", Severity.WARNING)]
    score = calculate_score(diags)
    # 100 - 2 * 0.75 = 98 (rounded)
    assert score.value == 98


def test_duplicate_rules_counted_once():
    diags = [_make_diag("rule-a"), _make_diag("rule-a"), _make_diag("rule-a")]
    score = calculate_score(diags)
    # 100 - 1 * 1.5 = 98 (rounded)
    assert score.value == 98


def test_score_floors_at_zero():
    diags = [_make_diag(f"rule-{i}") for i in range(100)]
    score = calculate_score(diags)
    assert score.value == 0
    assert score.label == "Critical"


def test_label_thresholds():
    assert calculate_score([]).label == "Great"
    # 50 unique error rules: 100 - 50*1.5 = 25
    diags_25 = [_make_diag(f"r-{i}") for i in range(50)]
    assert calculate_score(diags_25).label == "Critical"
    # 20 unique error rules: 100 - 20*1.5 = 70
    diags_70 = [_make_diag(f"r-{i}") for i in range(20)]
    assert calculate_score(diags_70).label == "Needs work"
