from python_doctor.rules.complexity import ComplexityRules
from python_doctor.types import Severity


def _run(source: str) -> list:
    return ComplexityRules().check(source, "app.py")


def test_simple_function_no_diagnostic():
    """A function with no branches has complexity 1 — no diagnostic expected."""
    source = """
def greet(name):
    return f"Hello, {name}"
"""
    diags = _run(source)
    assert diags == []


def test_high_complexity_warning():
    """A function exceeding complexity 15 produces a high-complexity warning."""
    # Build a function with many decision points to push complexity above 15.
    # Each if/elif adds 1, each for/while adds 1, and/or adds 1 each.
    source = """
def complex_function(a, b, c, d, e, f, g):
    result = 0
    if a:          # +1 = 2
        result += 1
    elif b:        # +1 = 3
        result += 2
    elif c:        # +1 = 4
        result += 3
    for i in range(10):  # +1 = 5
        result += i
    while d > 0:   # +1 = 6
        d -= 1
    if e and f:    # +1 (if) +1 (and) = 8
        result += e
    if f or g:     # +1 (if) +1 (or) = 10
        result += f
    if a and b and c:  # +1 (if) +2 (two ands) = 13
        result += 1
    assert result >= 0  # +1 = 14
    if a:          # +1 = 15
        x = 1 if b else 2  # +1 (IfExp) = 16
    return result
"""
    diags = _run(source)
    assert any(d.rule == "high-complexity" for d in diags)
    warning_diags = [d for d in diags if d.rule == "high-complexity"]
    assert all(d.severity == Severity.WARNING for d in warning_diags)
    assert all("complex_function" in d.message for d in warning_diags)
    assert all("max 15" in d.message for d in warning_diags)


def test_critical_complexity_error():
    """A function exceeding complexity 25 produces a critical-complexity error."""
    # Build a function with more than 25 decision points.
    branches = "\n".join([f"    if x == {i}:  # +1\n        result += {i}" for i in range(27)])
    source = f"""
def very_complex_function(x):
    result = 0
{branches}
    return result
"""
    diags = _run(source)
    assert any(d.rule == "critical-complexity" for d in diags)
    error_diags = [d for d in diags if d.rule == "critical-complexity"]
    assert all(d.severity == Severity.ERROR for d in error_diags)
    assert all("very_complex_function" in d.message for d in error_diags)
    assert all("max 15" in d.message for d in error_diags)


def test_high_complexity_not_error_below_25():
    """A function with complexity between 16 and 25 gets WARNING, not ERROR."""
    # Complexity of exactly 16 (just above threshold of 15).
    branches = "\n".join([f"    if x == {i}:\n        result += {i}" for i in range(16)])
    source = f"""
def moderate_function(x):
    result = 0
{branches}
    return result
"""
    diags = _run(source)
    # Should have a warning but no error
    assert any(d.rule == "high-complexity" for d in diags)
    assert not any(d.rule == "critical-complexity" for d in diags)


def test_syntax_error_returns_empty():
    """Invalid Python source returns no diagnostics."""
    diags = _run("def broken(")
    assert diags == []
