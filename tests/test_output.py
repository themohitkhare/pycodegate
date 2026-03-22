from io import StringIO

from rich.console import Console

from python_doctor.output import (
    format_doctor_face,
    format_score_bar,
    format_summary,
    print_scan_result,
)
from python_doctor.types import (
    Category,
    Diagnostic,
    ProjectInfo,
    ScanResult,
    Score,
    Severity,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_project(**kwargs) -> ProjectInfo:
    defaults = dict(
        path="/tmp/proj",
        python_version="3.12",
        framework=None,
        package_manager="uv",
        test_framework="pytest",
        has_type_hints=True,
        source_file_count=10,
    )
    defaults.update(kwargs)
    return ProjectInfo(**defaults)


def _make_result(diagnostics=None, score_value=85, profile="library") -> ScanResult:
    return ScanResult(
        score=Score(value=score_value, label="Great"),
        diagnostics=diagnostics or [],
        project=_make_project(),
        elapsed_ms=100,
        profile=profile,
    )


def _capture_output(result: ScanResult, verbose: bool = False) -> str:
    """Run print_scan_result and capture Rich console output as plain text."""
    buf = StringIO()
    console = Console(file=buf, highlight=False, markup=True, no_color=True)
    # Patch console into print_scan_result by monkey-patching module
    import python_doctor.output as output_mod

    original_console_cls = output_mod.Console

    class _FakeConsole(Console):
        def __new__(cls, **kw):
            return console

    output_mod.Console = _FakeConsole
    try:
        print_scan_result(result, verbose=verbose)
    finally:
        output_mod.Console = original_console_cls

    return buf.getvalue()


# ---------------------------------------------------------------------------
# Existing tests (preserved)
# ---------------------------------------------------------------------------


def test_score_bar_full():
    bar = format_score_bar(100)
    assert "100" in bar


def test_score_bar_empty():
    bar = format_score_bar(0)
    assert "0" in bar


def test_doctor_face_happy():
    face = format_doctor_face(90)
    assert face


def test_doctor_face_sad():
    face = format_doctor_face(30)
    assert face


def test_format_summary():
    result = ScanResult(
        score=Score(value=85, label="Great"),
        diagnostics=[
            Diagnostic(
                file_path="app.py",
                rule="no-eval",
                severity=Severity.ERROR,
                category=Category.SECURITY,
                message="Avoid eval()",
                help="Use ast.literal_eval()",
                line=1,
            )
        ],
        project=ProjectInfo(
            path="/tmp/proj",
            python_version="3.12",
            framework="fastapi",
            package_manager="uv",
            test_framework="pytest",
            has_type_hints=True,
            source_file_count=42,
        ),
        elapsed_ms=1234,
    )
    text = format_summary(result)
    assert "85" in text
    assert "Great" in text


# ---------------------------------------------------------------------------
# New tests: category-grouped output
# ---------------------------------------------------------------------------


def test_category_headers_appear():
    """Each category in CATEGORY_WEIGHTS should appear as a header."""
    result = _make_result()
    output = _capture_output(result)
    # At minimum the categories we know exist should show up
    assert "Security" in output
    assert "Correctness" in output
    assert "Complexity" in output
    assert "Architecture" in output
    assert "Performance" in output
    assert "Structure" in output
    assert "Imports" in output
    assert "Dead Code" in output


def test_all_clear_for_clean_categories():
    """Categories with zero diagnostics show 'All clear.'."""
    result = _make_result(diagnostics=[])
    output = _capture_output(result)
    assert "All clear." in output


def test_sub_scores_appear():
    """Sub-scores in (earned/max) format should appear for each category."""
    result = _make_result(diagnostics=[])
    output = _capture_output(result)
    # With no diagnostics every category earns its max, so earned==max
    # Check at least one pattern like "(24/24)" or similar parenthesised numbers
    import re

    matches = re.findall(r"\(\d+/\d+\)", output)
    assert len(matches) >= len(
        [
            "Security",
            "Correctness",
            "Complexity",
            "Architecture",
            "Performance",
            "Structure",
            "Imports",
            "Dead Code",
        ]
    ), f"Expected at least 8 sub-score tokens, got: {matches}"


def test_warning_appears_in_correct_category():
    """A diagnostic for ARCHITECTURE should show under the Architecture header."""
    diag = Diagnostic(
        file_path="app.py",
        rule="no-deep-nesting",
        severity=Severity.WARNING,
        category=Category.ARCHITECTURE,
        message="Nesting too deep",
        help="Reduce nesting",
        line=10,
    )
    result = _make_result(diagnostics=[diag])
    output = _capture_output(result)
    assert "no-deep-nesting" in output
    assert "Architecture" in output


def test_error_icon_for_error_severity():
    """ERROR diagnostics should render with an error marker."""
    diag = Diagnostic(
        file_path="app.py",
        rule="no-eval",
        severity=Severity.ERROR,
        category=Category.SECURITY,
        message="Avoid eval",
        help="",
        line=1,
    )
    result = _make_result(diagnostics=[diag])
    output = _capture_output(result)
    assert "no-eval" in output
    # Security category should not show "All clear."
    lines = output.splitlines()
    sec_idx = next(i for i, line in enumerate(lines) if "Security" in line)
    # The next non-empty line after the Security header should NOT be "All clear."
    following = [line for line in lines[sec_idx + 1 :] if line.strip()]
    assert following, "No content after Security header"
    assert "All clear" not in following[0]


def test_rule_count_shown():
    """Rule name and occurrence count should appear (e.g. 'no-deep-nesting × 3')."""
    diags = [
        Diagnostic(
            file_path=f"app{i}.py",
            rule="no-deep-nesting",
            severity=Severity.WARNING,
            category=Category.ARCHITECTURE,
            message="Nesting too deep",
            help="",
            line=i,
        )
        for i in range(3)
    ]
    result = _make_result(diagnostics=diags)
    output = _capture_output(result)
    assert "no-deep-nesting" in output
    assert "3" in output


def test_profile_shown_in_header():
    """Profile should appear in the header when set."""
    result = _make_result(profile="cli")
    output = _capture_output(result)
    assert "cli" in output


def test_profile_none_not_shown():
    """When profile is None it should not appear in output."""
    result = _make_result(profile=None)
    output = _capture_output(result)
    assert "Profile" not in output


def test_verbose_shows_file_paths():
    """In verbose mode, file paths should appear under each rule."""
    diag = Diagnostic(
        file_path="some/path/app.py",
        rule="no-deep-nesting",
        severity=Severity.WARNING,
        category=Category.ARCHITECTURE,
        message="Nesting too deep",
        help="",
        line=5,
    )
    result = _make_result(diagnostics=[diag])
    output = _capture_output(result, verbose=True)
    assert "some/path/app.py" in output
    assert "5" in output


def test_category_with_no_diagnostics_is_all_clear():
    """A category with no findings always shows All clear."""
    # Security has no diagnostics → should say All clear.
    diag = Diagnostic(
        file_path="app.py",
        rule="no-deep-nesting",
        severity=Severity.WARNING,
        category=Category.ARCHITECTURE,
        message="Nesting too deep",
        help="",
        line=1,
    )
    result = _make_result(diagnostics=[diag])
    output = _capture_output(result)
    # Security should still be "All clear."
    lines = output.splitlines()
    sec_idx = next((i for i, line in enumerate(lines) if "Security" in line), None)
    assert sec_idx is not None
    following = [line for line in lines[sec_idx + 1 :] if line.strip()]
    assert following[0].strip().endswith("All clear.")
