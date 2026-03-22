from python_doctor.types import Category, Diagnostic, ProjectInfo, ScanResult, Score, Severity


def test_diagnostic_creation():
    d = Diagnostic(
        file_path="app.py",
        rule="no-eval",
        severity=Severity.ERROR,
        category=Category.SECURITY,
        message="Avoid eval() with user input",
        help="Use ast.literal_eval() instead",
        line=10,
        column=4,
    )
    assert d.file_path == "app.py"
    assert d.severity == Severity.ERROR
    assert d.category == Category.SECURITY


def test_project_info_creation():
    p = ProjectInfo(
        path="/tmp/myproject",
        python_version="3.12",
        framework="django",
        package_manager="uv",
        test_framework="pytest",
        has_type_hints=True,
        source_file_count=42,
    )
    assert p.framework == "django"
    assert p.source_file_count == 42


def test_score_creation():
    s = Score(value=82, label="Great")
    assert s.value == 82
    assert s.label == "Great"


def test_scan_result_creation():
    result = ScanResult(
        score=Score(value=75, label="Great"),
        diagnostics=[],
        project=ProjectInfo(
            path="/tmp/p",
            python_version="3.11",
            framework=None,
            package_manager="pip",
            test_framework=None,
            has_type_hints=False,
            source_file_count=5,
        ),
        elapsed_ms=1200,
    )
    assert result.score.value == 75
    assert result.diagnostics == []
