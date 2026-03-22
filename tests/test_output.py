from python_doctor.output import format_doctor_face, format_score_bar, format_summary
from python_doctor.types import Category, Diagnostic, ProjectInfo, ScanResult, Score, Severity


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
                file_path="app.py", rule="no-eval", severity=Severity.ERROR,
                category=Category.SECURITY, message="Avoid eval()",
                help="Use ast.literal_eval()", line=1,
            )
        ],
        project=ProjectInfo(
            path="/tmp/proj", python_version="3.12", framework="fastapi",
            package_manager="uv", test_framework="pytest",
            has_type_hints=True, source_file_count=42,
        ),
        elapsed_ms=1234,
    )
    text = format_summary(result)
    assert "85" in text
    assert "Great" in text
