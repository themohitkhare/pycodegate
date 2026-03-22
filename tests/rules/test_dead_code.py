from python_doctor.rules.dead_code import DeadCodeRules
from python_doctor.types import Category


def test_detects_unused_function(tmp_path):
    (tmp_path / "app.py").write_text("""
def used_function():
    return 42

def unused_function():
    return 99

result = used_function()
""")
    rules = DeadCodeRules()
    diags = rules.check_project(str(tmp_path))
    assert any(d.rule == "dead-code" and "unused_function" in d.message for d in diags)
    assert all(d.category == Category.DEAD_CODE for d in diags)


def test_no_dead_code_in_clean_project(tmp_path):
    (tmp_path / "app.py").write_text("""
def greet(name):
    return f"Hello, {name}"

print(greet("world"))
""")
    rules = DeadCodeRules()
    diags = rules.check_project(str(tmp_path))
    assert not any("greet" in d.message for d in diags)
