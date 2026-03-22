from python_doctor.rules.performance import PerformanceRules


def _run(source: str) -> list:
    return PerformanceRules().check(source, "app.py")


def test_string_concat_in_loop():
    source = """
result = ""
for item in items:
    result += str(item)
"""
    diags = _run(source)
    assert any(d.rule == "no-string-concat-in-loop" for d in diags)


def test_global_import_in_function():
    source = """
def process():
    import json
    return json.dumps({})
"""
    diags = _run(source)
    assert any(d.rule == "no-import-in-function" for d in diags)


def test_top_level_import_is_ok():
    diags = _run("import json\njson.dumps({})")
    assert not any(d.rule == "no-import-in-function" for d in diags)


def test_star_import():
    diags = _run("from os.path import *")
    assert any(d.rule == "no-star-import" for d in diags)


def test_clean_code():
    source = """
import json

def process(items: list) -> str:
    parts = [str(item) for item in items]
    return json.dumps(parts)
"""
    diags = _run(source)
    assert diags == []
