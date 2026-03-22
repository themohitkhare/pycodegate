from python_doctor.rules.security import SecurityRules
from python_doctor.types import Severity


def _run(source: str, filename: str = "app.py") -> list:
    return SecurityRules().check(source, filename)


def test_no_eval_detected():
    diags = _run("result = eval(user_input)")
    assert len(diags) == 1
    assert diags[0].rule == "no-eval"
    assert diags[0].severity == Severity.ERROR


def test_no_exec_detected():
    diags = _run("exec(code_string)")
    assert len(diags) == 1
    assert diags[0].rule == "no-exec"


def test_no_pickle_load():
    diags = _run("import pickle\ndata = pickle.load(f)")
    assert any(d.rule == "no-pickle-load" for d in diags)


def test_no_yaml_unsafe_load():
    diags = _run("import yaml\ndata = yaml.load(f)")
    assert any(d.rule == "no-unsafe-yaml-load" for d in diags)


def test_yaml_safe_load_is_ok():
    diags = _run("import yaml\ndata = yaml.safe_load(f)")
    assert not any(d.rule == "no-unsafe-yaml-load" for d in diags)


def test_no_hardcoded_secrets():
    diags = _run('API_KEY = "sk-1234567890abcdef1234567890abcdef"')
    assert any(d.rule == "no-hardcoded-secret" for d in diags)


def test_no_hardcoded_password():
    diags = _run('PASSWORD = "hunter2"')
    assert any(d.rule == "no-hardcoded-secret" for d in diags)


def test_no_md5_usage():
    diags = _run("import hashlib\nhashlib.md5(data)")
    assert any(d.rule == "no-weak-hash" for d in diags)


def test_no_sha1_usage():
    diags = _run("import hashlib\nhashlib.sha1(data)")
    assert any(d.rule == "no-weak-hash" for d in diags)


def test_clean_code_no_issues():
    diags = _run("def greet(name: str) -> str:\n    return f'Hello, {name}'")
    assert diags == []
