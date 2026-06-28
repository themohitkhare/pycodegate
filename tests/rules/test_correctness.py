from pycodegate.rules.correctness import CorrectnessRules


def _run(source: str) -> list:
    return CorrectnessRules().check(source, "app.py")


def test_mutable_default_arg_list():
    diags = _run("def foo(items=[]):\n    pass")
    assert any(d.rule == "no-mutable-default" for d in diags)


def test_mutable_default_arg_dict():
    diags = _run("def foo(config={}):\n    pass")
    assert any(d.rule == "no-mutable-default" for d in diags)


def test_bare_except():
    diags = _run("try:\n    pass\nexcept:\n    pass")
    assert any(d.rule == "no-bare-except" for d in diags)


def test_specific_exception_ok():
    diags = _run("try:\n    pass\nexcept ValueError:\n    pass")
    assert not any(d.rule == "no-bare-except" for d in diags)


def test_broad_exception_not_flagged():
    # `except Exception` is idiomatic at boundaries — too noisy to flag in a gate.
    diags = _run("try:\n    pass\nexcept Exception:\n    pass")
    assert not any(d.rule == "no-broad-exception" for d in diags)


def test_assert_reported_regardless_of_filename():
    # The rule reports asserts; scan-level suppression handles test files.
    diags = _run("assert user.is_admin, 'Must be admin'")
    assert any(d.rule == "no-assert-in-production" for d in diags)


def test_mutable_default_reported_once_per_function():
    diags = _run("def foo(a=[], b={}):\n    pass")
    mutable = [d for d in diags if d.rule == "no-mutable-default"]
    assert len(mutable) == 1


def test_no_return_in_init():
    source = """
class Foo:
    def __init__(self):
        return 42
"""
    diags = _run(source)
    assert any(d.rule == "no-return-in-init" for d in diags)


def test_init_return_none_ok():
    source = """
class Foo:
    def __init__(self):
        return
"""
    diags = _run(source)
    assert not any(d.rule == "no-return-in-init" for d in diags)


def test_return_in_nested_function_inside_init_ok():
    # A return inside a closure defined in __init__ must NOT be flagged.
    source = """
class Foo:
    def __init__(self):
        def helper():
            return 42
        self.helper = helper
"""
    diags = _run(source)
    assert not any(d.rule == "no-return-in-init" for d in diags)
