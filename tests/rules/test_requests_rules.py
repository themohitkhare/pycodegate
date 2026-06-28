from pycodegate.rules.requests_rules import RequestsRules


def _run(source: str) -> list:
    return RequestsRules().check(source, "app.py")


def test_missing_timeout_flagged():
    source = """
import requests

resp = requests.get("https://example.com")
"""
    diags = _run(source)
    assert any(d.rule == "http-missing-timeout" for d in diags)


def test_timeout_present_ok():
    source = """
import requests

resp = requests.get("https://example.com", timeout=10)
"""
    diags = _run(source)
    assert not any(d.rule == "http-missing-timeout" for d in diags)


def test_dict_get_not_flagged():
    # `.get()` on a variable named client/session is not an HTTP call.
    source = """
def f(client, session, cache):
    a = client.get("key")
    b = session.get("thing")
    c = cache.get("x")
    return a, b, c
"""
    diags = _run(source)
    assert not any(d.rule == "http-missing-timeout" for d in diags)


def test_httpx_not_flagged_for_timeout():
    # httpx has a default timeout, so a missing one is not a problem.
    source = """
import httpx

resp = httpx.get("https://example.com")
"""
    diags = _run(source)
    assert not any(d.rule == "http-missing-timeout" for d in diags)


def test_requests_session_not_flagged_for_timeout():
    # requests.Session() takes no timeout argument; flagging it is a false positive.
    source = """
import requests

s = requests.Session()
"""
    diags = _run(source)
    assert not any(d.rule == "http-missing-timeout" for d in diags)


def test_verify_disabled_flagged():
    source = """
import requests

resp = requests.get("https://example.com", verify=False, timeout=10)
"""
    diags = _run(source)
    assert any(d.rule == "http-verify-disabled" for d in diags)


def test_verify_not_disabled_ok():
    source = """
import requests

resp = requests.get("https://example.com", timeout=10)
"""
    diags = _run(source)
    assert not any(d.rule == "http-verify-disabled" for d in diags)
