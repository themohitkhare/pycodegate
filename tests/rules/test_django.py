from python_doctor.rules.django import DjangoRules


def _run(source: str, filename: str = "views.py") -> list:
    return DjangoRules().check(source, filename)


def test_raw_sql():
    source = """
from django.db import connection
cursor = connection.cursor()
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
"""
    diags = _run(source)
    assert any(d.rule == "no-raw-sql-injection" for d in diags)


def test_debug_true_in_settings():
    diags = _run("DEBUG = True", filename="settings.py")
    assert any(d.rule == "no-debug-true" for d in diags)


def test_debug_in_non_settings_ok():
    diags = _run("DEBUG = True", filename="views.py")
    assert not any(d.rule == "no-debug-true" for d in diags)


def test_missing_select_related():
    source = """
for order in Order.objects.all():
    print(order.customer.name)
"""
    diags = _run(source)
    assert any(d.rule == "no-n-plus-one-query" for d in diags)


def test_secret_key_in_settings():
    diags = _run('SECRET_KEY = "django-insecure-abc123def456"', filename="settings.py")
    assert any(d.rule == "no-secret-key-in-source" for d in diags)
