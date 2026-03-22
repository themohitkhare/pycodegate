from pycodegate.rules.sqlalchemy import SQLAlchemyRules


def _run(source: str) -> list:
    return SQLAlchemyRules().check(source, "models.py")


# -- sqla-sql-injection ------------------------------------------------


def test_sql_injection_fstring():
    source = """
from sqlalchemy import text
q = text(f"SELECT * FROM users WHERE id = {user_id}")
"""
    diags = _run(source)
    assert any(d.rule == "sqla-sql-injection" for d in diags)


def test_sql_injection_parameterized_ok():
    source = """
from sqlalchemy import text
q = text("SELECT * FROM users WHERE id = :id")
"""
    diags = _run(source)
    assert not any(d.rule == "sqla-sql-injection" for d in diags)


# -- sqla-identity-compare ---------------------------------------------


def test_identity_compare_is_none():
    source = """
session.query(User).filter(User.name is None)
"""
    diags = _run(source)
    assert any(d.rule == "sqla-identity-compare" for d in diags)


def test_identity_compare_eq_none_ok():
    source = """
session.query(User).filter(User.name == None)
"""
    diags = _run(source)
    assert not any(d.rule == "sqla-identity-compare" for d in diags)


# -- sqla-mutable-default ----------------------------------------------


def test_mutable_default_list_literal():
    source = """
from sqlalchemy import Column, JSON
tags = Column(JSON, default=[])
"""
    diags = _run(source)
    assert any(d.rule == "sqla-mutable-default" for d in diags)


def test_mutable_default_callable_ok():
    source = """
from sqlalchemy import Column, JSON
tags = Column(JSON, default=list)
"""
    diags = _run(source)
    assert not any(d.rule == "sqla-mutable-default" for d in diags)


# -- sqla-len-all -------------------------------------------------------


def test_len_all_flagged():
    source = """
count = len(session.query(User).all())
"""
    diags = _run(source)
    assert any(d.rule == "sqla-len-all" for d in diags)


def test_len_list_ok():
    source = """
count = len([1, 2, 3])
"""
    diags = _run(source)
    assert not any(d.rule == "sqla-len-all" for d in diags)
