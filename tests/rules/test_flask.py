from python_doctor.rules.flask import FlaskRules


def _run(source: str, filename: str = "app.py") -> list:
    return FlaskRules().check(source, filename)


def test_secret_key_hardcoded():
    source = """
from flask import Flask
app = Flask(__name__)
app.secret_key = "super-secret-key-value"
"""
    diags = _run(source)
    assert any(d.rule == "no-flask-secret-in-source" for d in diags)


def test_debug_mode():
    source = """
from flask import Flask
app = Flask(__name__)
app.run(debug=True)
"""
    diags = _run(source)
    assert any(d.rule == "no-flask-debug-mode" for d in diags)


def test_sql_string_format():
    source = """
@app.route("/user/<user_id>")
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    db.execute(query)
"""
    diags = _run(source)
    assert any(d.rule == "no-sql-string-format" for d in diags)
