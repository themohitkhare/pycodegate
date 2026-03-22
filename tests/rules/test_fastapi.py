from python_doctor.rules.fastapi import FastAPIRules


def _run(source: str) -> list:
    return FastAPIRules().check(source, "main.py")


def test_sync_endpoint():
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/users")
def get_users():
    return []
"""
    diags = _run(source)
    assert any(d.rule == "prefer-async-endpoint" for d in diags)


def test_async_endpoint_ok():
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/users")
async def get_users():
    return []
"""
    diags = _run(source)
    assert not any(d.rule == "prefer-async-endpoint" for d in diags)


def test_missing_response_model():
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/users")
async def get_users():
    return []
"""
    diags = _run(source)
    assert any(d.rule == "missing-response-model" for d in diags)


def test_response_model_present_ok():
    source = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/users", response_model=list[dict])
async def get_users():
    return []
"""
    diags = _run(source)
    assert not any(d.rule == "missing-response-model" for d in diags)
