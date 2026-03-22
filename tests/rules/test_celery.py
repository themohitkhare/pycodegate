from pycodegate.rules.celery import CeleryRules


def _run(source: str) -> list:
    return CeleryRules().check(source, "tasks.py")


# -- celery-missing-bind --------------------------------------------------


def test_missing_bind():
    source = """
from celery import shared_task

@shared_task
def add(self, x, y):
    return x + y
"""
    diags = _run(source)
    assert any(d.rule == "celery-missing-bind" for d in diags)


def test_missing_bind_ok():
    source = """
from celery import shared_task

@shared_task(bind=True)
def add(self, x, y):
    return x + y
"""
    diags = _run(source)
    assert not any(d.rule == "celery-missing-bind" for d in diags)


# -- celery-retry-no-exc --------------------------------------------------


def test_retry_no_exc():
    source = """
@app.task(bind=True)
def fetch(self, url):
    try:
        pass
    except Exception as exc:
        self.retry()
"""
    diags = _run(source)
    assert any(d.rule == "celery-retry-no-exc" for d in diags)


def test_retry_with_exc_ok():
    source = """
@app.task(bind=True)
def fetch(self, url):
    try:
        pass
    except Exception as exc:
        self.retry(exc=exc)
"""
    diags = _run(source)
    assert not any(d.rule == "celery-retry-no-exc" for d in diags)


# -- celery-broad-autoretry ------------------------------------------------


def test_broad_autoretry():
    source = """
@app.task(autoretry_for=(Exception,))
def process(data):
    pass
"""
    diags = _run(source)
    assert any(d.rule == "celery-broad-autoretry" for d in diags)


def test_narrow_autoretry_ok():
    source = """
@app.task(autoretry_for=(ConnectionError, TimeoutError))
def process(data):
    pass
"""
    diags = _run(source)
    assert not any(d.rule == "celery-broad-autoretry" for d in diags)


# -- celery-direct-call ----------------------------------------------------


def test_direct_call():
    source = """
@app.task
def send_email(to, body):
    pass

send_email("a@b.com", "hi")
"""
    diags = _run(source)
    assert any(d.rule == "celery-direct-call" for d in diags)


def test_delay_call_ok():
    source = """
@app.task
def send_email(to, body):
    pass

send_email.delay("a@b.com", "hi")
"""
    diags = _run(source)
    assert not any(d.rule == "celery-direct-call" for d in diags)
