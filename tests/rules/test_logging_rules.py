from pycodegate.rules.logging_rules import LoggingRules
from pycodegate.types import Severity


def _run(source: str, filename: str = "app.py") -> list:
    return LoggingRules().check(source, filename)


# --- logging-fstring ---


def test_logging_fstring_detected():
    source = "logger.info(f'User {user_id} logged in')"
    diags = _run(source)
    assert len(diags) == 1
    assert diags[0].rule == "logging-fstring"
    assert diags[0].severity == Severity.WARNING


def test_logging_percent_style_ok():
    source = "logger.info('User %s logged in', user_id)"
    diags = _run(source)
    assert not any(d.rule == "logging-fstring" for d in diags)


# --- logging-root-logger ---


def test_logging_root_logger_detected():
    source = "import logging\nlogging.info('starting up')"
    diags = _run(source)
    assert any(d.rule == "logging-root-logger" for d in diags)


def test_logging_named_logger_ok():
    source = "import logging\nlogger = logging.getLogger(__name__)\nlogger.info('starting up')"
    diags = _run(source)
    assert not any(d.rule == "logging-root-logger" for d in diags)


# --- logging-error-no-exc-info ---


def test_logging_error_no_exc_info_detected():
    source = "try:\n    do_something()\nexcept Exception as e:\n    logger.error('failed')\n"
    diags = _run(source)
    assert any(d.rule == "logging-error-no-exc-info" for d in diags)


def test_logging_error_with_exc_info_ok():
    source = (
        "try:\n"
        "    do_something()\n"
        "except Exception as e:\n"
        "    logger.error('failed', exc_info=True)\n"
    )
    diags = _run(source)
    assert not any(d.rule == "logging-error-no-exc-info" for d in diags)
