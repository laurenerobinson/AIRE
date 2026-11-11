"""Request-local public phase notifications; no Java objects cross threads."""
from contextlib import contextmanager
from contextvars import ContextVar

_CALLBACK = ContextVar('aire_analysis_progress', default=None)


@contextmanager
def analysis_progress(callback):
    token = _CALLBACK.set(callback)
    try:
        yield
    finally:
        _CALLBACK.reset(token)


def report_progress(message):
    callback = _CALLBACK.get()
    if callback:
        callback(message)
