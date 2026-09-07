"""Request-body integrity helpers for the upload API.

A transfer that dies mid-body -- the app is killed, the mobile link drops, the
client's socket write times out while the server is busy, the edge proxy aborts
-- does **not** surface as an error inside Django. gunicorn's length-bounded
reader returns whatever arrived before EOF, and ``HttpRequest.body`` never
compares that to ``Content-Length``. The view therefore needs its own account of
how many bytes actually arrived, which is what this module provides:

* :func:`count_request_body` wraps the WSGI application so ``wsgi.input`` is
  proxied through a :class:`CountingInput`; the counter is exposed in the WSGI
  environ (and hence ``request.META``) under :data:`REQUEST_BODY_COUNTER_KEY`.
  This is the only way to measure a *multipart* body, which Django's parser
  consumes chunk by chunk.
* :func:`declared_content_length` parses the header the client committed to.

Nothing here imports Django models: ``config.wsgi`` loads it before the
application is fully set up.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

REQUEST_BODY_COUNTER_KEY = "goggles.request_body"


class CountingInput:
    """Proxy for ``wsgi.input`` that counts the bytes the application consumed.

    Only the file-like surface Django uses (``read`` / ``readline``) plus the
    remaining PEP 3333 input methods are exposed; every byte handed to the
    caller is added to :attr:`bytes_read`.
    """

    def __init__(self, stream):
        self._stream = stream
        self.bytes_read = 0

    def read(self, size: int | None = -1) -> bytes:
        data = self._stream.read(size)
        self.bytes_read += len(data)
        return data

    def readline(self, size: int | None = -1) -> bytes:
        data = self._stream.readline(size)
        self.bytes_read += len(data)
        return data

    def readlines(self, hint: int = -1) -> list[bytes]:
        lines = self._stream.readlines(hint)
        self.bytes_read += sum(len(line) for line in lines)
        return lines

    def __iter__(self):
        for line in self._stream:
            self.bytes_read += len(line)
            yield line

    def close(self) -> None:
        close = getattr(self._stream, "close", None)
        if close is not None:
            close()


def count_request_body(
    application: Callable[[dict[str, Any], Callable], Iterable[bytes]],
) -> Callable[[dict[str, Any], Callable], Iterable[bytes]]:
    """WSGI middleware: expose a byte counter for the request body in the environ."""

    def wrapped(environ: dict[str, Any], start_response: Callable) -> Iterable[bytes]:
        stream = environ.get("wsgi.input")
        if stream is not None:
            counter = CountingInput(stream)
            environ["wsgi.input"] = counter
            environ[REQUEST_BODY_COUNTER_KEY] = counter
        return application(environ, start_response)

    return wrapped


def declared_content_length(request) -> int | None:
    """The ``Content-Length`` the client committed to, or ``None`` if absent/invalid.

    ``None`` also covers chunked transfer encoding: behind gunicorn Django would
    read such a body as empty anyway, so the upload API refuses it up front.
    """
    raw = request.META.get("CONTENT_LENGTH")
    if raw is None or raw == "":
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    if value < 0:
        return None
    return value


def counted_body_bytes(request) -> int | None:
    """Bytes the application consumed from the request body, if a counter was installed."""
    counter = request.META.get(REQUEST_BODY_COUNTER_KEY)
    if counter is None:
        return None
    return counter.bytes_read
