"""Sync uploads with separate transfer and processing deadlines.

Heartbeat only on body-read progress. Validation/projection still run under the
normal sync worker deadline; never heartbeat from an independent timer thread.
Unvalidated bytes remain in the existing bounded in-memory request path.
"""

import math
import os
from time import monotonic

from gunicorn.workers.sync import SyncWorker


class ProgressInput:
    CHUNK_SIZE = 64 * 1024

    def __init__(self, stream, client, notify, *, transfer_timeout, idle_timeout):
        self.stream = stream
        self.client = client
        self.notify = notify
        self.transfer_timeout = transfer_timeout
        self.idle_timeout = idle_timeout
        self.deadline = None

    def _read(self, size, *, line=False):
        if size is None:
            size = -1
        chunks = []
        while size != 0:
            if self.deadline is None:
                self.deadline = monotonic() + self.transfer_timeout
            remaining = self.deadline - monotonic()
            if remaining <= 0:
                raise TimeoutError("Upload transfer deadline exceeded")
            previous_timeout = self.client.gettimeout()
            self.client.settimeout(min(remaining, self.idle_timeout))
            try:
                read = self.stream.readline if line else self.stream.read
                chunk = read(self.CHUNK_SIZE if size < 0 else min(size, self.CHUNK_SIZE))
            finally:
                self.client.settimeout(previous_timeout)
            if monotonic() > self.deadline:
                raise TimeoutError("Upload transfer deadline exceeded")
            if not chunk:
                break
            self.notify()
            chunks.append(chunk)
            if size > 0:
                size -= len(chunk)
            if line and chunk.endswith(b"\n"):
                break
        return b"".join(chunks)

    def read(self, size=-1):
        return self._read(size)

    def readline(self, size=-1):
        return self._read(size, line=True)

    def readlines(self, hint=-1):
        lines, total = [], 0
        for line in self:
            lines.append(line)
            total += len(line)
            if hint is not None and hint > 0 and total >= hint:
                break
        return lines

    def __iter__(self):
        return self

    def __next__(self):
        line = self.readline()
        if not line:
            raise StopIteration
        return line

    def __getattr__(self, name):
        return getattr(self.stream, name)


class IngestWorker(SyncWorker):
    def init_process(self):
        self.transfer_timeout = float(
            os.environ.get("GOGGLES_INGEST_TRANSFER_TIMEOUT_SECONDS", 900)
        )
        transaction_ms = int(os.environ.get("GOGGLES_INGEST_TRANSACTION_TIMEOUT_MS", 90000))
        if not math.isfinite(self.transfer_timeout) or self.transfer_timeout <= 0:
            raise ValueError("GOGGLES_INGEST_TRANSFER_TIMEOUT_SECONDS must be finite and positive")
        if self.cfg.timeout <= 0 or transaction_ms >= self.cfg.timeout * 1000:
            raise ValueError("Ingest worker timeout must exceed the database transaction deadline")
        super().init_process()

    def handle_request(self, listener, req, client, addr):
        original = self.wsgi

        def receive(environ, start_response):
            environ["wsgi.input"] = ProgressInput(
                environ["wsgi.input"],
                client,
                self.notify,
                transfer_timeout=self.transfer_timeout,
                idle_timeout=self.cfg.timeout,
            )
            return original(environ, start_response)

        self.wsgi = receive
        try:
            return super().handle_request(listener, req, client, addr)
        finally:
            self.wsgi = original
