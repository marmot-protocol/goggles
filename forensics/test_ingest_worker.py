"""Exercise the real sync-worker watchdog with synthetic, deliberately paced I/O."""

import contextlib
import http.client
import io
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.test import SimpleTestCase

from deploy.ingest_worker import ProgressInput

from .checks import ingestion_database_version


class IngestionDatabaseCheckTests(SimpleTestCase):
    def test_deploy_check_rejects_postgres_before_17(self):
        with mock.patch(
            "forensics.checks.connections",
            {"default": SimpleNamespace(vendor="postgresql", pg_version=160010)},
        ):
            errors = ingestion_database_version(None, databases=["default"])
        self.assertEqual([error.id for error in errors], ["forensics.E001"])

    def test_supported_databases_and_unselected_connections(self):
        for vendor, version in [("postgresql", 170000), ("sqlite", None)]:
            with mock.patch(
                "forensics.checks.connections",
                {"default": SimpleNamespace(vendor=vendor, pg_version=version)},
            ):
                self.assertEqual(ingestion_database_version(None, databases=["default"]), [])
        with mock.patch("forensics.checks.connections") as connections:
            self.assertEqual(ingestion_database_version(None), [])
            connections.__getitem__.assert_not_called()


class ProgressInputTests(SimpleTestCase):
    def test_preserves_bytes_and_wsgi_read_methods(self):
        body = b"a" * (ProgressInput.CHUNK_SIZE + 3) + b"\nlast\n"
        client = mock.Mock()
        client.gettimeout.return_value = None
        progress = mock.Mock()

        def wrap():
            return ProgressInput(
                io.BytesIO(body), client, progress, transfer_timeout=30, idle_timeout=2
            )

        stream = wrap()
        self.assertEqual(stream.read(0), b"")
        progress.assert_not_called()
        self.assertEqual(stream.read(None), body)
        self.assertEqual(progress.call_count, 2)
        self.assertEqual(stream.read(), b"")
        self.assertEqual(progress.call_count, 2)
        self.assertEqual(b"".join(wrap()), body)
        self.assertEqual(wrap().readline(None), body[:-5])
        self.assertEqual(wrap().readline(3), b"aaa")
        self.assertEqual(wrap().readlines(None), [body[:-5], b"last\n"])
        client.settimeout.assert_called_with(None)


LAB_APP = """
import os
import time

def application(environ, start_response):
    try:
        body = environ["wsgi.input"].read(int(environ.get("CONTENT_LENGTH") or 0))
    except TimeoutError:
        start_response("408 Request Timeout", [("Content-Length", "0")])
        return [b""]
    if environ["PATH_INFO"] == "/stall":
        # Computation after the transfer must not receive timer heartbeats.
        until = time.monotonic() + 30
        while time.monotonic() < until:
            pass
    result = f"{os.getpid()}:{len(body)}".encode()
    start_response("200 OK", [("Content-Length", str(len(result)))])
    return [result]
"""


class IngestWorkerWatchdogTests(SimpleTestCase):
    @contextlib.contextmanager
    def worker(self, transfer_timeout=10):
        with tempfile.TemporaryDirectory(prefix="goggles-worker-test-") as directory:
            Path(directory, "worker_lab.py").write_text(LAB_APP)
            with socket.socket() as listener, tempfile.TemporaryFile() as log:
                listener.bind(("127.0.0.1", 0))
                listener.listen()
                port = listener.getsockname()[1]
                process = subprocess.Popen(
                    [
                        sys.executable,
                        "-m",
                        "gunicorn",
                        "worker_lab:application",
                        "--bind",
                        f"fd://{listener.fileno()}",
                        "--worker-class",
                        "deploy.ingest_worker.IngestWorker",
                        "--workers",
                        "1",
                        "--timeout",
                        "2",
                        "--graceful-timeout",
                        "1",
                    ],
                    env=os.environ
                    | {
                        "PYTHONPATH": f"{Path(__file__).resolve().parent.parent}:{directory}",
                        "GOGGLES_INGEST_TRANSACTION_TIMEOUT_MS": "1000",
                        "GOGGLES_INGEST_TRANSFER_TIMEOUT_SECONDS": str(transfer_timeout),
                    },
                    pass_fds=(listener.fileno(),),
                    stdout=log,
                    stderr=log,
                )
                listener.close()
                try:
                    deadline = time.monotonic() + 10
                    while True:
                        if process.poll() is not None or time.monotonic() >= deadline:
                            log.seek(0)
                            self.fail(f"Synthetic worker did not start: {log.read().decode()}")
                        try:
                            pid = self.probe(port)
                            break
                        except (OSError, http.client.HTTPException):
                            time.sleep(0.05)
                    yield port, pid
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)

    def probe(self, port):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.request("GET", "/pid")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            return int(response.read().split(b":")[0])
        finally:
            connection.close()

    def upload(self, port, path, chunks):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
        self.addCleanup(connection.close)
        connection.putrequest("POST", path)
        connection.putheader("Content-Length", chunks * ProgressInput.CHUNK_SIZE)
        connection.endheaders()
        return connection

    def test_progressing_transfer_outlives_processing_watchdog(self):
        with self.worker() as (port, pid):
            connection = self.upload(port, "/read", 12)
            started = time.monotonic()
            for _ in range(12):
                connection.send(b"x" * ProgressInput.CHUNK_SIZE)
                time.sleep(0.4)
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), f"{pid}:{12 * ProgressInput.CHUNK_SIZE}".encode())
            self.assertGreater(time.monotonic() - started, 4)
            self.assertEqual(self.probe(port), pid)

    def test_progress_cannot_extend_total_transfer_budget(self):
        with self.worker(transfer_timeout=1.5) as (port, pid):
            connection = self.upload(port, "/read", 10)
            started = time.monotonic()
            for _ in range(7):
                try:
                    connection.send(b"x" * ProgressInput.CHUNK_SIZE)
                except OSError:
                    break
                time.sleep(0.3)
            response = connection.getresponse()
            self.assertEqual(response.status, 408)
            response.read()
            self.assertLess(time.monotonic() - started, 4)
            self.assertEqual(self.probe(port), pid)

    def test_processing_stall_is_killed_after_body_finishes(self):
        with self.worker() as (port, pid):
            connection = self.upload(port, "/stall", 1)
            connection.send(b"x" * ProgressInput.CHUNK_SIZE)
            started = time.monotonic()
            response = connection.getresponse()
            self.assertEqual(response.status, 500)
            response.read()
            self.assertLess(time.monotonic() - started, 6)
            self.assertNotEqual(self.probe(port), pid)

    def test_idle_transfer_is_bounded(self):
        with self.worker() as (port, _pid):
            connection = self.upload(port, "/read", 1)
            started = time.monotonic()
            response = connection.getresponse()
            # Socket deadline normally wins; watchdog may win at its boundary.
            self.assertIn(response.status, (408, 500))
            response.read()
            self.assertLess(time.monotonic() - started, 6)
            self.probe(port)
