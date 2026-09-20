"""Synthetic PostgreSQL/HTTP contention lab. Never points at production.

Run with the repo venv Python; --source can select the before worktree. Requires
Docker (local Caddy) and an empty, disposable loopback PostgreSQL database whose
name starts with goggles_lab_. No production data or credentials are used.
"""

import argparse
import json
import os
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source", type=Path, required=True)
parser.add_argument("--database-url", required=True)
parser.add_argument("--split", action="store_true")
parser.add_argument("--messages", type=int, default=100)
parser.add_argument("--port", type=int, default=58100)
parser.add_argument("--shared-workers", type=int, default=1)
parser.add_argument("--shared-threads", type=int, default=6)
parser.add_argument(
    "--large", action="store_true", help="Also exercise a valid 64 MiB raw/multipart file"
)
args = parser.parse_args()
db = urlparse(args.database_url)
if db.hostname not in {"127.0.0.1", "localhost"} or not db.path.startswith("/goggles_lab_"):
    parser.error("Use a disposable goggles_lab_* database on loopback")
sys.path.insert(0, str(args.source.resolve()))
os.environ.update(
    DJANGO_SETTINGS_MODULE="config.settings",
    DJANGO_DEBUG="1",
    DJANGO_ALLOWED_HOSTS="127.0.0.1,localhost,testserver",
    DATABASE_URL=args.database_url,
    GLITCHTIP_DSN="",
)

import django  # noqa: E402

django.setup()
from django.contrib.auth.models import User  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.db import connection, connections  # noqa: E402
from django.test import Client  # noqa: E402

from forensics.models import AuditFile, PersonalAccessToken, UploadToken  # noqa: E402
from forensics.seed_data import GroupScript, Participant  # noqa: E402

call_command("migrate", verbosity=0)
if AuditFile.objects.exists() or User.objects.exists():
    parser.error("Database must be empty (never deletes existing data)")
user = User.objects.create_user("synthetic-lab-reader")
token, _ = UploadToken.issue("synthetic-lab-upload")
pat, _ = PersonalAccessToken.issue("synthetic-lab-export", user=user)
client = Client()
client.force_login(user)
cookie = f"sessionid={client.cookies['sessionid'].value}"

release = threading.Event()
two_entered = threading.Event()
all_started = threading.Event()
gate_count = 0
started_count = 0
gate_mutex = threading.Lock()


class Gate(socketserver.BaseRequestHandler):
    def handle(self):
        global gate_count, started_count
        message = self.request.recv(5)
        with gate_mutex:
            if message == b"start":
                started_count += 1
                if started_count == 6:
                    all_started.set()
                return
            gate_count += 1
            if gate_count >= 2:
                two_entered.set()
        if release.wait(25):
            self.request.sendall(b"1")


server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Gate)
threading.Thread(target=server.serve_forever, daemon=True).start()

samples = []
stop = threading.Event()


def observe():
    try:
        with connection.cursor() as cursor:
            while not stop.is_set():
                cursor.execute(
                    "SELECT coalesce(max(extract(epoch FROM clock_timestamp()-xact_start)),0), "
                    "coalesce(max(extract(epoch FROM clock_timestamp()-query_start)) "
                    "FILTER (WHERE wait_event_type='Lock'),0), "
                    "count(*) FILTER (WHERE wait_event_type='Lock') "
                    "FROM pg_stat_activity WHERE datname=current_database() "
                    "AND pid<>pg_backend_pid()"
                )
                samples.append(tuple(float(v) for v in cursor.fetchone()))
                stop.wait(0.02)
    finally:
        connections.close_all()


def request(
    path, raw=None, *, gate=False, timeout=30, port=None, content_type="application/x-ndjson"
):
    headers = {"Cookie": cookie, "Authorization": f"Bearer {token if raw else pat}"}
    if raw is not None:
        headers["Content-Type"] = content_type
    if gate:
        headers["X-Lab-Gate"] = "1"
    req = urllib.request.Request(
        f"http://127.0.0.1:{port or args.port}{path}", data=raw, headers=headers
    )
    start = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        exc.read()
        status = exc.code
    except (TimeoutError, OSError):
        status = "timeout"
    return {"status": status, "seconds": round(time.monotonic() - start, 4)}


processes = []
container = f"goggles-ingestion-lab-{args.port}"
report = {"split": args.split, "messages_per_history": args.messages, "gate_hold_seconds": 3.5}
report["shared_pool"] = [args.shared_workers, args.shared_threads]
observer = threading.Thread(target=observe, daemon=True)
read_samples = {"health": [], "browse": [], "export": []}
reader = None
try:
    with tempfile.TemporaryDirectory(prefix="goggles-http-lab-") as directory:
        temp = Path(directory)
        env = os.environ | {
            "PYTHONPATH": f"{args.source.resolve()}:{Path(__file__).parent.resolve()}",
            "LAB_GATE_PORT": str(server.server_address[1]),
        }
        for port, split_ingest in [(args.port + 1, False)] + (
            [(args.port + 2, True)] if args.split else []
        ):
            command = [
                sys.executable,
                "-m",
                "gunicorn",
                "ingestion_lab_wsgi:application",
                "--bind",
                f"0.0.0.0:{port}",
                "--workers",
                "2" if split_ingest else str(args.shared_workers),
                "--threads",
                "1" if split_ingest else str(args.shared_threads),
                "--timeout",
                "120",
            ]
            processes.append(
                subprocess.Popen(
                    command,
                    cwd=args.source,
                    env=env
                    | {"GOGGLES_UPLOADS_ENABLED": "0" if args.split and not split_ingest else "1"},
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            )
            deadline = time.monotonic() + 15
            while request("/healthz/", port=port, timeout=0.2)["status"] != 200:
                if time.monotonic() > deadline:
                    raise RuntimeError("lab Gunicorn failed to start")
                stop.wait(0.05)
        # Same route syntax as the committed proxy, with local ports and no TLS.
        route = ""
        if args.split:
            route = f"""
 @audit_upload {{
  method POST
  path /api/v1/audit-logs/ /api/v1/groups/*/audit-logs/
 }}
 handle @audit_upload {{
  reverse_proxy host.docker.internal:{args.port + 2} {{
   unhealthy_request_count 2
   transport http {{
    dial_timeout 2s
    response_header_timeout 125s
   }}
  }}
 }}
 handle_errors {{
  header Retry-After 30
  respond "Retry later" 503
 }}
"""
        config = temp / "Caddyfile"
        config.write_text(f"""{{
 admin off
}}
:80 {{
 request_body {{
  max_size 68MiB
 }}
 {route}
 handle {{
  reverse_proxy host.docker.internal:{args.port + 1}
 }}
}}
""")
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-d",
                "--name",
                container,
                "-p",
                f"127.0.0.1:{args.port}:80",
                "-v",
                f"{config}:/etc/caddy/Caddyfile:ro",
                "caddy:2",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 15
        while request("/healthz/", timeout=0.2)["status"] != 200:
            if time.monotonic() > deadline:
                raise RuntimeError("lab Caddy failed to start")
            stop.wait(0.05)
        observer.start()
        alice = Participant("lab-alice", "Synthetic", "ios")
        bob = Participant("lab-bob", "Synthetic", "android")
        histories = []
        for name in ("lab-shared-a", "lab-shared-b"):
            script = GroupScript(name, [alice, bob], start_ms=1700000000000)
            script.start(alice)
            script.start(bob)
            for _ in range(args.messages):
                script.send_message(alice, [bob], "synthetic", epoch=7)
            script.emit(alice, {"type": "convergence_run_state", "phase": "stable"})
            histories.append(script)
        report["history_uploads"] = []
        for history in histories:
            for participant in (alice, bob):
                raw = (
                    "\n".join(json.dumps(e) for e in history._events[participant.name]) + "\n"
                ).encode()
                result = request("/api/v1/audit-logs/", raw, timeout=120)
                result["bytes"] = len(raw)
                result["events"] = len(history._events[participant.name])
                report["history_uploads"].append(result)
                if result["status"] != 201:
                    raise RuntimeError("history upload failed")

        def observe_reads():
            paths = {
                "health": "/healthz/",
                "browse": "/",
                "export": f"/api/v1/groups/{histories[0].group_ref}/export/",
            }
            while not stop.is_set():
                for name, path in paths.items():
                    if stop.is_set():
                        return
                    read_samples[name].append(request(path, timeout=1))
                stop.wait(0.1)

        reader = threading.Thread(target=observe_reads, daemon=True)
        reader.start()

        # Six different recorder segments, two shared groups, each backfilling
        # older convergence evidence and forcing full retained-history replay.
        segments = []
        for index in range(6):
            value = dict(histories[index % 2]._events[alice.name][0])
            value.update(
                engine_id=f"{index + 100:032x}",
                seq=1,
                kind={"type": "convergence_run_state", "phase": "evaluating"},
            )
            segments.append((json.dumps(value) + "\n").encode())
        with ThreadPoolExecutor(max_workers=6) as pool:
            started = time.monotonic()
            # Admit one owner per group first, independent of HTTP accept order.
            futures = [
                pool.submit(request, "/api/v1/audit-logs/", raw, gate=True, timeout=120)
                for raw in segments[:2]
            ]
            try:
                if not two_entered.wait(15):
                    raise RuntimeError("both projection owners must reach the gate")
                futures.extend(
                    pool.submit(request, "/api/v1/audit-logs/", raw, gate=True, timeout=120)
                    for raw in segments[2:]
                )
                if not args.split and not all_started.wait(15):
                    raise RuntimeError("all six shared request slots must be occupied")
                hold_until = time.monotonic() + report["gate_hold_seconds"]
                report["reads_while_held"] = {
                    name: request(path, timeout=1)
                    for name, path in [
                        ("health", "/healthz/"),
                        ("browse", "/"),
                        ("export", f"/api/v1/groups/{histories[0].group_ref}/export/"),
                    ]
                }
                # Identical injected stall duration in before/after measurements.
                stop.wait(max(0, hold_until - time.monotonic()))
            finally:
                release.set()
            report["concurrent_uploads"] = [future.result(timeout=120) for future in futures]
            report["concurrent_wall_seconds"] = round(time.monotonic() - started, 4)
        report["retry_uploads"] = [
            request("/api/v1/audit-logs/", raw, timeout=120) for raw in segments
        ]
        report["duplicate"] = request("/api/v1/audit-logs/", segments[0])
        if args.large:
            # Legal schema data with large raw fields; this probes byte/body
            # boundaries, not the worst-case count of tiny events or heap use.
            values = []
            for seq in range(64):
                values.append(
                    {
                        "schema_version": "marmot-forensics-audit/v4",
                        "seq": seq,
                        "wall_time_ms": 1700000000000 + seq,
                        "engine_id": "ff" * 16,
                        "account_ref": "ee" * 16,
                        "kind": {
                            "type": "recorder_started",
                            "recorder": "x" * (1024 * 1024 - 1000),
                        },
                    }
                )
            raw = ("\n".join(json.dumps(value) for value in values) + "\n").encode()
            values[-1]["kind"]["recorder"] += "x" * (64 * 1024 * 1024 - len(raw))
            raw = ("\n".join(json.dumps(value) for value in values) + "\n").encode()
            del values
            report["large_bytes"] = len(raw)
            report["large_raw"] = request("/api/v1/audit-logs/", raw, timeout=120)
            multipart = (
                b'--lab\r\nContent-Disposition: form-data; name="audit_log"; '
                b'filename="synthetic.jsonl"'
                b"\r\nContent-Type: application/x-ndjson\r\n\r\n" + raw + b"\r\n--lab--\r\n"
            )
            report["large_multipart_duplicate"] = request(
                "/api/v1/audit-logs/",
                multipart,
                timeout=120,
                content_type="multipart/form-data; boundary=lab",
            )
        stop.set()
        reader.join(timeout=4)
        report["read_samples_during_ingestion"] = {
            name: {
                "count": len(values),
                "statuses": dict(Counter(str(value["status"]) for value in values)),
                "max_seconds": max(value["seconds"] for value in values),
            }
            for name, values in read_samples.items()
            if values
        }
        report["max_transaction_seconds"] = round(max(row[0] for row in samples), 4)
        report["max_lock_wait_seconds"] = round(max(row[1] for row in samples), 4)
        report["max_lock_waiters"] = int(max(row[2] for row in samples))
        report["durable_queue_jobs"] = 0
        print(json.dumps(report, indent=2), flush=True)
finally:
    release.set()
    stop.set()
    if observer.is_alive():
        observer.join(timeout=5)
    if reader is not None and reader.is_alive():
        reader.join(timeout=4)
    subprocess.run(
        ["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    for process in processes:
        process.terminate()
    for process in processes:
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    server.shutdown()
    server.server_close()
