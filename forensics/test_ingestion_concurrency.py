"""Real PostgreSQL connections and explicit gates, never timing-based races."""

import json
from concurrent.futures import ThreadPoolExecutor
from io import StringIO
from threading import Event
from time import monotonic
from unittest import skipUnless
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection, connections, transaction
from django.test import Client, TransactionTestCase, override_settings

from . import ingest, projections
from .models import AuditEvent, AuditFile, AuditGroup, PersonalAccessToken, UploadToken
from .retention import retention_lock


def event(seq=0, *, engine="aa" * 16, group="bb" * 16):
    value = {
        "schema_version": "marmot-forensics-audit/v4",
        "seq": seq,
        "wall_time_ms": 1700000000000 + seq,
        "engine_id": engine,
        "account_ref": "cc" * 16,
        "recorder_session_id": "synthetic-session",
        "kind": {"type": "source_context", "source": {"app_version": "synthetic-1"}},
    }
    if group is not None:
        value["group_ref"] = group
    return value


def body(*events):
    return ("\n".join(json.dumps(value) for value in events) + "\n").encode()


def upload(raw):
    # Every worker owns its connection, including on BaseException/cancellation.
    try:
        return ingest.ingest_audit_log_bytes(dump_bytes=raw)
    finally:
        connections.close_all()


@skipUnless(connection.vendor == "postgresql", "requires PostgreSQL row/transaction locks")
class IngestionConcurrencyTests(TransactionTestCase):
    def setUp(self):
        self.group = AuditGroup.objects.create(slug="bb" * 16, group_ref="bb" * 16)

    def run_held_upload(self, first, contender, *, fails=False):
        entered, release = Event(), Event()
        original = ingest.rebuild_file_projections

        def held(audit_file):
            if audit_file.engine_ids == ["aa" * 16]:
                entered.set()
                if not release.wait(10):
                    raise AssertionError("test did not release projection gate")
            return original(audit_file)

        with patch.object(ingest, "rebuild_file_projections", side_effect=held):
            with ThreadPoolExecutor(max_workers=2) as pool:
                active = pool.submit(upload, first)
                try:
                    self.assertTrue(entered.wait(5))
                    start = monotonic()
                    other = pool.submit(upload, contender)
                    if fails:
                        with self.assertRaises(ingest.UploadRejected) as error:
                            other.result(timeout=3)
                        self.assertEqual(error.exception.code, "ingest_busy")
                    else:
                        self.assertTrue(other.result(timeout=3).created)
                    self.assertLess(monotonic() - start, 3)
                    # A separate connection can still read while the writer is held.
                    self.assertEqual(Client().get("/healthz/").status_code, 200)
                    self.assert_no_waiters()
                finally:
                    release.set()
                self.assertTrue(active.result(timeout=5).created)

    def assert_no_waiters(self):
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
                "AND wait_event_type='Lock' AND pid<>pg_backend_pid()"
            )
            self.assertEqual(cursor.fetchone()[0], 0)

    def test_same_group_fails_before_evidence_write_then_retry_succeeds(self):
        contender = body(event(1, engine="dd" * 16))
        self.run_held_upload(body(event()), contender, fails=True)
        self.assertEqual(AuditFile.objects.count(), 1)
        self.assertTrue(ingest.ingest_audit_log_bytes(dump_bytes=contender).created)
        self.assertEqual(AuditEvent.objects.count(), 2)

    def test_disjoint_groups_make_progress_concurrently(self):
        self.run_held_upload(body(event()), body(event(1, engine="dd" * 16, group="ee" * 16)))

    def test_identical_inflight_file_retries_without_waiting_on_unique_hash(self):
        raw = body(event())
        self.run_held_upload(raw, raw, fails=True)
        result = ingest.ingest_audit_log_bytes(dump_bytes=raw)
        self.assertFalse(result.created)
        self.assertEqual(AuditFile.objects.count(), 1)

    def test_overlapping_ungrouped_segments_preserve_line_dedup_and_raw_provenance(self):
        first = body(event(group=None))
        second = body(event(group=None), event(1, group=None))
        self.run_held_upload(first, second, fails=True)
        result = ingest.ingest_audit_log_bytes(dump_bytes=second)
        self.assertEqual(result.audit_file.raw_text, second.decode())
        self.assertEqual(result.audit_file.duplicate_event_count, 1)
        self.assertEqual(AuditEvent.objects.count(), 2)

    def test_reverse_multi_group_order_fails_promptly_and_retry_keeps_memberships(self):
        first = body(event(), event(1, group="ee" * 16))
        second = body(event(2, engine="dd" * 16, group="ee" * 16), event(3, engine="dd" * 16))
        self.run_held_upload(first, second, fails=True)
        result = ingest.ingest_audit_log_bytes(dump_bytes=second)
        self.assertEqual(result.audit_file.groups.count(), 2)

    def test_error_and_cancellation_release_all_transaction_locks(self):
        raw = body(event())
        for error in (RuntimeError("synthetic failure"), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                with patch.object(ingest, "rebuild_file_projections", side_effect=error):
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        expected = (
                            ingest.UploadRejected if isinstance(error, Exception) else type(error)
                        )
                        with self.assertRaises(expected):
                            pool.submit(upload, raw).result(timeout=5)
                self.assertEqual(AuditFile.objects.count(), 0)
                self.assertEqual(AuditEvent.objects.count(), 0)
                self.assertFalse(connection.in_atomic_block)
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() "
                        "AND xact_start IS NOT NULL AND pid<>pg_backend_pid()"
                    )
                    self.assertEqual(cursor.fetchone()[0], 0)
        self.assertTrue(ingest.ingest_audit_log_bytes(dump_bytes=raw).created)

    @override_settings(GOGGLES_INGEST_STATEMENT_TIMEOUT_MS=50)
    def test_statement_deadline_rolls_back_and_does_not_leak_to_read_connection(self):
        def slow_query(_file):
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_sleep(2)")

        with patch.object(ingest, "rebuild_file_projections", side_effect=slow_query):
            with self.assertRaises(ingest.UploadRejected):
                ingest.ingest_audit_log_bytes(dump_bytes=body(event()))
        self.assertEqual(AuditFile.objects.count(), 0)
        with connection.cursor() as cursor:
            cursor.execute("SHOW statement_timeout")
            self.assertEqual(cursor.fetchone()[0], "0")
        self.assertTrue(ingest.ingest_audit_log_bytes(dump_bytes=body(event())).created)

    @override_settings(GOGGLES_INGEST_TRANSACTION_TIMEOUT_MS=100)
    def test_transaction_deadline_stops_many_short_queries_and_rolls_back(self):
        def many_queries(_file):
            with connection.cursor() as cursor:
                for _ in range(10000):
                    cursor.execute("SELECT 1")

        start = monotonic()
        with patch.object(ingest, "rebuild_file_projections", side_effect=many_queries):
            with ThreadPoolExecutor(max_workers=1) as pool:
                with self.assertRaises(ingest.UploadRejected):
                    pool.submit(upload, body(event())).result(timeout=5)
        self.assertLess(monotonic() - start, 5)
        self.assertEqual(AuditFile.objects.count(), 0)
        self.assertEqual(AuditEvent.objects.count(), 0)
        self.assert_no_waiters()

    @override_settings(GOGGLES_INGEST_IDLE_TIMEOUT_MS=100)
    def test_idle_deadline_releases_locks_while_python_is_stalled(self):
        entered, release = Event(), Event()

        def stalled(_file):
            entered.set()
            self.assertTrue(release.wait(5))
            AuditFile.objects.count()  # Observe the server-side disconnect.

        with patch.object(ingest, "rebuild_file_projections", side_effect=stalled):
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(upload, body(event()))
                try:
                    self.assertTrue(entered.wait(5))
                    # This waiter must be released by the DB idle deadline,
                    # while the uploader is still stalled behind the gate.
                    with transaction.atomic(), connection.cursor() as cursor:
                        cursor.execute("SET LOCAL lock_timeout='2s'")
                        AuditGroup.objects.select_for_update().get(pk=self.group.pk)
                    self.assertEqual(AuditFile.objects.count(), 0)
                finally:
                    release.set()
                with self.assertRaises(ingest.UploadRejected):
                    future.result(timeout=5)

    def test_both_api_routes_return_retry_after_and_auth_stays_required(self):
        token, _ = UploadToken.issue("synthetic uploader")
        user = User.objects.create_user("synthetic reader")
        pat, _ = PersonalAccessToken.issue("synthetic reader", user=user)
        for path in ("/api/v1/audit-logs/", f"/api/v1/groups/{self.group.slug}/audit-logs/"):
            for credential in ("", pat):
                self.assertEqual(
                    self.client.post(
                        path,
                        body(event()),
                        content_type="application/x-ndjson",
                        HTTP_AUTHORIZATION=f"Bearer {credential}",
                    ).status_code,
                    401,
                )
            with patch.object(ingest, "begin_ingestion", side_effect=ingest.IngestionBusy):
                response = self.client.post(
                    path,
                    body(event()),
                    content_type="application/x-ndjson",
                    HTTP_AUTHORIZATION=f"Bearer {token}",
                )
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response["Retry-After"], "30")
            self.assertEqual(response.json()["reason"], "ingest_busy")
        self.assertEqual(AuditFile.objects.count(), 0)

    def test_retention_overlap_is_excluded_and_rebuild_blocks_upload_without_waiters(self):
        entered, release = Event(), Event()

        def maintenance():
            try:
                with retention_lock(), transaction.atomic():
                    group = AuditGroup.objects.select_for_update().get(pk=self.group.pk)
                    entered.set()
                    self.assertTrue(release.wait(5))
                    projections.rebuild_group_projections(group)
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(maintenance)
            try:
                self.assertTrue(entered.wait(5))
                with self.assertRaises(CommandError):
                    call_command("prune_audit_data", stdout=StringIO())
                with self.assertRaises(ingest.UploadRejected) as error:
                    ingest.ingest_audit_log_bytes(dump_bytes=body(event()))
                self.assertEqual(error.exception.code, "ingest_busy")
                self.assert_no_waiters()
            finally:
                release.set()
            future.result(timeout=5)
        call_command("prune_audit_data", stdout=StringIO())
        self.assertTrue(ingest.ingest_audit_log_bytes(dump_bytes=body(event())).created)
