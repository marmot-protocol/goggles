import json
from importlib import import_module

from django.apps import apps as global_apps
from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from .analysis import timeline_engines, valid_events_for_group
from .audit_schema import SCHEMA_VERSION
from .ingest import ingest_audit_log_bytes
from .models import AuditFile, AuditGroup
from .views import engine_source_values, group_engine_rows

User = get_user_model()


class RotatedSourceMetadataTests(TestCase):
    def test_metadata_query_count_and_sqlite_index_plans(self):
        for index in range(5):
            self.upload(session=f"session-{index}", source={"app_version": str(index)})
            self.upload(session=f"session-{index}", group="dd" * 16, seq=100)
        group = AuditGroup.objects.get()
        if connection.vendor == "sqlite":
            with connection.cursor() as cursor:
                cursor.execute("ANALYZE")
        with self.assertNumQueries(3), CaptureQueriesContext(connection) as queries:
            values = engine_source_values(group)
        self.assertEqual(values["bb" * 16]["app_versions"], [str(i) for i in range(5)])
        if connection.vendor == "sqlite":
            with connection.cursor() as cursor:
                cursor.execute("EXPLAIN QUERY PLAN " + queries[0]["sql"])
                plan = str(cursor.fetchall())
                self.assertIn("COVERING INDEX goggles_group_sessions_idx", plan)
                cursor.execute("EXPLAIN QUERY PLAN " + queries[2]["sql"])
                self.assertIn("goggles_session_source_idx", str(cursor.fetchall()))

    def test_exact_timeline_metadata_precedes_incomplete_file_fallback(self):
        self.upload(session=None, group="dd" * 16, source={"hardware_model": "Fallback"})
        self.upload(source={"hardware_model": "Exact"})
        self.upload(group="dd" * 16, seq=100)
        engines, _ = timeline_engines(valid_events_for_group(AuditGroup.objects.get()))
        self.assertEqual(engines[0]["label"], "Exact / bbbbbbbbbbbb")

    def test_source_validity_matches_group_evidence_validity(self):
        startup = self.upload(source={"app_version": "1.0"})
        self.upload(group="dd" * 16, seq=100)
        group = AuditGroup.objects.get()
        startup.validation_status = AuditFile.STATUS_INVALID
        startup.validation_error = "another line is invalid"
        startup.save(update_fields=["validation_status", "validation_error"])
        self.assertEqual(engine_source_values(group)["bb" * 16]["app_versions"], ["1.0"])
        startup.validation_error = "audit log contains multiple engine_ids"
        startup.save(update_fields=["validation_error"])
        self.assertEqual(engine_source_values(group)["bb" * 16]["app_versions"], [])

    def test_group_engine_rows_preserve_each_session_account(self):
        for account in ("aa" * 16, "ee" * 16):
            self.upload(account=account, group="dd" * 16, seq=100)
        row = group_engine_rows(AuditGroup.objects.get())[0]
        self.assertEqual(row["account_refs"], ["aa" * 16, "ee" * 16])

    def upload(
        self,
        *,
        session="session-1",
        account="aa" * 16,
        engine="bb" * 16,
        source=None,
        group=None,
        seq=0,
    ):
        event = {
            "schema_version": SCHEMA_VERSION,
            "seq": seq,
            "wall_time_ms": 1700000000000 + seq,
            "engine_id": engine,
            "account_ref": account,
            "kind": {"type": "recorder_started", "recorder": "synthetic"},
        }
        if session:
            event["recorder_session_id"] = session
        if group:
            event["group_ref"] = group
        if source is not None:
            event["kind"] = {"type": "source_context", "source": source}
        return ingest_audit_log_bytes(dump_bytes=(json.dumps(event) + "\n").encode()).audit_file

    def test_startup_metadata_resolves_later_group_and_timeline_without_rewriting_files(self):
        startup = self.upload(
            source={
                "platform": "ios",
                "hardware_model": "iPhone17,2",
                "app_version": "1.0",
                "device_id": "cc" * 16,
            }
        )
        segment = self.upload(group="dd" * 16, seq=100)
        group = AuditGroup.objects.get()
        self.assertFalse(startup.groups.exists())
        values = engine_source_values(group)["bb" * 16]
        self.assertEqual(values["app_versions"], ["1.0"])
        self.assertEqual(values["device_ids"], ["cc" * 16])
        self.assertEqual(values["hardware_models"], ["iPhone17,2"])
        self.assertEqual(group_engine_rows(group)[0]["label"], "ios / iPhone17,2 / bbbbbbbbbbbb")
        with self.assertNumQueries(2):
            engines, _ = timeline_engines(valid_events_for_group(group))
        self.assertEqual(engines[0]["label"], "ios / iPhone17,2 / bbbbbbbbbbbb")
        segment.refresh_from_db()
        self.assertEqual(segment.source_app_version, "")
        self.assertNotIn("app_version", segment.raw_text)
        # Metadata arriving after the group segment works without a rebuild.
        self.upload(session="session-2", group="dd" * 16, seq=101)
        self.upload(session="session-2", source={"app_version": "2.0"})
        self.assertEqual(engine_source_values(group)["bb" * 16]["app_versions"], ["1.0", "2.0"])
        # Retention removes evidence: do not keep a stale derived copy.
        startup.delete()
        self.assertEqual(engine_source_values(group)["bb" * 16]["app_versions"], ["2.0"])

    def test_metadata_does_not_cross_session_account_or_engine_boundaries(self):
        self.upload(group="dd" * 16, seq=100)
        self.upload(session="other", source={"app_version": "wrong-session"})
        self.upload(account="ee" * 16, source={"app_version": "wrong-account"})
        self.upload(engine="ff" * 16, source={"app_version": "wrong-engine"})
        self.upload(session=None, source={"app_version": "unknown-session"})
        self.assertEqual(
            engine_source_values(AuditGroup.objects.get())["bb" * 16]["app_versions"], []
        )

    def test_missing_session_does_not_borrow_metadata(self):
        self.upload(session=None, group="dd" * 16, seq=100)
        self.upload(source={"app_version": "unrelated"})
        self.assertEqual(
            engine_source_values(AuditGroup.objects.get())["bb" * 16]["app_versions"], []
        )

    def test_context_source_and_engine_limit(self):
        self.upload(group="dd" * 16, seq=100)
        self.upload(engine="ff" * 16, group="dd" * 16, seq=100)
        event = {
            "schema_version": SCHEMA_VERSION,
            "seq": 0,
            "wall_time_ms": 1700000000000,
            "engine_id": "bb" * 16,
            "account_ref": "aa" * 16,
            "recorder_session_id": "session-1",
            "context": {"source": {"app_version": "1.0"}},
            "kind": {"type": "recorder_started", "recorder": "synthetic"},
        }
        ingest_audit_log_bytes(dump_bytes=(json.dumps(event) + "\n").encode())
        values = engine_source_values(AuditGroup.objects.get(), engine_ids=["bb" * 16])
        self.assertEqual(list(values), ["bb" * 16])
        self.assertEqual(values["bb" * 16]["app_versions"], ["1.0"])

    def test_file_summary_does_not_override_exact_session_metadata(self):
        old = self.upload(source={"app_version": "old", "hardware_model": "Old Model"})
        new = self.upload(
            session="session-2", source={"app_version": "new", "hardware_model": "New Model"}
        )
        segment = self.upload(session="session-2", group="dd" * 16, seq=100)
        body = old.raw_text + new.raw_text + segment.raw_text
        old.delete()
        new.delete()
        segment.delete()
        combined = ingest_audit_log_bytes(dump_bytes=body.encode()).audit_file
        self.assertEqual(combined.source_app_version, "old")
        group = AuditGroup.objects.get()
        self.assertEqual(engine_source_values(group)["bb" * 16]["app_versions"], ["new"])
        engines, _ = timeline_engines(valid_events_for_group(group))
        self.assertEqual(engines[0]["label"], "New Model / bbbbbbbbbbbb")


class LocalMemberRefExportTests(TestCase):
    """A file's own source_context local_member_ref rides its t:"source" export row."""

    def setUp(self):
        user = User.objects.create_user(username="reader", password="pw")
        self.client.force_login(user)

    def test_source_row_exports_the_files_local_member_ref_in_lowercase(self):
        self.upload({"platform": "ios", "local_member_ref": "Dd" * 16})

        row = self.export_source_rows()[0]

        self.assertEqual(row["source_local_member_ref"], "dd" * 16)
        self.assertEqual(row["source_platform"], "ios")

    def test_missing_local_member_ref_exports_null_and_leaves_the_row_unchanged(self):
        self.upload({"platform": "ios", "app_version": "1.0"})
        self.upload()

        with_source, without_source = sorted(self.export_source_rows(), key=lambda row: row["id"])

        self.assertIsNone(with_source["source_local_member_ref"])
        self.assertEqual(with_source["source_platform"], "ios")
        self.assertEqual(with_source["source_app_version"], "1.0")
        self.assertIsNone(without_source["source_local_member_ref"])
        self.assertEqual(without_source["source_platform"], "")

    def test_manifest_declares_member_refs_as_sensitive_export_content(self):
        self.upload({"local_member_ref": "Dd" * 16})

        manifest = self.export_records()[0]

        self.assertIn("member_refs", manifest["sensitivity"]["contains"])

    def test_backfill_derives_historical_files_value_from_their_own_events(self):
        self.upload({"local_member_ref": "Dd" * 16})
        self.upload({"platform": "ios"})
        # Simulate a file ingested before the column existed.
        AuditFile.objects.update(source_local_member_ref="")
        self.assertEqual(
            [row["source_local_member_ref"] for row in self.export_source_rows()], [None, None]
        )

        self.backfill()

        rows = sorted(self.export_source_rows(), key=lambda row: row["id"])
        self.assertEqual([row["source_local_member_ref"] for row in rows], ["dd" * 16, None])

    def test_backfill_and_ingest_both_leave_conflicting_refs_unknown(self):
        repeated = self.upload(
            {"platform": "ios"},
            {"local_member_ref": "Aa" * 16},
            {"local_member_ref": "aa" * 16},
        )
        conflicting = self.upload(
            {"local_member_ref": "11" * 16},
            {"local_member_ref": "22" * 16},
        )
        self.assertEqual(repeated.source_local_member_ref, "aa" * 16)
        self.assertEqual(conflicting.source_local_member_ref, "")
        AuditFile.objects.update(source_local_member_ref="")

        self.backfill()

        self.assertEqual(
            {row["id"]: row["source_local_member_ref"] for row in self.export_source_rows()},
            {repeated.id: "aa" * 16, conflicting.id: None},
        )

    def test_backfill_leaves_untrusted_raw_refs_unknown(self):
        def raw_source_line(ref, schema_version=SCHEMA_VERSION):
            source = {"type": "source_context", "source": {"local_member_ref": ref}}
            return json.dumps({"schema_version": schema_version, "kind": source}) + "\n"

        over_long = self.upload({"platform": "ios"})
        pre_v4 = self.upload({"platform": "android"})
        invalid = self.upload({"platform": "linux"})
        AuditFile.objects.filter(id=over_long.id).update(
            raw_text=raw_source_line("ab" * 16 + "ffff-extra")
        )
        AuditFile.objects.filter(id=pre_v4.id).update(
            raw_text=raw_source_line("ab" * 16, "marmot-forensics-audit/v3")
        )
        AuditFile.objects.filter(id=invalid.id).update(
            raw_text=raw_source_line("ab" * 16), validation_status=AuditFile.STATUS_INVALID
        )

        self.backfill()

        self.assertEqual(
            list(AuditFile.objects.values_list("source_local_member_ref", flat=True)), ["", "", ""]
        )

    def test_backfill_recovers_a_ref_whose_source_event_was_deduplicated(self):
        # A growing active file is re-uploaded: its leading source_context line
        # duplicates the earlier upload's, so no event is stored for it.
        first = self.upload({"local_member_ref": "Dd" * 16}, group_rows=1)
        grown = self.upload({"local_member_ref": "Dd" * 16}, group_rows=2)
        self.assertEqual(grown.duplicate_event_count, 2)
        AuditFile.objects.update(source_local_member_ref="")

        self.backfill()

        self.assertEqual(
            {row["id"]: row["source_local_member_ref"] for row in self.export_source_rows()},
            {first.id: "dd" * 16, grown.id: "dd" * 16},
        )

    def test_backfill_and_ingest_both_decode_an_escaped_key(self):
        body = json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "seq": 0,
                "wall_time_ms": 1700000000000,
                "engine_id": "bb" * 16,
                "account_ref": "aa" * 16,
                "group_ref": "dd" * 16,
                "context": {"source": {"local_member_ref": "44" * 16}},
                "kind": {"type": "recorder_started", "recorder": "synthetic"},
            }
        ).replace("local_member_ref", "local_\\u006dember_ref")
        audit_file = ingest_audit_log_bytes(dump_bytes=f"{body}\n".encode()).audit_file
        self.assertEqual(audit_file.source_local_member_ref, "44" * 16)
        AuditFile.objects.update(source_local_member_ref="")

        self.backfill()

        self.assertEqual(self.export_source_rows()[0]["source_local_member_ref"], "44" * 16)

    def test_backfill_and_ingest_both_read_an_event_context_source(self):
        body = json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "seq": 0,
                "wall_time_ms": 1700000000000,
                "engine_id": "bb" * 16,
                "account_ref": "aa" * 16,
                "group_ref": "dd" * 16,
                "context": {"source": {"local_member_ref": "33" * 16}},
                "kind": {"type": "recorder_started", "recorder": "synthetic"},
            }
        )
        audit_file = ingest_audit_log_bytes(dump_bytes=f"{body}\n".encode()).audit_file
        self.assertEqual(audit_file.source_local_member_ref, "33" * 16)
        AuditFile.objects.update(source_local_member_ref="")

        self.backfill()

        self.assertEqual(self.export_source_rows()[0]["source_local_member_ref"], "33" * 16)

    def upload(self, *sources, group_rows=1):
        base = {
            "schema_version": SCHEMA_VERSION,
            "wall_time_ms": 1700000000000,
            "engine_id": "bb" * 16,
            "account_ref": "aa" * 16,
            "recorder_session_id": "session-1",
        }
        events = [
            {**base, "seq": seq, "kind": {"type": "source_context", "source": source}}
            for seq, source in enumerate(sources)
        ]
        events.extend(
            {
                **base,
                "seq": seq,
                "group_ref": "dd" * 16,
                "kind": {"type": "recorder_started", "recorder": "synthetic"},
            }
            for seq in range(len(sources), len(sources) + group_rows)
        )
        body = "".join(json.dumps(event) + "\n" for event in events)
        return ingest_audit_log_bytes(dump_bytes=body.encode()).audit_file

    @staticmethod
    def backfill():
        migration = import_module("forensics.migrations.0019_backfill_source_local_member_ref")
        migration.backfill_source_local_member_refs(global_apps, None)

    def export_records(self):
        group = AuditGroup.objects.get()
        response = self.client.get(reverse("api-group-export-stream", kwargs={"slug": group.slug}))
        self.assertEqual(response.status_code, 200)
        body = b"".join(response.streaming_content).decode()
        return [json.loads(line) for line in body.splitlines() if line]

    def export_source_rows(self):
        return [record for record in self.export_records() if record["t"] == "source"]
