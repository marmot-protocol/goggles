import json

from django.test import TestCase

from .analysis import timeline_engines, valid_events_for_group
from .audit_schema import SCHEMA_VERSION
from .ingest import ingest_audit_log_bytes
from .models import AuditGroup
from .views import engine_source_values, group_engine_rows


class RotatedSourceMetadataTests(TestCase):
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
