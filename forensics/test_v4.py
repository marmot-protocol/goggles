"""The destructive-cutover boundary: prohibited bytes never become evidence."""

import hashlib
import json
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import DataError, connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase, TransactionTestCase, override_settings
from django.urls import reverse

from .analysis import timeline_engines
from .audit_schema import SCHEMA_VERSION, audit_validator, schema_error_code
from .ingest import ingest_audit_log_bytes
from .management.commands.purge_audit_data import audit_data_counts
from .models import (
    AnalysisRun,
    AuditEvent,
    AuditFile,
    AuditGroup,
    DeliveryArtifact,
    PersonalAccessToken,
    RecipientExpectation,
    UploadRejection,
    UploadToken,
)
from .seed_data import build_dev_scenario
from .views import (
    attach_delivery_matrices,
    delivery_artifact_queryset,
    group_engine_rows,
    legacy_engine_pubkeys,
    observation_identity_values,
    observation_matches_expected,
)


class V4BoundaryTests(TestCase):
    def setUp(self):
        self.raw_token, self.token = UploadToken.issue("v4 client")
        self.user = User.objects.create_user("v4-analyst")
        self.raw_pat, self.pat = PersonalAccessToken.issue("v4 reader", user=self.user)

    def event(self, **updates):
        event = {
            "schema_version": SCHEMA_VERSION,
            "seq": 0,
            "wall_time_ms": 1700000000000,
            "engine_id": "0123456789abcdef0123456789abcdef",
            "account_ref": "aa" * 16,
            "group_ref": "bb" * 16,
            "kind": {
                "type": "source_context",
                "source": {
                    "hardware_model": "iPhone17,2",
                    "platform": "ios",
                    "device_id": "cc" * 16,
                    "app_version": "2026.9.10+34",
                },
            },
        }
        return event | updates

    def post(self, body, multipart=False, **metadata):
        if isinstance(body, dict):
            body = json.dumps(body).encode()
        if isinstance(body, str):
            body = body.encode()
        headers = {"HTTP_AUTHORIZATION": f"Bearer {self.raw_token}"}
        if not multipart:
            headers["CONTENT_LENGTH"] = str(len(body))
        if multipart:
            return self.client.post(
                reverse("api-audit-log-upload"),
                {
                    "audit_log": SimpleUploadedFile("renamed-v4.jsonl", body),
                    **metadata,
                },
                **headers,
            )
        return self.client.post(
            reverse("api-audit-log-upload"),
            body,
            content_type="application/x-ndjson",
            **headers,
            **metadata,
        )

    def assert_no_evidence(self):
        for name, count in audit_data_counts().items():
            if name != "upload_rejections":
                self.assertEqual(count, 0, name)

    def test_rejects_versions_mixed_files_and_malformed_input_before_writes(self):
        marker = "PROHIBITED-ACCOUNT-NAME"
        valid = json.dumps(self.event())
        cases = [
            b"\xff",
            b"",
            b"{not json}",
            b"[]",
            b"null",
            b'{"x":NaN}',
            b'{"x":1,"x":2}',
            b'"\\ud800"',
        ]
        for version in ("v1", "v2", "v3", "v5", "unknown", None, ["v4"]):
            legacy = self.event(
                schema_version=f"marmot-forensics-audit/{version}"
                if isinstance(version, str)
                else version
            )
            legacy["kind"]["source"]["account_label"] = marker
            raw = json.dumps(legacy)
            cases.extend([raw, valid + "\n" + raw, raw + "\n" + valid])
        for multipart in (False, True):
            for body in cases:
                with self.subTest(multipart=multipart, body_type=type(body).__name__):
                    response = self.post(body, multipart)
                    self.assertEqual(response.status_code, 400)
                    self.assert_no_evidence()
                    self.assertNotIn(marker, response.content.decode())
        self.assertNotIn(marker, json.dumps(list(UploadRejection.objects.values()), default=str))
        self.assertEqual(
            {f.name for f in UploadRejection._meta.fields},
            {
                "id",
                "created_at",
                "upload_token",
                "received_bytes",
                "declared_content_length",
                "status_code",
                "reason",
                "line_number",
            },
        )

    def test_removed_and_unknown_fields_are_rejected_at_every_schema_layer(self):
        for multipart in (False, True):
            for key in (
                "account_label",
                "device_label",
                "device_name",
                "account_pubkey_hex",
                "account_npub",
                "hostname",
                "serial_number",
                "unknown-PROHIBITED",
            ):
                for placement in ("root", "kind", "source", "context_source"):
                    event = self.event()
                    target = event
                    if placement == "kind":
                        target = event["kind"]
                    if placement == "source":
                        target = event["kind"]["source"]
                    if placement == "context_source":
                        event["context"] = {"source": {}}
                        target = event["context"]["source"]
                    target[key] = "PROHIBITED"
                    with self.subTest(multipart=multipart, key=key, placement=placement):
                        response = self.post(event, multipart)
                        self.assertEqual(response.status_code, 400)
                        self.assert_no_evidence()
                        self.assertNotIn("PROHIBITED", response.content.decode())

    def test_body_metadata_and_raw_hashes_survive_but_request_labels_do_not(self):
        body = json.dumps(self.event()).encode()
        response = self.post(
            body,
            HTTP_X_GOGGLES_ACCOUNT_LABEL="PROHIBITED",
            HTTP_X_GOGGLES_DEVICE_LABEL="PROHIBITED",
            HTTP_X_GOGGLES_HARDWARE_MODEL="PROHIBITED",
            HTTP_USER_AGENT="PROHIBITED",
        )
        self.assertEqual(response.status_code, 201)
        file = AuditFile.objects.get()
        self.assertEqual(file.raw_text, body.decode())
        self.assertEqual(file.file_sha256, hashlib.sha256(body).hexdigest())
        self.assertEqual(file.source_hardware_model, "iPhone17,2")
        self.assertEqual(file.source_name, "")
        self.assertEqual(file.user_agent, "")
        self.assertEqual(AuditEvent.objects.get().line_hash, hashlib.sha256(body).hexdigest())
        self.assertNotIn("PROHIBITED", json.dumps(list(AuditFile.objects.values()), default=str))
        row = group_engine_rows(AuditGroup.objects.get())[0]
        self.assertEqual(row["label"], "ios / iPhone17,2 / 0123456789ab")
        self.assertNotIn("account_labels", row["source_metadata"])
        self.client.force_login(self.user)
        export = self.client.get(reverse("group-agent-export", kwargs={"slug": "bb" * 16}))
        self.assertEqual(export.status_code, 200)
        self.assertContains(export, "iPhone17,2")
        self.assertNotContains(export, "source_account_label")
        # The same upload through multipart is validated before deduplication.
        response = self.post(
            body,
            True,
            account_label="PROHIBITED",
            device_label="PROHIBITED",
            device_name="PROHIBITED",
            hardware_model="PROHIBITED",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(AuditFile.objects.count(), 1)
        # Also exercise a fresh multipart file, so deduplication cannot mask
        # accidental persistence of form metadata on the create path.
        response = self.post(
            self.event(seq=1),
            True,
            account_label="PROHIBITED",
            device_label="PROHIBITED",
            device_name="PROHIBITED",
            hardware_model="PROHIBITED",
        )
        self.assertEqual(response.status_code, 201)
        self.assertNotIn("PROHIBITED", json.dumps(list(AuditFile.objects.values()), default=str))
        self.assertEqual(
            set(AuditFile.objects.values_list("source_hardware_model", flat=True)), {"iPhone17,2"}
        )

    def test_v4_segment_without_source_context_is_valid(self):
        response = self.post(self.event(kind={"type": "recorder_started", "recorder": "mdk"}))
        self.assertEqual(response.status_code, 201)
        self.assertEqual(AuditFile.objects.get().source_hardware_model, "")

    def test_rejected_legacy_hash_does_not_deduplicate_into_historical_file(self):
        body = json.dumps(self.event(schema_version="marmot-forensics-audit/v3")).encode()
        old = AuditFile.objects.create(
            file_sha256=hashlib.sha256(body).hexdigest(),
            raw_text=body.decode(),
            byte_size=len(body),
        )
        self.assertEqual(self.post(body).status_code, 400)
        self.assertEqual(AuditFile.objects.get().pk, old.pk)

    def test_purge_preserves_credentials_and_legacy_replays_cannot_repopulate(self):
        self.assertEqual(self.post(self.event()).status_code, 201)
        AnalysisRun.objects.create(
            group=AuditGroup.objects.get(),
            created_by=self.user,
            title="historical report",
            report_json={"removed": "PROHIBITED"},
        )
        self.post(b"invalid")
        out = StringIO()
        call_command("purge_audit_data", "--dry-run", stdout=out)
        self.assertIn("upload_rejections=1", out.getvalue())
        self.assertEqual(AuditFile.objects.count(), 1)
        call_command("purge_audit_data", "--confirm-delete-audit-data", stdout=StringIO())
        self.assert_no_evidence()
        self.assertFalse(UploadRejection.objects.exists())
        self.assertIsNotNone(UploadToken.authenticate(self.raw_token))
        self.assertIsNotNone(PersonalAccessToken.authenticate(self.raw_pat))
        self.assertTrue(User.objects.filter(pk=self.user.pk).exists())
        for multipart in (False, True):
            for version in ("v1", "v2", "v3"):
                self.assertEqual(
                    self.post(
                        self.event(schema_version="marmot-forensics-audit/" + version), multipart
                    ).status_code,
                    400,
                )
                self.assert_no_evidence()
            prohibited = self.event()
            prohibited["kind"]["source"]["account_label"] = "PROHIBITED"
            self.assertEqual(self.post(prohibited, multipart).status_code, 400)
            self.assert_no_evidence()
        self.assertEqual(self.post(self.event()).status_code, 201)

    def test_internal_failure_rolls_back_raw_evidence_and_groups(self):
        for multipart in (False, True):
            with (
                self.assertLogs("forensics.ingest", level="WARNING") as logs,
                patch(
                    "forensics.ingest.refresh_group_rollups", side_effect=DataError("PROHIBITED")
                ),
            ):
                response = self.post(self.event(), multipart)
            self.assertEqual(response.status_code, 503)
            self.assertEqual(
                logs.output,
                ["WARNING:forensics.ingest:audit log ingestion failed: error_type=DataError"],
            )
            self.assert_no_evidence()
            self.assertNotIn("PROHIBITED", response.content.decode())

    def test_fixed_diagnostics_distinguish_contract_and_storage_errors(self):
        oversized_time = self.event(wall_time_ms=4102444800001)
        self.assertTrue(audit_validator().is_valid(oversized_time))
        for multipart in (False, True):
            for payload, expected in (
                (b"{", "invalid_json"),
                (b"[]", "invalid_json_object"),
                (self.event(schema_version="marmot-forensics-audit/v3"), "unsupported_schema"),
                (self.event(unknown="PROHIBITED"), "invalid_v4_schema"),
                (oversized_time, "storage_limit_exceeded"),
            ):
                with self.subTest(multipart=multipart, expected=expected):
                    response = self.post(payload, multipart)
                    self.assertEqual(response.status_code, 400)
                    self.assertEqual(
                        response.json(), {"error": expected, "reason": expected, "line_number": 1}
                    )
                    self.assertEqual(UploadRejection.objects.latest("id").reason, expected)
                    self.assert_no_evidence()

    def test_schema_cli_reports_missing_schema_without_path(self):
        with self.assertRaisesMessage(CommandError, "unreadable_schema") as caught:
            call_command("validate_audit_schema", "unused.jsonl", schema="/PROHIBITED/missing.json")
        self.assertEqual(str(caught.exception), "unreadable_schema")

    def test_timeline_merges_complementary_and_partial_source_metadata(self):
        for sources in (
            [("ios", "iPhone17,2"), ("ios", "")],
            [("", "iPhone17,2"), ("ios", "")],
            [("ios", ""), ("", "iPhone17,2")],
        ):
            events = [
                SimpleNamespace(
                    engine_id="a" * 32,
                    account_ref="b" * 32,
                    wall_time_ms=idx,
                    audit_file_id=idx,
                    audit_file=SimpleNamespace(
                        source_platform=platform, source_hardware_model=model
                    ),
                )
                for idx, (platform, model) in enumerate(sources)
            ]
            engines, _ = timeline_engines(events)
            self.assertEqual(engines[0]["label"], "ios / iPhone17,2 / aaaaaaaaaaaa")

    def test_legacy_observation_identity_remains_readable_until_purge(self):
        observation = SimpleNamespace(
            account_ref="",
            engine_id="a" * 32,
            evidence_events=SimpleNamespace(
                all=lambda: [
                    SimpleNamespace(
                        schema_version="marmot-forensics-audit/v2",
                        context_source={"account_pubkey_hex": "b" * 64},
                    ),
                    SimpleNamespace(
                        schema_version=SCHEMA_VERSION,
                        context_source={"account_pubkey_hex": "c" * 64},
                    ),
                ]
            ),
        )
        identities = observation_identity_values(observation)
        self.assertTrue(observation_matches_expected(identities, "pubkey_hex", "b" * 64))
        self.assertFalse(observation_matches_expected(identities, "pubkey_hex", "c" * 64))

    def test_legacy_missing_recipient_marks_real_engine_cell_without_source_pubkey(self):
        self.assertEqual(self.post(self.event()).status_code, 201)
        event = AuditEvent.objects.get()
        pubkey = "d" * 64
        event.schema_version = "marmot-forensics-audit/v2"
        event.context_source = {"account_pubkey_hex": pubkey}
        event.save(update_fields=["schema_version", "context_source"])
        artifact = DeliveryArtifact.objects.create(group=event.group, artifact_id="e" * 64)
        RecipientExpectation.objects.create(
            artifact=artifact,
            evidence_event=event,
            recipient_scope="group_members",
            expected_pubkeys_hex=[pubkey],
        )
        engines = group_engine_rows(event.group)
        artifact = delivery_artifact_queryset().get(pk=artifact.pk)
        attach_delivery_matrices([artifact], event.group, engines=engines)
        self.assertEqual(artifact.recipient_matrix[0]["status"], "missing_inferred")
        self.assertEqual(artifact.delivery_engine_cells[0]["status"], "missing_inferred")
        self.assertEqual(artifact.delivery_engine_cells[0]["engine"], engines[0])
        self.assertNotIn(pubkey, json.dumps(artifact.delivery_engine_cells))
        self.assertNotIn("account_pubkeys_hex", json.dumps(engines))
        event.schema_version = SCHEMA_VERSION
        event.save(update_fields=["schema_version"])
        self.assertEqual(legacy_engine_pubkeys(event.group), {})

    def test_schema_valid_odd_hex_group_ref_is_visible_on_both_upload_paths(self):
        event = self.event(group_ref="abc")
        self.assertTrue(audit_validator().is_valid(event))
        for multipart in (False, True):
            response = self.post(event, multipart)
            self.assertIn(response.status_code, (200, 201))
            self.assertEqual(response.json()["groups"], ["abc"])
            stored = AuditEvent.objects.get()
            self.assertEqual(stored.group.group_ref, "abc")
            self.assertEqual(group_engine_rows(stored.group)[0]["event_count"], 1)
            self.assertFalse(UploadRejection.objects.exists())
        # An explicit fallback must not steal a schema-valid declared reference.
        response = self.client.post(
            reverse("api-group-audit-log-upload", kwargs={"group_slug": "fallback"}),
            json.dumps(event),
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {self.raw_token}",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["groups"], ["abc"])
        self.assertFalse(AuditGroup.objects.filter(slug="fallback").exists())

    def test_rejections_ui_identifies_credential_without_request_metadata(self):
        self.post(b"invalid")
        self.client.force_login(self.user)
        response = self.client.get(reverse("upload-log-list"))
        self.assertContains(response, self.token.name)
        self.assertContains(response, self.token.token_prefix)
        self.assertEqual(response.context["stats"]["rejected"], 1)

    def test_multiple_multipart_files_cannot_hide_legacy_second_part(self):
        response = self.client.post(
            reverse("api-audit-log-upload"),
            {
                "audit_log": [
                    SimpleUploadedFile("new.jsonl", json.dumps(self.event()).encode()),
                    SimpleUploadedFile("new2.jsonl", b"PROHIBITED"),
                ]
            },
            HTTP_AUTHORIZATION=f"Bearer {self.raw_token}",
        )
        self.assertEqual(response.status_code, 413)
        self.assert_no_evidence()

    def test_fixture_variants_match_authoritative_schema_and_ingest(self):
        for log in build_dev_scenario():
            for raw in log.jsonl.splitlines():
                event = json.loads(raw)
                self.assertTrue(audit_validator().is_valid(event))
                self.assertIsNone(schema_error_code(event))
            self.assertTrue(ingest_audit_log_bytes(dump_bytes=log.dump_bytes).created)

    def test_upload_telemetry_drops_arbitrary_request_and_exception_values(self):
        from config.settings import scrub_glitchtip_event

        for path in ("/api/v1/audit-logs/", "/api/v1/groups/example/audit-logs/"):
            self.assertIsNone(
                scrub_glitchtip_event(
                    {
                        "request": {
                            "url": "https://goggles.example" + path,
                            "headers": {"Unknown": "PROHIBITED"},
                            "data": "PROHIBITED",
                        },
                        "exception": {"values": [{"value": "PROHIBITED"}]},
                        "breadcrumbs": {"values": [{"message": "PROHIBITED"}]},
                    },
                    {},
                )
            )

    def test_rotated_segment_keeps_known_engine_model_on_timeline(self):
        from .analysis import timeline_engines

        self.post(self.event())
        self.post(
            self.event(
                seq=1,
                wall_time_ms=1700000000001,
                kind={"type": "recorder_started", "recorder": "mdk"},
            )
        )
        engines, _ = timeline_engines(
            AuditEvent.objects.select_related("audit_file").order_by("seq")
        )
        self.assertEqual(engines[0]["label"], "ios / iPhone17,2 / 0123456789ab")

    @override_settings(FILE_UPLOAD_MAX_MEMORY_SIZE=1)
    def test_multipart_validation_never_spools_raw_bytes_to_disk(self):
        with patch(
            "django.core.files.uploadhandler.TemporaryUploadedFile",
            side_effect=AssertionError("unvalidated data reached disk"),
        ):
            self.assertEqual(self.post(b"PROHIBITED" * 1000, True).status_code, 400)
            self.assert_no_evidence()
            self.assertEqual(self.post(self.event(), True).status_code, 201)


class V4MigrationTests(TransactionTestCase):
    def test_upgrade_removes_metadata_without_implicitly_purging_evidence_or_credentials(self):
        latest = ("forensics", "0015_remove_auditfile_source_account_label_and_more")
        previous = ("forensics", "0014_uploadrejection")
        user = User.objects.create_user("migration-user")
        raw_token, token = UploadToken.issue("migration-client")
        raw_pat, _ = PersonalAccessToken.issue("migration-reader", user=user)
        executor = MigrationExecutor(connection)
        executor.migrate([previous])
        try:
            old_apps = executor.loader.project_state([previous]).apps
            old_files = old_apps.get_model("forensics", "AuditFile")
            old_rejections = old_apps.get_model("forensics", "UploadRejection")
            raw = '{"schema_version":"marmot-forensics-audit/v3","account_label":"PROHIBITED"}'
            old = old_files.objects.create(
                file_sha256="c" * 64,
                byte_size=len(raw),
                raw_text=raw,
                source_account_label="PROHIBITED",
                source_device_label="PROHIBITED",
                source_device_name="PROHIBITED",
            )
            old_rejections.objects.create(
                upload_token_id=token.pk,
                reason="incomplete_body",
                status_code=400,
                source_device_label="PROHIBITED",
                user_agent="PROHIBITED",
            )
        finally:
            MigrationExecutor(connection).migrate([latest])
        self.assertEqual(AuditFile.objects.get(pk=old.pk).raw_text, raw)
        self.assertNotIn(
            "PROHIBITED", json.dumps(list(UploadRejection.objects.values()), default=str)
        )
        for name in ("source_account_label", "source_device_label", "source_device_name"):
            self.assertNotIn(name, {field.name for field in AuditFile._meta.fields})
        call_command("purge_audit_data", "--confirm-delete-audit-data", stdout=StringIO())
        self.assertTrue(all(count == 0 for count in audit_data_counts().values()))
        self.assertIsNotNone(UploadToken.authenticate(raw_token))
        self.assertIsNotNone(PersonalAccessToken.authenticate(raw_pat))
        self.assertTrue(User.objects.filter(pk=user.pk).exists())
