import json
from io import StringIO

from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from .analysis import (
    audit_files_for_group,
    display_group_ref,
    group_list_rows,
    timeline_payload_for_group,
    valid_events_for_group,
)
from .ingest import ingest_audit_log_bytes
from .models import AuditEvent, AuditFile, AuditGroup, UploadToken

SCHEMA_VERSION = "marmot-forensics-audit/v1"
ENGINE_ALICE = "0123456789abcdef0123456789abcdef"
ENGINE_BOB = "abcdef0123456789abcdef0123456789"
ACCOUNT_ALICE = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ACCOUNT_BOB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
GROUP_REF = "11" * 32
OTHER_GROUP_REF = "44" * 32
MSG_ID = "22" * 32
OTHER_MSG_ID = "33" * 32
DIGEST_A = "aa" * 32
DIGEST_B = "bb" * 32


def audit_event(
    seq,
    engine_id=ENGINE_ALICE,
    group_ref=GROUP_REF,
    account_ref=ACCOUNT_ALICE,
    kind=None,
    wall_time_ms=None,
    context=None,
    human_action=None,
):
    action = human_action or {
        "action": "update_group_profile",
        "origin": "local_user",
        "fields": ["name"],
        "component_ids": [32769],
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "seq": seq,
        "wall_time_ms": wall_time_ms or 1_700_000_000_000 + seq,
        "account_ref": account_ref,
        "engine_id": engine_id,
        "group_ref": group_ref,
        "context": context
        if context is not None
        else {"operation_id": f"op-{seq}", "human_action": action},
        "kind": kind
        or {
            "type": "ingest_entry",
            "msg_id": MSG_ID,
            "envelope_kind": "group_message",
            "payload_len": 512,
            "payload_digest": DIGEST_A,
        },
    }


def jsonl(*events):
    return "\n".join(json.dumps(event, separators=(",", ":")) for event in events) + "\n"


def representative_audit_log(engine_id=ENGINE_ALICE):
    return jsonl(
        audit_event(
            0,
            engine_id=engine_id,
            kind={
                "type": "ingest_entry",
                "msg_id": MSG_ID,
                "envelope_kind": "group_message",
                "payload_len": 512,
                "payload_digest": DIGEST_A,
            },
        ),
        audit_event(
            1,
            engine_id=engine_id,
            kind={
                "type": "ingest_outcome",
                "msg_id": MSG_ID,
                "outcome_kind": "processed",
                "epoch": 7,
            },
        ),
    )


class AuditLogIngestionTests(TestCase):
    def test_bearer_token_post_stores_valid_jsonl_and_normalizes_events(self):
        raw_token, token = UploadToken.issue("ios test client")
        body = representative_audit_log()

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["created"], True)
        self.assertEqual(response.json()["group"], GROUP_REF)
        self.assertEqual(response.json()["groups"], [GROUP_REF])
        self.assertEqual(response.json()["validation_status"], "valid")
        self.assertEqual(response.json()["event_count"], 2)

        group = AuditGroup.objects.get(slug=GROUP_REF)
        self.assertEqual(group.group_ref, GROUP_REF)
        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.upload_token, token)
        self.assertEqual(audit_file.raw_text, body)
        self.assertEqual(audit_file.byte_size, len(body.encode("utf-8")))
        self.assertEqual(audit_file.account_refs, [ACCOUNT_ALICE])
        self.assertEqual(audit_file.engine_ids, [ENGINE_ALICE])
        self.assertEqual(audit_file.group_refs, [GROUP_REF])
        self.assertEqual(audit_file.schema_versions, [SCHEMA_VERSION])

        events = list(AuditEvent.objects.filter(group=group).order_by("line_number"))
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].event_type, "ingest_entry")
        self.assertEqual(events[0].account_ref, ACCOUNT_ALICE)
        self.assertEqual(events[0].engine_id, ENGINE_ALICE)
        self.assertEqual(events[0].group_ref, GROUP_REF)
        self.assertEqual(events[0].msg_id, MSG_ID)
        self.assertEqual(events[0].payload_digest, DIGEST_A)
        self.assertEqual(events[1].event_type, "ingest_outcome")
        self.assertEqual(events[1].outcome_kind, "processed")
        self.assertEqual(events[1].epoch, 7)

    def test_api_rejects_upload_without_valid_token(self):
        for authorization in ("", "Bearer invalid-token"):
            headers = {}
            if authorization:
                headers["HTTP_AUTHORIZATION"] = authorization
            response = self.client.post(
                reverse("api-audit-log-upload"),
                data=representative_audit_log(),
                content_type="application/x-ndjson",
                **headers,
            )

            self.assertEqual(response.status_code, 401)
        self.assertEqual(AuditFile.objects.count(), 0)
        self.assertEqual(AuditEvent.objects.count(), 0)

    def test_api_rejects_non_post_upload_attempts_cleanly(self):
        raw_token, _token = UploadToken.issue("ios test client")

        response = self.client.get(
            reverse("api-audit-log-upload"),
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 405)
        self.assertEqual(AuditFile.objects.count(), 0)
        self.assertEqual(AuditEvent.objects.count(), 0)

    @override_settings(
        GOGGLES_MAX_DUMP_BYTES=10,
        DATA_UPLOAD_MAX_MEMORY_SIZE=1024,
        FILE_UPLOAD_MAX_MEMORY_SIZE=1024,
    )
    def test_api_rejects_oversized_upload_without_saving(self):
        raw_token, _token = UploadToken.issue("ios test client")

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data="x" * 11,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json()["error"], "audit log exceeds maximum upload size")
        self.assertEqual(AuditFile.objects.count(), 0)
        self.assertEqual(AuditEvent.objects.count(), 0)

    @override_settings(
        GOGGLES_MAX_DUMP_BYTES=100,
        DATA_UPLOAD_MAX_MEMORY_SIZE=10,
        FILE_UPLOAD_MAX_MEMORY_SIZE=10,
    )
    def test_api_rejects_django_body_limit_without_saving(self):
        raw_token, _token = UploadToken.issue("ios test client")

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data="x" * 11,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json()["error"], "audit log exceeds maximum upload size")
        self.assertEqual(AuditFile.objects.count(), 0)
        self.assertEqual(AuditEvent.objects.count(), 0)

    def test_multipart_audit_log_upload_is_accepted(self):
        raw_token, _token = UploadToken.issue("android qa client")
        body = representative_audit_log(ENGINE_BOB)
        upload_file = SimpleUploadedFile(
            "audit-android.jsonl",
            body.encode("utf-8"),
            content_type="application/x-ndjson",
        )

        response = self.client.post(
            reverse("api-group-audit-log-upload", kwargs={"group_slug": "mobile-qa"}),
            data={"audit_log": upload_file},
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["group"], GROUP_REF)
        self.assertEqual(response.json()["groups"], [GROUP_REF])
        self.assertFalse(AuditGroup.objects.filter(slug="mobile-qa").exists())
        self.assertEqual(AuditFile.objects.get().source_name, "audit-android.jsonl")
        self.assertEqual(AuditEvent.objects.get(event_type="ingest_entry").engine_id, ENGINE_BOB)

    def test_one_engine_upload_can_populate_multiple_groups(self):
        raw_token, _token = UploadToken.issue("alice devices")
        body = jsonl(
            audit_event(0),
            audit_event(
                1,
                group_ref=OTHER_GROUP_REF,
                kind={
                    "type": "message_state_changed",
                    "msg_id": OTHER_MSG_ID,
                    "new_state": "processed",
                    "reason": "state_update",
                },
            ),
        )

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["groups"], [GROUP_REF, OTHER_GROUP_REF])

        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.account_refs, [ACCOUNT_ALICE])
        self.assertEqual(audit_file.engine_ids, [ENGINE_ALICE])
        self.assertEqual(audit_file.group_refs, [GROUP_REF, OTHER_GROUP_REF])
        self.assertIsNone(getattr(audit_file, "group", None))

        first_group = AuditGroup.objects.get(group_ref=GROUP_REF)
        second_group = AuditGroup.objects.get(group_ref=OTHER_GROUP_REF)
        self.assertEqual(
            list(AuditEvent.objects.filter(group=first_group).values_list("seq", flat=True)),
            [0],
        )
        self.assertEqual(
            list(AuditEvent.objects.filter(group=second_group).values_list("seq", flat=True)),
            [1],
        )

    def test_long_group_refs_with_same_slug_prefix_create_distinct_groups(self):
        raw_token, _token = UploadToken.issue("alice devices")
        shared_prefix = "aa" * 80
        first_group_ref = shared_prefix + "00"
        second_group_ref = shared_prefix + "11"

        first_response = self.client.post(
            reverse("api-audit-log-upload"),
            data=jsonl(audit_event(0, group_ref=first_group_ref)),
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )
        second_response = self.client.post(
            reverse("api-audit-log-upload"),
            data=jsonl(audit_event(1, group_ref=second_group_ref)),
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(first_response.status_code, 201)
        self.assertEqual(second_response.status_code, 201)
        self.assertEqual(AuditGroup.objects.count(), 2)

        first_group = AuditGroup.objects.get(group_ref=first_group_ref)
        second_group = AuditGroup.objects.get(group_ref=second_group_ref)
        self.assertNotEqual(first_group.slug, second_group.slug)
        self.assertEqual(
            list(AuditEvent.objects.filter(group=first_group).values_list("group_ref", flat=True)),
            [first_group_ref],
        )
        self.assertEqual(
            list(AuditEvent.objects.filter(group=second_group).values_list("group_ref", flat=True)),
            [second_group_ref],
        )

    def test_upload_source_metadata_headers_are_saved(self):
        raw_token, _token = UploadToken.issue("alice iphone")

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=representative_audit_log(),
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
            HTTP_X_GOGGLES_ACCOUNT_LABEL="Alice",
            HTTP_X_GOGGLES_DEVICE_LABEL="Alice iPhone",
            HTTP_X_GOGGLES_PLATFORM="ios",
            HTTP_X_GOGGLES_APP_VERSION="2026.6.8",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            response.json()["source"],
            {
                "account_label": "Alice",
                "device_label": "Alice iPhone",
                "platform": "ios",
                "app_version": "2026.6.8",
            },
        )

        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.source_account_label, "Alice")
        self.assertEqual(audit_file.source_device_label, "Alice iPhone")
        self.assertEqual(audit_file.source_platform, "ios")
        self.assertEqual(audit_file.source_app_version, "2026.6.8")

    def test_invalid_jsonl_returns_400_and_saves_quarantined_upload(self):
        raw_token, _token = UploadToken.issue("ios test client")
        bad_body = representative_audit_log() + "{not-json}\n"

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=bad_body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["validation_status"], "invalid")
        self.assertIn("line 3", response.json()["error"])

        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.validation_status, "invalid")
        self.assertIn("line 3", audit_file.validation_error)
        self.assertEqual(audit_file.group_refs, [GROUP_REF])
        self.assertEqual(audit_file.events.count(), 3)
        bad_event = audit_file.events.get(line_number=3)
        self.assertEqual(bad_event.parse_status, "invalid")
        self.assertEqual(bad_event.raw_line, "{not-json}")
        self.assertIn("JSON", bad_event.validation_error)

    def test_overlong_normalized_value_returns_400_and_is_quarantined(self):
        raw_token, _token = UploadToken.issue("ios test client")
        body = jsonl(
            audit_event(
                0,
                kind={
                    "type": "ingest_entry",
                    "msg_id": MSG_ID,
                    "envelope_kind": "x" * 121,
                    "payload_len": 512,
                    "payload_digest": DIGEST_A,
                },
            )
        )

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["validation_status"], "invalid")
        self.assertIn("envelope_kind", response.json()["error"])

        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.validation_status, AuditFile.STATUS_INVALID)
        event = audit_file.events.get()
        self.assertEqual(event.parse_status, AuditEvent.STATUS_INVALID)
        self.assertIn("envelope_kind", event.validation_error)
        self.assertEqual(event.envelope_kind, "")

    def test_json_booleans_are_rejected_for_integer_fields(self):
        raw_token, _token = UploadToken.issue("ios test client")
        body = jsonl(
            audit_event(
                True,
                wall_time_ms=True,
                kind={
                    "type": "ingest_entry",
                    "msg_id": MSG_ID,
                    "envelope_kind": "group_message",
                    "payload_len": True,
                    "payload_digest": DIGEST_A,
                },
            )
        )

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["validation_status"], "invalid")
        self.assertIn("seq must be a non-negative integer", response.json()["error"])
        self.assertIn("wall_time_ms must be a non-negative integer", response.json()["error"])
        self.assertIn("payload_len must be a non-negative integer", response.json()["error"])

        event = AuditEvent.objects.get()
        self.assertEqual(event.parse_status, AuditEvent.STATUS_INVALID)
        self.assertIsNone(event.seq)
        self.assertIsNone(event.wall_time_ms)
        self.assertIsNone(event.payload_len)

    def test_out_of_range_bigint_returns_400_and_is_quarantined(self):
        # seq exceeds the bigint column ceiling (9.2e18). Previously this
        # passed value_if_int(), was normalized as valid, and only blew up at
        # bulk_create() with an uncaught DataError -> 500 and lost raw text.
        raw_token, _token = UploadToken.issue("ios test client")
        body = jsonl(audit_event(100_000_000_000_000_000_000))

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["validation_status"], "invalid")
        self.assertIn("seq must be a non-negative integer within range", response.json()["error"])

        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.validation_status, AuditFile.STATUS_INVALID)
        # Raw evidence is preserved rather than lost to a 500.
        self.assertEqual(audit_file.raw_text, body)
        event = audit_file.events.get()
        self.assertEqual(event.parse_status, AuditEvent.STATUS_INVALID)
        self.assertIsNone(event.seq)
        self.assertIn("seq must be a non-negative integer within range", event.validation_error)

    def test_out_of_range_integer_field_returns_400_and_is_quarantined(self):
        # target_count -> human_action_target_count is a PositiveIntegerField
        # (32-bit integer column, max 2,147,483,647). 5e9 fits a bigint but not
        # this column, so it must be rejected even though it is well below the
        # bigint ceiling -- a value a buggy client could plausibly emit.
        raw_token, _token = UploadToken.issue("ios test client")
        body = jsonl(
            audit_event(
                0,
                human_action={
                    "action": "update_group_profile",
                    "origin": "local_user",
                    "fields": ["name"],
                    "target_count": 5_000_000_000,
                },
            )
        )

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["validation_status"], "invalid")
        self.assertIn(
            "target_count must be a non-negative integer within range",
            response.json()["error"],
        )

        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.validation_status, AuditFile.STATUS_INVALID)
        self.assertEqual(audit_file.raw_text, body)
        event = audit_file.events.get()
        self.assertEqual(event.parse_status, AuditEvent.STATUS_INVALID)
        self.assertIsNone(event.human_action_target_count)
        self.assertIn(
            "target_count must be a non-negative integer within range",
            event.validation_error,
        )

    def test_mixed_engine_audit_log_returns_400_and_is_quarantined(self):
        raw_token, _token = UploadToken.issue("mixed client")
        body = jsonl(
            audit_event(0, engine_id=ENGINE_ALICE),
            audit_event(1, engine_id=ENGINE_BOB),
        )

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["validation_status"], "invalid")
        self.assertIn("multiple engine_ids", response.json()["error"])

        group = AuditGroup.objects.get(slug=GROUP_REF)
        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.validation_status, "invalid")
        self.assertEqual(audit_file.valid_event_count, 2)
        self.assertEqual(audit_file.invalid_event_count, 0)
        self.assertEqual(audit_file.engine_ids, [ENGINE_ALICE, ENGINE_BOB])
        self.assertEqual(audit_file.events.count(), 2)
        payload = timeline_payload_for_group(group, list(valid_events_for_group(group)), [])
        self.assertEqual(payload["engines"], [])
        self.assertEqual(payload["items"], [])

    def test_reuploading_grown_append_only_log_deduplicates_existing_lines(self):
        raw_token, _token = UploadToken.issue("ios test client")
        first = representative_audit_log()
        grown = first + json.dumps(
            audit_event(
                2,
                kind={
                    "type": "message_state_changed",
                    "msg_id": MSG_ID,
                    "new_state": "processed",
                    "reason": "state_update",
                },
            ),
            separators=(",", ":"),
        )

        first_response = self.client.post(
            reverse("api-audit-log-upload"),
            data=first,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )
        grown_response = self.client.post(
            reverse("api-audit-log-upload"),
            data=grown,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(first_response.status_code, 201)
        self.assertEqual(grown_response.status_code, 201)
        self.assertEqual(AuditFile.objects.count(), 2)
        self.assertEqual(AuditEvent.objects.filter(group__slug=GROUP_REF).count(), 3)
        self.assertEqual(AuditFile.objects.order_by("created_at").last().duplicate_event_count, 2)

    def test_corrected_valid_upload_keeps_lines_seen_in_quarantined_upload(self):
        raw_token, _token = UploadToken.issue("ios test client")
        bad_body = json.dumps(audit_event(0), separators=(",", ":")) + "\n{not-json}\n"
        corrected_body = jsonl(
            audit_event(0),
            audit_event(
                1,
                kind={
                    "type": "message_state_changed",
                    "msg_id": OTHER_MSG_ID,
                    "new_state": "processed",
                    "reason": "state_update",
                },
            ),
        )

        bad_response = self.client.post(
            reverse("api-audit-log-upload"),
            data=bad_body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )
        corrected_response = self.client.post(
            reverse("api-audit-log-upload"),
            data=corrected_body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(bad_response.status_code, 400)
        self.assertEqual(corrected_response.status_code, 201)
        self.assertEqual(corrected_response.json()["duplicate_event_count"], 0)

        valid_file = AuditFile.objects.get(validation_status=AuditFile.STATUS_VALID)
        self.assertEqual(valid_file.valid_event_count, 2)
        self.assertEqual(valid_file.events.count(), 2)
        self.assertEqual(
            list(
                AuditEvent.objects.filter(
                    group__slug=GROUP_REF,
                    audit_file__validation_status=AuditFile.STATUS_VALID,
                    parse_status=AuditEvent.STATUS_VALID,
                ).values_list("msg_id", flat=True)
            ),
            [MSG_ID, OTHER_MSG_ID],
        )

    def test_upload_batches_database_work_for_many_lines(self):
        raw_token, _token = UploadToken.issue("ios test client")
        body = jsonl(
            *[
                audit_event(
                    seq,
                    kind={
                        "type": "ingest_entry",
                        "msg_id": f"{seq:064x}",
                        "envelope_kind": "group_message",
                        "payload_len": 512,
                        "payload_digest": DIGEST_A,
                    },
                )
                for seq in range(20)
            ]
        )

        with CaptureQueriesContext(connection) as queries:
            response = self.client.post(
                reverse("api-audit-log-upload"),
                data=body,
                content_type="application/x-ndjson",
                HTTP_AUTHORIZATION=f"Bearer {raw_token}",
            )

        self.assertEqual(response.status_code, 201)
        self.assertLessEqual(len(queries), 35)
        self.assertEqual(AuditEvent.objects.count(), 20)

    def test_all_supported_audit_kind_variants_are_normalized(self):
        raw_token, _token = UploadToken.issue("ios test client")
        cases = [
            (
                "ingest_entry",
                {
                    "type": "ingest_entry",
                    "msg_id": MSG_ID,
                    "envelope_kind": "group_message",
                    "payload_len": 512,
                    "payload_digest": DIGEST_A,
                },
                {
                    "msg_id": MSG_ID,
                    "envelope_kind": "group_message",
                    "payload_len": 512,
                    "payload_digest": DIGEST_A,
                },
            ),
            (
                "ingest_outcome",
                {
                    "type": "ingest_outcome",
                    "msg_id": MSG_ID,
                    "outcome_kind": "processed",
                    "stale_reason": "already_seen",
                    "epoch": 7,
                },
                {
                    "msg_id": MSG_ID,
                    "outcome_kind": "processed",
                    "stale_reason": "already_seen",
                    "epoch": 7,
                },
            ),
            (
                "send_entry",
                {
                    "type": "send_entry",
                    "intent_kind": "invite",
                },
                {
                    "intent_kind": "invite",
                },
            ),
            (
                "send_outcome",
                {
                    "type": "send_outcome",
                    "intent_kind": "invite",
                    "result_kind": "group_evolution",
                    "outbound_msg_id": MSG_ID,
                    "outbound_welcome_msg_ids": [OTHER_MSG_ID],
                },
                {
                    "intent_kind": "invite",
                    "result_kind": "group_evolution",
                    "outbound_msg_id": MSG_ID,
                    "outbound_welcome_msg_ids": [OTHER_MSG_ID],
                },
            ),
            (
                "publish_attempt",
                {
                    "type": "publish_attempt",
                    "msg_id": MSG_ID,
                    "target_kind": "group",
                    "relay_urls": ["wss://relay1.example", "wss://relay2.example"],
                    "required_acks": 1,
                },
                {
                    "msg_id": MSG_ID,
                    "target_kind": "group",
                    "relay_urls": ["wss://relay1.example", "wss://relay2.example"],
                    "required_acks": 1,
                },
            ),
            (
                "publish_outcome",
                {
                    "type": "publish_outcome",
                    "msg_id": MSG_ID,
                    "target_kind": "group",
                    "accepted_relay_urls": ["wss://relay1.example"],
                    "failed_relays": [{"relay_url": "wss://relay2.example", "reason": "timeout"}],
                    "required_acks": 1,
                    "met_required_acks": True,
                },
                {
                    "msg_id": MSG_ID,
                    "target_kind": "group",
                    "accepted_relay_urls": ["wss://relay1.example"],
                    "failed_relays": [{"relay_url": "wss://relay2.example", "reason": "timeout"}],
                    "required_acks": 1,
                    "met_required_acks": True,
                },
            ),
            (
                "human_action",
                {
                    "type": "human_action",
                    "action": "promote_admin",
                    "origin": "observed_group_event",
                    "phase": "observed",
                    "fields": ["admins"],
                    "component_ids": [32770],
                    "target_count": 1,
                    "message_ids": [OTHER_MSG_ID],
                    "from_epoch": 7,
                    "to_epoch": 8,
                },
                {
                    "human_action_action": "promote_admin",
                    "human_action_origin": "observed_group_event",
                    "human_action_phase": "observed",
                    "human_action_fields": ["admins"],
                    "human_action_component_ids": [32770],
                    "human_action_target_count": 1,
                    "human_action_message_ids": [OTHER_MSG_ID],
                    "from_epoch": 7,
                    "to_epoch": 8,
                },
            ),
            (
                "epoch_confirmed",
                {
                    "type": "epoch_confirmed",
                    "from_epoch": 6,
                    "to_epoch": 7,
                    "pending_kind": "commit",
                },
                {
                    "from_epoch": 6,
                    "to_epoch": 7,
                    "pending_kind": "commit",
                },
            ),
            (
                "epoch_rolled_back",
                {
                    "type": "epoch_rolled_back",
                    "pending_epoch": 8,
                    "restored_epoch": 6,
                    "pending_kind": "proposal",
                },
                {
                    "pending_epoch": 8,
                    "restored_epoch": 6,
                    "pending_kind": "proposal",
                },
            ),
            (
                "snapshot_created",
                {
                    "type": "snapshot_created",
                    "snapshot_name": "pre-peel",
                    "source_epoch": 6,
                    "reason": "before_rewind",
                },
                {
                    "snapshot_name": "pre-peel",
                    "source_epoch": 6,
                    "reason": "before_rewind",
                },
            ),
            (
                "fork_resolution",
                {
                    "type": "fork_resolution",
                    "source_epoch": 6,
                    "candidate_digest": DIGEST_A,
                    "incumbent_digest": DIGEST_B,
                    "winner": "candidate",
                    "invalidated_msg_id": OTHER_MSG_ID,
                },
                {
                    "source_epoch": 6,
                    "candidate_digest": DIGEST_A,
                    "incumbent_digest": DIGEST_B,
                    "winner": "candidate",
                    "invalidated_msg_id": OTHER_MSG_ID,
                },
            ),
            (
                "convergence_decision",
                {
                    "type": "convergence_decision",
                    "current_tip_epoch": 6,
                    "candidate_count": 2,
                    "eligible_count": 1,
                    "max_rewind_commits": 5,
                    "selected_branch_id": "branch-a",
                    "selected_fork_epoch": 6,
                    "selected_tip_epoch": 7,
                },
                {
                    "current_tip_epoch": 6,
                    "candidate_count": 2,
                    "eligible_count": 1,
                    "max_rewind_commits": 5,
                    "selected_branch_id": "branch-a",
                    "selected_fork_epoch": 6,
                    "selected_tip_epoch": 7,
                },
            ),
            (
                "peeler_outcome",
                {
                    "type": "peeler_outcome",
                    "msg_id": MSG_ID,
                    "outcome": "decrypt_failed",
                    "fallback_snapshot_used": True,
                    "detail": "no_matching_epoch",
                },
                {
                    "msg_id": MSG_ID,
                    "outcome": "decrypt_failed",
                    "fallback_snapshot_used": True,
                    "detail": "no_matching_epoch",
                },
            ),
            (
                "auto_commit_decision",
                {
                    "type": "auto_commit_decision",
                    "proposal_kind": "commit",
                    "decision": "accept",
                    "reason": "eligible",
                },
                {
                    "proposal_kind": "commit",
                    "decision": "accept",
                    "reason": "eligible",
                },
            ),
            (
                "message_state_changed",
                {
                    "type": "message_state_changed",
                    "msg_id": OTHER_MSG_ID,
                    "new_state": "epoch_invalidated",
                    "reason": "fork_loser",
                },
                {
                    "msg_id": OTHER_MSG_ID,
                    "new_state": "epoch_invalidated",
                    "reason": "fork_loser",
                },
            ),
            (
                "rejection",
                {
                    "type": "rejection",
                    "msg_id": OTHER_MSG_ID,
                    "reason": "bad_epoch",
                },
                {
                    "msg_id": OTHER_MSG_ID,
                    "reason": "bad_epoch",
                },
            ),
        ]
        body = jsonl(
            *[
                audit_event(seq, kind=kind, wall_time_ms=1_700_000_000_000 + seq)
                for seq, (_event_type, kind, _expected) in enumerate(cases)
            ]
        )

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["event_count"], len(cases))
        self.assertEqual(response.json()["validation_status"], AuditFile.STATUS_VALID)

        events_by_type = {event.event_type: event for event in AuditEvent.objects.all()}
        self.assertEqual(
            set(events_by_type),
            {event_type for event_type, _kind, _expected in cases},
        )
        for event_type, _kind, expected_values in cases:
            with self.subTest(event_type=event_type):
                event = events_by_type[event_type]
                self.assertEqual(event.parse_status, AuditEvent.STATUS_VALID)
                self.assertEqual(event.validation_error, "")
                for field, expected_value in expected_values.items():
                    self.assertEqual(getattr(event, field), expected_value)

    def test_malformed_audit_kind_corpus_is_quarantined(self):
        raw_token, _token = UploadToken.issue("ios test client")
        missing_kind = audit_event(0)
        missing_kind.pop("kind")
        missing_type = audit_event(2)
        missing_type["kind"] = {}
        old_format = audit_event(4)
        old_format.pop("context")
        cases = [
            (
                missing_kind,
                "kind must be an object",
            ),
            (
                audit_event(1, kind="not-an-object"),
                "kind must be an object",
            ),
            (
                missing_type,
                "kind.type must be a non-empty string",
            ),
            (
                audit_event(3, kind={"type": ""}),
                "kind.type must be a non-empty string",
            ),
            (
                old_format,
                "new audit rows must include",
            ),
            (
                audit_event(
                    5,
                    kind={
                        "type": "ingest_entry",
                        "envelope_kind": "group_message",
                        "payload_len": 512,
                        "payload_digest": DIGEST_A,
                    },
                ),
                "msg_id is required",
            ),
        ]

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=jsonl(*(event for event, _expected_error in cases)),
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["validation_status"], AuditFile.STATUS_INVALID)
        self.assertEqual(response.json()["event_count"], 0)
        self.assertEqual(response.json()["invalid_event_count"], len(cases))

        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.validation_status, AuditFile.STATUS_INVALID)
        self.assertEqual(audit_file.valid_event_count, 0)
        self.assertEqual(audit_file.invalid_event_count, len(cases))
        self.assertEqual(audit_file.events.count(), len(cases))
        for line_number, (_event, expected_error) in enumerate(cases, start=1):
            with self.subTest(line_number=line_number):
                event = audit_file.events.get(line_number=line_number)
            self.assertEqual(event.parse_status, AuditEvent.STATUS_INVALID)
            self.assertIn(expected_error, event.validation_error)

    def test_unknown_future_kind_is_valid_with_human_action_context(self):
        raw_token, _token = UploadToken.issue("ios test client")
        body = jsonl(audit_event(0, kind={"type": "future_transport_detail", "shape": "new"}))

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 201)
        event = AuditEvent.objects.get()
        self.assertEqual(event.event_type, "future_transport_detail")
        self.assertEqual(event.human_action_action, "update_group_profile")
        self.assertEqual(event.raw_kind["shape"], "new")


class DashboardTests(TestCase):
    def test_upload_log_list_requires_login(self):
        response = self.client.get(reverse("upload-log-list"))

        self.assertEqual(response.status_code, 302)

    def test_upload_log_list_shows_successful_and_failed_uploads(self):
        raw_token, token = UploadToken.issue("ios test client")
        user = User.objects.create_user(
            username="analyst",
            password="correct horse battery staple",
        )

        valid_response = self.client.post(
            reverse("api-audit-log-upload"),
            data=representative_audit_log(),
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
            HTTP_X_GOGGLES_ACCOUNT_LABEL="Alice",
            HTTP_X_GOGGLES_DEVICE_LABEL="MacBook",
            HTTP_X_GOGGLES_PLATFORM="macOS",
            HTTP_X_GOGGLES_APP_VERSION="1.2.3",
            HTTP_USER_AGENT="DarkMatter/1.2.3",
            REMOTE_ADDR="203.0.113.10",
        )
        self.assertEqual(valid_response.status_code, 201)

        invalid_event = audit_event(9, kind={"type": "send_entry", "intent_kind": "profile"})
        invalid_event.pop("context")
        invalid_response = self.client.post(
            reverse("api-audit-log-upload"),
            data=jsonl(invalid_event),
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
            HTTP_X_GOGGLES_PLATFORM="iOS",
            HTTP_X_GOGGLES_APP_VERSION="9.9.9",
            REMOTE_ADDR="198.51.100.22",
        )
        self.assertEqual(invalid_response.status_code, 400)

        token.refresh_from_db()
        self.assertIsNotNone(token.last_used_at)
        valid_file = AuditFile.objects.get(validation_status=AuditFile.STATUS_VALID)
        invalid_file = AuditFile.objects.get(validation_status=AuditFile.STATUS_INVALID)

        self.client.force_login(user)
        response = self.client.get(reverse("upload-log-list"))

        self.assertContains(response, "Upload logs")
        self.assertContains(response, "2")
        self.assertContains(response, "1")
        self.assertContains(response, "valid")
        self.assertContains(response, "invalid")
        self.assertContains(response, "ios test client")
        self.assertContains(response, "Alice")
        self.assertContains(response, "MacBook")
        self.assertContains(response, "macOS")
        self.assertContains(response, "1.2.3")
        self.assertContains(response, "iOS")
        self.assertContains(response, "9.9.9")
        self.assertContains(response, "203.0.113.10")
        self.assertContains(response, "198.51.100.22")
        self.assertContains(response, "new audit rows must include")
        self.assertContains(
            response,
            f'href="{reverse("audit-file-detail", args=[valid_file.id])}"',
        )
        self.assertContains(
            response,
            f'href="{reverse("audit-file-detail", args=[invalid_file.id])}"',
        )

    def test_group_detail_is_login_required_and_shows_audit_workflows(self):
        group = AuditGroup.objects.create(
            name="QA fork group",
            slug=GROUP_REF,
            group_ref=GROUP_REF,
        )
        raw_token, _token = UploadToken.issue("qa clients")
        alice = jsonl(
            audit_event(
                0,
                engine_id=ENGINE_ALICE,
                kind={
                    "type": "send_outcome",
                    "intent_kind": "invite",
                    "result_kind": "group_evolution",
                    "outbound_msg_id": MSG_ID,
                    "outbound_welcome_msg_ids": [OTHER_MSG_ID],
                },
            ),
            audit_event(
                1,
                engine_id=ENGINE_ALICE,
                kind={
                    "type": "fork_resolution",
                    "source_epoch": 6,
                    "candidate_digest": DIGEST_A,
                    "incumbent_digest": DIGEST_B,
                    "winner": "candidate",
                    "invalidated_msg_id": OTHER_MSG_ID,
                },
            ),
            audit_event(
                2,
                engine_id=ENGINE_ALICE,
                kind={
                    "type": "convergence_decision",
                    "current_tip_epoch": 6,
                    "candidate_count": 2,
                    "eligible_count": 1,
                    "max_rewind_commits": 5,
                    "selected_branch_id": "branch-a",
                    "selected_fork_epoch": 6,
                    "selected_tip_epoch": 7,
                },
            ),
        )
        bob = jsonl(
            audit_event(
                0,
                engine_id=ENGINE_BOB,
                kind={
                    "type": "ingest_entry",
                    "msg_id": MSG_ID,
                    "envelope_kind": "group_message",
                    "payload_len": 512,
                    "payload_digest": DIGEST_A,
                },
                wall_time_ms=1_700_000_000_050,
            ),
            audit_event(
                1,
                engine_id=ENGINE_BOB,
                kind={
                    "type": "peeler_outcome",
                    "msg_id": MSG_ID,
                    "outcome": "decrypt_failed",
                    "fallback_snapshot_used": False,
                    "detail": "no_matching_epoch",
                },
                wall_time_ms=1_700_000_000_060,
            ),
            audit_event(
                2,
                engine_id=ENGINE_BOB,
                kind={
                    "type": "message_state_changed",
                    "msg_id": OTHER_MSG_ID,
                    "new_state": "epoch_invalidated",
                    "reason": "fork_loser",
                },
                wall_time_ms=1_700_000_000_070,
            ),
        )

        for body in (alice, bob):
            response = self.client.post(
                reverse("api-group-audit-log-upload", kwargs={"group_slug": group.slug}),
                data=body,
                content_type="application/x-ndjson",
                HTTP_AUTHORIZATION=f"Bearer {raw_token}",
            )
            self.assertEqual(response.status_code, 201)

        response = self.client.get(reverse("group-detail", kwargs={"slug": group.slug}))
        self.assertEqual(response.status_code, 302)

        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")
        response = self.client.get(reverse("group-detail", kwargs={"slug": group.slug}))

        self.assertContains(response, "QA fork group")
        self.assertContains(response, 'id="timeline-data"')
        self.assertContains(response, ENGINE_ALICE)
        self.assertContains(response, ENGINE_BOB)
        self.assertContains(response, "Actions")
        self.assertContains(response, "update_group_profile")
        self.assertContains(response, "Message trace")
        self.assertContains(response, MSG_ID)
        self.assertContains(response, "Fork &amp; convergence")
        self.assertContains(response, "candidate")
        self.assertContains(response, "Peeler &amp; rejections")
        self.assertContains(response, "decrypt_failed")
        self.assertContains(response, "Missing observations")
        self.assertContains(response, OTHER_MSG_ID)
        payload = response.context["timeline_payload"]
        self.assertEqual(
            sorted(payload),
            ["engines", "epochs", "excluded", "group", "integrity", "items", "time", "version"],
        )


class HealthCheckTests(TestCase):
    def test_healthz_returns_minimal_json_without_login(self):
        response = self.client.get(reverse("healthz"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertEqual(response.json(), {"status": "ok"})


class SeedDevCommandTests(TestCase):
    def test_seed_dev_creates_admin_user_and_sample_audit_log_idempotently(self):
        output = StringIO()

        call_command("seed_dev", stdout=output)
        call_command("seed_dev", stdout=StringIO())

        admin = User.objects.get(username="admin")
        self.assertTrue(admin.check_password("pass123"))
        self.assertTrue(admin.is_staff)
        self.assertTrue(admin.is_superuser)

        group = AuditGroup.objects.get(group_ref=GROUP_REF)
        self.assertEqual(group.slug, GROUP_REF)
        self.assertEqual(
            AuditFile.objects.filter(events__group=group).distinct().count(),
            2,
        )
        self.assertEqual(AuditEvent.objects.filter(group=group).count(), 6)
        self.assertIn("admin / pass123", output.getvalue())

    def test_seed_dev_seeds_new_format_action_logs(self):
        call_command("seed_dev", stdout=StringIO())

        group = AuditGroup.objects.get(group_ref=GROUP_REF)
        files = list(audit_files_for_group(group))
        self.assertEqual(len(files), 2)
        self.assertTrue(all(f.validation_status == AuditFile.STATUS_VALID for f in files))

        events = list(valid_events_for_group(group))
        self.assertEqual(len(events), 6)
        self.assertEqual(
            sorted({event.human_action_action for event in events}),
            ["promote_admin", "update_group_profile"],
        )

        payload = timeline_payload_for_group(group, events, files)
        self.assertEqual(
            [engine["label"] for engine in payload["engines"]],
            [
                "Alice / iPhone 15 / ios",
                "Bob / Pixel 9 / android",
            ],
        )
        self.assertTrue(any(item["type"] == "human_action" for item in payload["items"]))
        self.assertTrue(any(item["type"] == "publish_outcome" for item in payload["items"]))
        self.assertEqual(payload["excluded"]["count"], 0)


# ---------------------------------------------------------------------------
# Timeline payload
# ---------------------------------------------------------------------------

T0 = 1_700_000_000_000
ENGINE_CAROL = "fedcba9876543210fedcba9876543210"


def ingest_body(body, **source):
    return ingest_audit_log_bytes(
        dump_bytes=body.encode("utf-8"),
        content_type="application/x-ndjson",
        **source,
    )


def payload_for(group):
    return timeline_payload_for_group(
        group,
        list(valid_events_for_group(group)),
        list(audit_files_for_group(group)),
    )


def epoch_confirmed(seq, engine_id, from_epoch, to_epoch, wall_time_ms):
    return audit_event(
        seq,
        engine_id=engine_id,
        kind={
            "type": "epoch_confirmed",
            "from_epoch": from_epoch,
            "to_epoch": to_epoch,
            "pending_kind": "commit",
        },
        wall_time_ms=wall_time_ms,
    )


class TimelinePayloadTests(TestCase):
    def test_first_timed_confirmer_gets_commit_role(self):
        ingest_body(
            jsonl(epoch_confirmed(0, ENGINE_ALICE, 6, 7, T0)),
            source_account_label="Alice",
        )
        ingest_body(jsonl(epoch_confirmed(0, ENGINE_BOB, 6, 7, T0 + 5000)))
        group = AuditGroup.objects.get(slug=GROUP_REF)

        payload = payload_for(group)

        self.assertEqual(
            [engine["engine_id"] for engine in payload["engines"]],
            [ENGINE_ALICE, ENGINE_BOB],
        )
        self.assertEqual(payload["engines"][0]["label"], "Alice")
        ep = payload["epochs"][0]
        self.assertEqual(ep["epoch"], 7)
        self.assertTrue(ep["confirmed"])
        self.assertEqual(ep["first_confirmed_engine"], 0)
        self.assertEqual(ep["first_confirmed_ms"], T0)
        self.assertEqual(ep["spread_ms"], 5000)
        self.assertEqual(ep["unconfirmed_engines"], [])
        roles = {item["engine"]: item.get("role") for item in payload["items"]}
        self.assertEqual(roles, {0: "commit", 1: "applied"})
        self.assertEqual(
            [conf["engine"] for conf in ep["confirmations"]],
            [0, 1],
        )

    def test_duplicate_confirmation_by_one_engine_sets_repeat_flag(self):
        ingest_body(jsonl(epoch_confirmed(0, ENGINE_ALICE, 6, 7, T0)))
        ingest_body(
            jsonl(
                epoch_confirmed(0, ENGINE_BOB, 6, 7, T0 + 5000),
                epoch_confirmed(1, ENGINE_BOB, 6, 7, T0 + 9000),
            )
        )
        group = AuditGroup.objects.get(slug=GROUP_REF)

        ep = payload_for(group)["epochs"][0]

        self.assertEqual(len(ep["confirmations"]), 3)
        self.assertEqual([conf["repeat"] for conf in ep["confirmations"]], [False, False, True])
        self.assertEqual(ep["first_confirmed_engine"], 0)
        self.assertEqual(ep["spread_ms"], 9000)

    def test_unconfirmed_engines_listed_per_epoch(self):
        ingest_body(jsonl(epoch_confirmed(0, ENGINE_ALICE, 6, 7, T0)))
        ingest_body(jsonl(audit_event(0, engine_id=ENGINE_CAROL, wall_time_ms=T0 + 100)))
        group = AuditGroup.objects.get(slug=GROUP_REF)

        payload = payload_for(group)

        self.assertEqual(payload["epochs"][0]["unconfirmed_engines"], [1])

    def test_rollback_creates_stub_epoch_with_roles(self):
        ingest_body(
            jsonl(
                epoch_confirmed(0, ENGINE_BOB, 7, 8, T0),
                audit_event(
                    1,
                    engine_id=ENGINE_BOB,
                    kind={
                        "type": "epoch_rolled_back",
                        "pending_epoch": 9,
                        "restored_epoch": 8,
                        "pending_kind": "commit",
                    },
                    wall_time_ms=T0 + 1000,
                ),
            )
        )
        group = AuditGroup.objects.get(slug=GROUP_REF)

        payload = payload_for(group)

        self.assertEqual([ep["epoch"] for ep in payload["epochs"]], [8, 9])
        eight, nine = payload["epochs"]
        self.assertTrue(eight["confirmed"])
        self.assertEqual(eight["rollbacks"][0]["role"], "restored_to")
        self.assertEqual(eight["fork_status"], "none")
        self.assertFalse(nine["confirmed"])
        self.assertIsNone(nine["commit_item_id"])
        self.assertEqual(nine["rollbacks"][0]["role"], "abandoned")
        self.assertEqual(nine["fork_status"], "suspected")
        rollback_item = next(
            item for item in payload["items"] if item["type"] == "epoch_rolled_back"
        )
        self.assertEqual(rollback_item["role"], "rollback")

    def test_fork_resolution_details_on_source_epoch(self):
        ingest_body(
            jsonl(
                audit_event(
                    0,
                    kind={
                        "type": "fork_resolution",
                        "source_epoch": 6,
                        "candidate_digest": DIGEST_A,
                        "incumbent_digest": DIGEST_B,
                        "winner": "candidate",
                        "invalidated_msg_id": OTHER_MSG_ID,
                    },
                    wall_time_ms=T0,
                )
            )
        )
        group = AuditGroup.objects.get(slug=GROUP_REF)

        payload = payload_for(group)

        six = payload["epochs"][0]
        self.assertEqual(six["epoch"], 6)
        self.assertFalse(six["confirmed"])
        self.assertEqual(six["fork_status"], "resolved")
        fork = six["forks"][0]
        self.assertEqual(fork["winner"], "candidate")
        self.assertEqual(fork["candidate_digest"], DIGEST_A)
        self.assertEqual(fork["incumbent_digest"], DIGEST_B)
        self.assertEqual(fork["invalidated_msg_id"], OTHER_MSG_ID)
        self.assertTrue(payload["integrity"]["has_fork_activity"])

    def test_message_event_count_uses_event_epoch(self):
        ingest_body(
            jsonl(
                epoch_confirmed(0, ENGINE_ALICE, 6, 7, T0),
                audit_event(1, wall_time_ms=T0 + 10),
                audit_event(
                    2,
                    kind={
                        "type": "ingest_outcome",
                        "msg_id": MSG_ID,
                        "outcome_kind": "processed",
                        "epoch": 7,
                    },
                    wall_time_ms=T0 + 20,
                ),
            )
        )
        group = AuditGroup.objects.get(slug=GROUP_REF)

        ep = payload_for(group)["epochs"][0]

        self.assertEqual(ep["message_event_count"], 1)

    def test_null_wall_time_event_excluded_with_count(self):
        ingest_body(jsonl(audit_event(0, wall_time_ms=T0)))
        group = AuditGroup.objects.get(slug=GROUP_REF)
        audit_file = AuditFile.objects.get()
        orphan = AuditEvent.objects.create(
            audit_file=audit_file,
            group=group,
            line_number=999,
            line_hash="ff" * 32,
            raw_line="{}",
            parse_status=AuditEvent.STATUS_VALID,
            engine_id=ENGINE_ALICE,
            event_type="send_entry",
            intent_kind="message",
        )

        payload = payload_for(group)

        self.assertNotIn(orphan.id, [item["id"] for item in payload["items"]])
        self.assertEqual(payload["excluded"]["count"], 1)
        self.assertEqual(payload["excluded"]["by_reason"]["no_wall_time"], 1)
        self.assertEqual(payload["excluded"]["event_ids"], [orphan.id])

    def test_engines_ordered_by_first_event(self):
        ingest_body(jsonl(audit_event(0, wall_time_ms=T0 + 1000)), source_account_label="Alice")
        ingest_body(
            jsonl(audit_event(0, engine_id=ENGINE_BOB, account_ref=ACCOUNT_BOB, wall_time_ms=T0)),
            source_account_label="Bob",
        )
        group = AuditGroup.objects.get(slug=GROUP_REF)

        engines = payload_for(group)["engines"]

        self.assertEqual([engine["label"] for engine in engines], ["Bob", "Alice"])
        self.assertEqual([engine["idx"] for engine in engines], [0, 1])
        self.assertEqual(engines[0]["initials"], "B")
        self.assertEqual(engines[0]["short"], ENGINE_BOB[:8])
        self.assertIn(engines[0]["color_index"], range(1, 9))

    def test_empty_group_payload_shape(self):
        group = AuditGroup.objects.create(name="Empty", slug="empty", group_ref="ee" * 32)

        payload = payload_for(group)

        self.assertEqual(payload["engines"], [])
        self.assertEqual(payload["epochs"], [])
        self.assertEqual(payload["items"], [])
        self.assertIsNone(payload["time"]["start_ms"])
        self.assertEqual(payload["integrity"]["divergent_message_count"], 0)
        self.assertEqual(payload["excluded"]["count"], 0)

    def test_payload_is_json_serializable(self):
        ingest_body(representative_audit_log())
        group = AuditGroup.objects.get(slug=GROUP_REF)

        payload = payload_for(group)

        self.assertEqual(json.loads(json.dumps(payload)), payload)

    def test_related_key_falls_back_to_digest(self):
        ingest_body(jsonl(audit_event(0, wall_time_ms=T0)))
        group = AuditGroup.objects.get(slug=GROUP_REF)

        item = payload_for(group)["items"][0]

        self.assertEqual(item["related_key"], MSG_ID)
        self.assertEqual(item["digest"], DIGEST_A)


class GroupListAnnotationTests(TestCase):
    def seed_fork_group(self):
        ingest_body(
            jsonl(
                audit_event(0, wall_time_ms=T0),
                epoch_confirmed(1, ENGINE_ALICE, 4, 5, T0 + 100),
                audit_event(
                    2,
                    kind={
                        "type": "fork_resolution",
                        "source_epoch": 5,
                        "candidate_digest": DIGEST_A,
                        "winner": "candidate",
                    },
                    wall_time_ms=T0 + 200,
                ),
            )
        )
        ingest_body(
            jsonl(
                audit_event(
                    0,
                    engine_id=ENGINE_BOB,
                    account_ref=ACCOUNT_BOB,
                    kind={"type": "send_entry", "intent_kind": "message"},
                    wall_time_ms=T0 + 300,
                )
            )
        )

    def seed_clean_group(self):
        ingest_body(jsonl(epoch_confirmed(0, ENGINE_CAROL, 2, 3, T0 + 400)))

    def test_rows_annotate_engines_epochs_files_and_divergence(self):
        self.seed_fork_group()
        # the clean group lives under a different group_ref
        ingest_body(
            jsonl(
                audit_event(
                    0,
                    engine_id=ENGINE_CAROL,
                    group_ref=OTHER_GROUP_REF,
                    kind={
                        "type": "epoch_confirmed",
                        "from_epoch": 2,
                        "to_epoch": 3,
                        "pending_kind": "commit",
                    },
                    wall_time_ms=T0 + 400,
                )
            )
        )

        rows = {group.slug: group for group in group_list_rows()}

        fork_group = rows[GROUP_REF]
        self.assertEqual(fork_group.engine_count, 2)
        self.assertEqual(fork_group.epoch_min, 4)
        self.assertEqual(fork_group.epoch_max, 5)
        self.assertEqual(fork_group.event_count, 4)
        self.assertEqual(fork_group.audit_file_count, 2)
        self.assertEqual(fork_group.last_activity_ms, T0 + 300)
        self.assertTrue(fork_group.has_fork_activity)
        self.assertEqual(fork_group.divergent_count, 1)  # MSG_ID unseen by bob
        self.assertIsNotNone(fork_group.last_activity)

        clean_group = rows[OTHER_GROUP_REF]
        self.assertEqual(clean_group.engine_count, 1)
        self.assertEqual(clean_group.epoch_min, 2)
        self.assertEqual(clean_group.epoch_max, 3)
        self.assertFalse(clean_group.has_fork_activity)
        self.assertEqual(clean_group.divergent_count, 0)

    def test_rows_expose_group_ref_display_and_search_values(self):
        self.seed_clean_group()
        long_ref = "ab" * 60
        AuditGroup.objects.create(name="Group legacy", slug="legacy-ref", group_ref=long_ref)

        rows = {group.slug: group for group in group_list_rows()}

        self.assertEqual(rows[GROUP_REF].display_ref, GROUP_REF)
        self.assertEqual(rows[GROUP_REF].search_ref, GROUP_REF)
        self.assertEqual(rows["legacy-ref"].display_ref, display_group_ref(long_ref))
        self.assertEqual(rows["legacy-ref"].search_ref, long_ref)
        self.assertEqual(
            rows["legacy-ref"].display_ref,
            f"{long_ref[:32]}...{long_ref[-32:]}",
        )

    def test_group_list_view_query_count_is_bounded(self):
        self.seed_fork_group()
        self.seed_clean_group()
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(reverse("group-list"))

        self.assertEqual(response.status_code, 200)
        self.assertLessEqual(len(ctx.captured_queries), 8)

    def test_group_list_view_renders_search_and_group_ref_without_generated_label(self):
        self.seed_clean_group()
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

        response = self.client.get(reverse("group-list"))

        self.assertContains(response, "data-group-search")
        self.assertContains(response, "data-group-count-title")
        self.assertContains(response, "table-search")
        self.assertContains(response, "All groups")
        self.assertNotContains(response, 'for="group-search"')
        self.assertContains(response, f'data-group-ref="{GROUP_REF}"')
        self.assertContains(response, f">{GROUP_REF}</a>")
        self.assertNotContains(response, f"Group {GROUP_REF[:12]}")


class GroupDetailTimelineViewTests(TestCase):
    def test_group_detail_embeds_timeline_json_script(self):
        ingest_body(representative_audit_log())
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

        response = self.client.get(reverse("group-detail", kwargs={"slug": GROUP_REF}))

        self.assertContains(response, 'id="timeline-data"')
        payload = response.context["timeline_payload"]
        self.assertEqual(payload["version"], 1)
        self.assertEqual(len(payload["engines"]), 1)
        self.assertEqual(json.loads(json.dumps(payload)), payload)

    def test_group_detail_fetches_events_with_bounded_queries(self):
        ingest_body(representative_audit_log(engine_id=ENGINE_ALICE))
        ingest_body(representative_audit_log(engine_id=ENGINE_BOB))
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(reverse("group-detail", kwargs={"slug": GROUP_REF}))

        self.assertEqual(response.status_code, 200)
        self.assertLessEqual(len(ctx.captured_queries), 12)


class ProfileTests(TestCase):
    OLD_PASSWORD = "correct horse battery staple"
    NEW_PASSWORD = "n3w-passphrase-galaxy"

    def make_user(self):
        return User.objects.create_user(username="analyst", password=self.OLD_PASSWORD)

    def test_profile_requires_login(self):
        response = self.client.get(reverse("profile"))

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response["Location"])

    def test_profile_shows_username_and_password_form(self):
        self.make_user()
        self.client.login(username="analyst", password=self.OLD_PASSWORD)

        response = self.client.get(reverse("profile"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "analyst")
        self.assertContains(response, 'name="old_password"')
        self.assertContains(response, 'name="new_password1"')
        self.assertContains(response, 'name="new_password2"')
        # Username must not be editable from this page.
        self.assertNotContains(response, 'name="username"')

    def test_user_can_change_their_own_password(self):
        user = self.make_user()
        self.client.login(username="analyst", password=self.OLD_PASSWORD)

        response = self.client.post(
            reverse("profile"),
            data={
                "old_password": self.OLD_PASSWORD,
                "new_password1": self.NEW_PASSWORD,
                "new_password2": self.NEW_PASSWORD,
            },
            follow=True,
        )

        self.assertRedirects(response, reverse("profile"))
        user.refresh_from_db()
        self.assertTrue(user.check_password(self.NEW_PASSWORD))
        # The change keeps the current session authenticated.
        self.assertEqual(int(self.client.session["_auth_user_id"]), user.pk)
        # The redirect target surfaces a success banner.
        self.assertContains(response, "message--success")
        self.assertContains(response, "Your password has been updated.")

    def test_wrong_current_password_is_rejected(self):
        user = self.make_user()
        self.client.login(username="analyst", password=self.OLD_PASSWORD)

        response = self.client.post(
            reverse("profile"),
            data={
                "old_password": "not the password",
                "new_password1": self.NEW_PASSWORD,
                "new_password2": self.NEW_PASSWORD,
            },
        )

        self.assertEqual(response.status_code, 200)
        user.refresh_from_db()
        self.assertTrue(user.check_password(self.OLD_PASSWORD))

    def test_profile_does_not_change_username(self):
        user = self.make_user()
        self.client.login(username="analyst", password=self.OLD_PASSWORD)

        self.client.post(
            reverse("profile"),
            data={
                "username": "renamed",
                "old_password": self.OLD_PASSWORD,
                "new_password1": self.NEW_PASSWORD,
                "new_password2": self.NEW_PASSWORD,
            },
        )

        user.refresh_from_db()
        self.assertEqual(user.username, "analyst")


class AuditFileAdminTests(TestCase):
    """Regression coverage for goggles#34.

    Opening an ``AuditFile`` in the admin must stay usable no matter how many
    events the file holds. Events are reached through the paginated
    ``AuditEventAdmin`` changelist, never rendered as an unbounded inline
    formset.
    """

    def setUp(self):
        self.admin_user = User.objects.create_superuser(
            username="root", email="root@example.com", password="pass123"
        )
        self.client.force_login(self.admin_user)

    @staticmethod
    def make_audit_file(event_count, **kwargs):
        audit_file = AuditFile.objects.create(
            file_sha256=f"{event_count:064x}",
            byte_size=event_count * 100,
            raw_text="\n".join(f"line {i}" for i in range(event_count)),
            valid_event_count=event_count,
            **kwargs,
        )
        AuditEvent.objects.bulk_create(
            AuditEvent(
                audit_file=audit_file,
                line_number=i + 1,
                line_hash=f"{i:064x}",
                raw_line=f"line {i}",
                event_type="ingest_entry",
                engine_id=ENGINE_ALICE,
                account_ref=ACCOUNT_ALICE,
            )
            for i in range(event_count)
        )
        return audit_file

    def change_url(self, audit_file):
        return reverse("admin:forensics_auditfile_change", args=[audit_file.pk])

    def test_audit_file_admin_has_no_event_inline(self):
        from .admin import AuditFileAdmin

        inline_models = [inline.model for inline in AuditFileAdmin.inlines]
        self.assertNotIn(AuditEvent, inline_models)
        self.assertEqual(list(AuditFileAdmin.inlines), [])

    def test_admin_module_defines_no_event_inline(self):
        from forensics import admin as forensics_admin

        self.assertFalse(
            hasattr(forensics_admin, "AuditEventInline"),
            "The unbounded AuditEventInline must not exist (goggles#34).",
        )

    def test_change_page_query_count_is_bounded_regardless_of_events(self):
        small = self.make_audit_file(2)
        large = self.make_audit_file(200, source_name="big")

        with CaptureQueriesContext(connection) as small_queries:
            response_small = self.client.get(self.change_url(small))
        self.assertEqual(response_small.status_code, 200)

        with CaptureQueriesContext(connection) as large_queries:
            response_large = self.client.get(self.change_url(large))
        self.assertEqual(response_large.status_code, 200)

        # The page must not issue (or render) one query/row per event. The
        # events link uses a static label, so there is not even a COUNT query
        # that scales with events: query volume is identical for a 2-event and
        # a 200-event file.
        self.assertEqual(len(small_queries), len(large_queries))

    def test_change_page_does_not_render_a_row_per_event(self):
        audit_file = self.make_audit_file(50)
        response = self.client.get(self.change_url(audit_file))
        content = response.content.decode()
        # An inline formset would emit one management-form row per event; the
        # link-out approach never renders editable event rows. Guard against
        # the per-event line numbers leaking into editable inline inputs.
        self.assertNotIn('name="events-50-id"', content)
        self.assertNotIn('id="id_events-TOTAL_FORMS"', content)

    def test_change_page_links_to_filtered_event_changelist(self):
        audit_file = self.make_audit_file(3)
        response = self.client.get(self.change_url(audit_file))
        content = response.content.decode()
        changelist = reverse("admin:forensics_auditevent_changelist")
        expected = f"{changelist}?audit_file__id__exact={audit_file.pk}"
        self.assertIn(expected, content)
        # The label is intentionally static ("View events") so no per-event
        # COUNT query runs on every change-page render (goggles#34).
        self.assertIn("View events", content)

    def test_event_link_label_does_not_run_a_count_query(self):
        """The events link must not COUNT events on every render.

        A per-event ``count()`` scales with the number of events, which is the
        same unbounded cost we removed by dropping the inline. Asserting on the
        rendered label keeps the static-link contract enforced.
        """
        audit_file = self.make_audit_file(7)
        response = self.client.get(self.change_url(audit_file))
        content = response.content.decode()
        self.assertIn("View events", content)
        # No dynamic count is embedded in the label.
        self.assertNotIn("View 7 event", content)

    def test_filtered_event_changelist_is_reachable_and_scoped(self):
        target = self.make_audit_file(3, source_name="target")
        other = self.make_audit_file(5, source_name="other")
        changelist = reverse("admin:forensics_auditevent_changelist")
        response = self.client.get(changelist, {"audit_file__id__exact": target.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["cl"].result_count, 3)
        self.assertNotEqual(other.pk, target.pk)

    def test_schema_versions_not_in_audit_file_list_filter(self):
        from .admin import AuditFileAdmin

        self.assertNotIn("schema_versions", AuditFileAdmin.list_filter)
        self.assertIn("validation_status", AuditFileAdmin.list_filter)

    def test_audit_event_admin_filterable_by_audit_file(self):
        from .admin import AuditEventAdmin

        self.assertIn("audit_file", AuditEventAdmin.list_filter)

    # --- raw_text bounding (goggles#34, adversarial review follow-up) -------
    #
    # Removing the event inline alone did not make the change page bounded:
    # ``AuditFile.raw_text`` is a TextField holding the entire uploaded JSONL,
    # and the default model form rendered it into one editable textarea, so a
    # 50 MB upload still produced a huge response. The change form must exclude
    # the editable raw_text field and only show a bounded preview.

    @staticmethod
    def make_file_with_raw_text(raw_text, **kwargs):
        import hashlib

        digest = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        return AuditFile.objects.create(
            file_sha256=digest,
            byte_size=len(raw_text.encode("utf-8")),
            raw_text=raw_text,
            **kwargs,
        )

    def test_change_form_excludes_editable_raw_text(self):
        from .admin import AuditFileAdmin

        self.assertIn("raw_text", AuditFileAdmin.exclude)
        audit_file = self.make_file_with_raw_text("line one\nline two\n")
        response = self.client.get(self.change_url(audit_file))
        content = response.content.decode()
        # No editable raw_text textarea/input may appear on the change page.
        self.assertNotIn('name="raw_text"', content)
        self.assertNotIn('id="id_raw_text"', content)

    def test_change_page_renders_bounded_raw_text_preview(self):
        from .admin import RAW_TEXT_PREVIEW_CHARS

        marker = "ZRAWMARKER"
        # A line every ~10 chars, far past the preview cap.
        big_raw = "\n".join(f"{i}-{marker}" for i in range(50000))
        self.assertGreater(len(big_raw), RAW_TEXT_PREVIEW_CHARS)
        audit_file = self.make_file_with_raw_text(big_raw)
        response = self.client.get(self.change_url(audit_file))
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        # The preview label is present...
        self.assertIn("Raw text (preview)", content)
        # ...but only the first RAW_TEXT_PREVIEW_CHARS of raw text are emitted,
        # so the last line of a huge file never reaches the page.
        self.assertNotIn(f"49999-{marker}", content)
        # The first line does appear in the preview.
        self.assertIn(f"0-{marker}", content)

    def test_change_page_html_is_bounded_regardless_of_file_size(self):
        small = self.make_file_with_raw_text("only one line\n")
        huge_raw = "x" * 5_000_000  # ~5 MB of raw text
        huge = self.make_file_with_raw_text(huge_raw)

        small_len = len(self.client.get(self.change_url(small)).content)
        huge_len = len(self.client.get(self.change_url(huge)).content)

        # The huge file must not balloon the change page. Allow generous slack
        # for the bounded preview, but reject anything approaching the raw size.
        self.assertLess(huge_len - small_len, 50_000)
        self.assertLess(huge_len, 200_000)
