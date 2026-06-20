import contextlib
import hashlib
import json
import os
from datetime import timedelta
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth.models import User
from django.core.exceptions import ImproperlyConfigured, RequestDataTooBig
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.db import connection
from django.test import SimpleTestCase, TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone

from config import settings as settings_module

from . import analysis as analysis_module
from . import ingest as ingest_module
from .analysis import (
    audit_files_for_group,
    display_group_ref,
    group_list_rows,
    human_action_groups_for_group,
    timeline_payload_for_group,
    valid_events_for_group,
)
from .ingest import (
    MSG_ID_MAX_LENGTH,
    group_ref_max_length,
    ingest_audit_log_bytes,
)
from .models import AuditEvent, AuditFile, AuditGroup, UploadToken
from .views import audit_bytes_from_request

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


class UploadTokenHashKeyTests(TestCase):
    """Token hashing is keyed on GOGGLES_TOKEN_HASH_KEY, not SECRET_KEY.

    Rotating Django's SECRET_KEY is a recommended security action and must not
    silently invalidate every issued upload token (regression for #22).
    """

    def test_token_survives_secret_key_rotation_with_dedicated_hash_key(self):
        with override_settings(
            SECRET_KEY="signing-key-v1",
            GOGGLES_TOKEN_HASH_KEY="dedicated-token-hash-key",
        ):
            raw_token, token = UploadToken.issue("ios qa device")

        # Rotate ONLY the Django signing key; the dedicated hash key is stable.
        with override_settings(
            SECRET_KEY="signing-key-v2-rotated",
            GOGGLES_TOKEN_HASH_KEY="dedicated-token-hash-key",
        ):
            authenticated = UploadToken.authenticate(raw_token)

        self.assertIsNotNone(authenticated)
        self.assertEqual(authenticated.pk, token.pk)

    def test_rotating_token_hash_key_invalidates_tokens(self):
        with override_settings(
            SECRET_KEY="signing-key-v1",
            GOGGLES_TOKEN_HASH_KEY="dedicated-token-hash-key-v1",
        ):
            raw_token, _token = UploadToken.issue("ios qa device")

        # Rotating the dedicated key DOES invalidate tokens, as documented.
        with override_settings(
            SECRET_KEY="signing-key-v1",
            GOGGLES_TOKEN_HASH_KEY="dedicated-token-hash-key-v2",
        ):
            self.assertIsNone(UploadToken.authenticate(raw_token))

    def test_hash_is_keyed_on_token_hash_key_not_secret_key(self):
        import hashlib
        import hmac

        secret = "entropy-rich-secret"
        with override_settings(
            SECRET_KEY="some-signing-key",
            GOGGLES_TOKEN_HASH_KEY="distinct-token-hash-key",
        ):
            produced = UploadToken.hash_secret(secret)

        expected = hmac.new(
            b"distinct-token-hash-key",
            secret.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(produced, expected)

        secret_key_hash = hmac.new(
            b"some-signing-key",
            secret.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        self.assertNotEqual(produced, secret_key_hash)

    def test_unset_hash_key_falls_back_to_secret_key(self):
        # When GOGGLES_TOKEN_HASH_KEY is unset, settings.py resolves it to
        # SECRET_KEY (the historical/backward-compatible fallback). Tokens
        # hashed under that fallback must authenticate, and the hash must equal
        # an explicit HMAC keyed on SECRET_KEY.
        import hashlib
        import hmac

        # settings.GOGGLES_TOKEN_HASH_KEY == SECRET_KEY reproduces the
        # "env var unset" state (config/settings.py: `os.environ.get(...) or
        # SECRET_KEY`).
        with override_settings(
            SECRET_KEY="legacy-signing-key",
            GOGGLES_TOKEN_HASH_KEY="legacy-signing-key",
        ):
            raw_token, token = UploadToken.issue("legacy device")

            produced = UploadToken.hash_secret("entropy-rich-secret")
            expected = hmac.new(
                b"legacy-signing-key",
                b"entropy-rich-secret",
                hashlib.sha256,
            ).hexdigest()
            self.assertEqual(produced, expected)

            authenticated = UploadToken.authenticate(raw_token)
            self.assertIsNotNone(authenticated)
            self.assertEqual(authenticated.pk, token.pk)

    def test_legacy_token_survives_pinning_hash_key_to_secret_key(self):
        # Documented zero-downtime migration: a token issued under the
        # SECRET_KEY fallback keeps working when an operator pins
        # GOGGLES_TOKEN_HASH_KEY to the current SECRET_KEY value before
        # decoupling. A jump straight to a *fresh* key, by contrast, breaks it.
        with override_settings(
            SECRET_KEY="current-signing-key",
            GOGGLES_TOKEN_HASH_KEY="current-signing-key",  # fallback state
        ):
            raw_token, token = UploadToken.issue("legacy device")

        # Operator pins the dedicated key to the current SECRET_KEY: safe.
        with override_settings(
            SECRET_KEY="current-signing-key",
            GOGGLES_TOKEN_HASH_KEY="current-signing-key",
        ):
            authenticated = UploadToken.authenticate(raw_token)
        self.assertIsNotNone(authenticated)
        self.assertEqual(authenticated.pk, token.pk)

        # Jumping straight to a fresh dedicated key invalidates the legacy
        # token (the all-token outage the migration runbook warns about).
        with override_settings(
            SECRET_KEY="current-signing-key",
            GOGGLES_TOKEN_HASH_KEY="brand-new-dedicated-key",
        ):
            self.assertIsNone(UploadToken.authenticate(raw_token))


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

    def test_unicode_line_separator_inside_json_string_does_not_split_jsonl_record(self):
        separators = (
            ("NEL (U+0085)", "\u0085"),
            ("LINE SEPARATOR (U+2028)", "\u2028"),
            ("PARAGRAPH SEPARATOR (U+2029)", "\u2029"),
        )

        for separator_index, (separator_name, separator) in enumerate(separators):
            with self.subTest(separator=separator_name):
                raw_token, _token = UploadToken.issue(f"ios test client {separator_name}")
                first_event = audit_event(separator_index * 2)
                first_event["context"]["operation_id"] = f"before{separator}after"
                first_line = json.dumps(
                    first_event,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                second_line = json.dumps(
                    audit_event(separator_index * 2 + 1),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                body = f"{first_line}\n{second_line}\n"

                self.assertNotIn("\n", first_line)
                self.assertIn(separator, first_line)

                response = self.client.post(
                    reverse("api-audit-log-upload"),
                    data=body,
                    content_type="application/x-ndjson",
                    HTTP_AUTHORIZATION=f"Bearer {raw_token}",
                )

                self.assertEqual(response.status_code, 201)
                self.assertEqual(response.json()["validation_status"], AuditFile.STATUS_VALID)
                self.assertEqual(response.json()["event_count"], 2)

                audit_file = AuditFile.objects.get(raw_text=body)
                self.assertEqual(audit_file.validation_status, AuditFile.STATUS_VALID)
                events = list(audit_file.events.order_by("line_number"))
                self.assertEqual([event.line_number for event in events], [1, 2])
                self.assertEqual([event.parse_status for event in events], ["valid", "valid"])
                self.assertEqual(events[0].raw_line, first_line)
                expected_hash = hashlib.sha256(first_line.encode("utf-8")).hexdigest()
                self.assertEqual(events[0].line_hash, expected_hash)
                self.assertEqual(events[0].context_operation_id, f"before{separator}after")
                self.assertEqual(events[1].raw_line, second_line)

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

    @override_settings(GOGGLES_MAX_DUMP_BYTES=10)
    def test_multipart_upload_size_limit_rejects_before_reading_file(self):
        class OversizedUpload(SimpleUploadedFile):
            def read(self, *args, **kwargs):
                raise AssertionError("oversized upload should be rejected before read()")

            def chunks(self, *args, **kwargs):
                raise AssertionError("oversized upload should be rejected before chunks()")

        upload_file = OversizedUpload(
            "audit-too-large.jsonl",
            b"x" * 11,
            content_type="application/x-ndjson",
        )
        request = SimpleNamespace(
            FILES={"audit_log": upload_file},
            body=b"",
            content_type="multipart/form-data",
        )

        with self.assertRaises(RequestDataTooBig):
            audit_bytes_from_request(request)

    @override_settings(
        GOGGLES_MAX_DUMP_BYTES=10,
        DATA_UPLOAD_MAX_MEMORY_SIZE=1024,
        FILE_UPLOAD_MAX_MEMORY_SIZE=1024,
    )
    def test_api_rejects_oversized_multipart_upload_without_saving(self):
        raw_token, _token = UploadToken.issue("ios test client")
        upload_file = SimpleUploadedFile(
            "audit-too-large.jsonl",
            b"x" * 11,
            content_type="application/x-ndjson",
        )

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data={"audit_log": upload_file},
            HTTP_AUTHORIZATION="Bearer " + raw_token,
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

    def test_invalid_utf8_upload_file_sha256_race_returns_existing_audit_file(self):
        # save_invalid_upload() does the same check-then-create on file_sha256
        # as the valid ingestion path. If a concurrent request inserts the same
        # non-UTF-8 payload after the existence check but before create(), the
        # losing request must resolve to the winning AuditFile instead of
        # propagating IntegrityError and dropping the raw evidence. Regression
        # for marmot-protocol/goggles#35.
        dump_bytes = b"\xff\xfeinvalid marmot audit bytes"
        raw_text = dump_bytes.decode("utf-8", errors="replace")
        file_sha256 = hashlib.sha256(dump_bytes).hexdigest()
        original_group_for_slug = ingest_module.group_for_slug
        race_winner = {}

        def insert_race_winner(slug, name=""):
            group = original_group_for_slug(slug, name)
            if "audit_file" not in race_winner:
                race_winner["audit_file"] = AuditFile.objects.create(
                    file_sha256=file_sha256,
                    byte_size=len(dump_bytes),
                    raw_text=raw_text,
                    validation_status=AuditFile.STATUS_INVALID,
                    validation_error="winner preserved invalid UTF-8 evidence",
                    total_line_count=1,
                    invalid_event_count=1,
                )
                AuditEvent.objects.create(
                    group=group,
                    audit_file=race_winner["audit_file"],
                    line_number=1,
                    line_hash=hashlib.sha256(
                        raw_text.encode("utf-8", errors="replace")
                    ).hexdigest(),
                    raw_line=raw_text,
                    parse_status=AuditEvent.STATUS_INVALID,
                    validation_error="winner preserved invalid UTF-8 evidence",
                )
            return group

        with mock.patch.object(ingest_module, "group_for_slug", side_effect=insert_race_winner):
            result = ingest_audit_log_bytes(
                dump_bytes=dump_bytes,
                fallback_group_slug="mobile-qa",
                fallback_group_name="Mobile QA",
            )

        self.assertFalse(result.created)
        self.assertEqual(result.audit_file, race_winner["audit_file"])
        self.assertEqual(AuditFile.objects.count(), 1)
        self.assertEqual(AuditEvent.objects.count(), 1)
        self.assertEqual(result.audit_file.file_sha256, file_sha256)
        self.assertEqual(result.audit_file.raw_text, raw_text)

    def test_deeply_nested_json_line_is_quarantined_not_500(self):
        # A single deeply-nested JSON line makes json.loads recurse until it
        # raises RecursionError (a RuntimeError subclass, not a JSONDecodeError).
        # Unfixed, that exception escapes parse_jsonl()/ingest_audit_log_bytes()
        # and the view, 500ing the request *before* any AuditFile is created --
        # so the raw evidence is lost. It must instead be treated like any other
        # malformed JSON: a 400 with a saved, quarantined AuditFile that
        # preserves the raw upload and the offending raw line. Regression for
        # marmot-protocol/goggles#24.
        #
        # The nesting depth here is chosen to exceed CPython's recursion limit
        # in the C json scanner (which tolerates a few thousand levels), so the
        # test genuinely reproduces the RecursionError escape on the unfixed
        # parser rather than merely hitting the "not a JSON object" path.
        raw_token, _token = UploadToken.issue("ios test client")
        deep_line = "[" * 100000 + "]" * 100000
        bad_body = representative_audit_log() + deep_line + "\n"

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
        # Raw upload text is preserved intact, not lost.
        self.assertEqual(audit_file.raw_text, bad_body)
        self.assertIn("line 3", audit_file.validation_error)
        self.assertEqual(audit_file.events.count(), 3)
        bad_event = audit_file.events.get(line_number=3)
        self.assertEqual(bad_event.parse_status, "invalid")
        # The offending raw line is preserved verbatim as evidence.
        self.assertEqual(bad_event.raw_line, deep_line)
        self.assertIn("invalid JSON", bad_event.validation_error)

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

    def test_overlong_group_ref_is_quarantined_not_500(self):
        # group_ref is a TextField (no max_length) but lives in a composite
        # btree index (group_ref, wall_time_ms). On Postgres an index tuple
        # larger than ~2704 bytes is rejected with a DataError
        # ("index row size N exceeds btree version 4 maximum 2704"), which is
        # NOT an IntegrityError and so escapes the ``except IntegrityError``
        # handler in ingest_audit_log_bytes() -- 500ing the upload and losing
        # the raw evidence. valid_group_ref() already rejects a ~6000-char hex
        # value (it exceeds AuditGroup.group_ref max_length=512), so the file
        # is quarantined; the oversized value must be dropped from the stored
        # indexed column rather than handed verbatim to bulk_create().
        # The raw upload text and offending raw line must still be preserved as
        # evidence. Regression for marmot-protocol/goggles#14.
        #
        # NOTE: the value must be INCOMPRESSIBLE. Postgres applies the 2704-byte
        # btree limit to the (TOAST-compressed) index tuple, so a repetitive
        # string like "ab" * 3000 compresses well under the limit and does NOT
        # reproduce the crash. A string of distinct hex chunks does not compress
        # and overflows the index exactly as the production payload does.
        raw_token, _token = UploadToken.issue("ios test client")
        oversized_group_ref = "".join(
            hashlib.md5(str(i).encode()).hexdigest() for i in range(200)
        )  # 200 * 32 = 6400 incompressible, even-length hex chars
        self.assertGreater(len(oversized_group_ref), group_ref_max_length())
        bad_event = audit_event(0, group_ref=oversized_group_ref)
        body = jsonl(bad_event)

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["validation_status"], "invalid")
        self.assertIn("group_ref", response.json()["error"])

        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.validation_status, AuditFile.STATUS_INVALID)
        # Raw upload text is preserved intact, not lost to a 500/rollback.
        self.assertEqual(audit_file.raw_text, body)
        # No AuditGroup is created for an out-of-schema ref.
        self.assertFalse(AuditGroup.objects.filter(group_ref=oversized_group_ref).exists())

        event = audit_file.events.get()
        self.assertEqual(event.parse_status, AuditEvent.STATUS_INVALID)
        self.assertIn("group_ref", event.validation_error)
        # The oversized value is dropped from the stored (indexed) column...
        self.assertEqual(event.group_ref, "")
        # ...but the verbatim line is preserved as evidence.
        self.assertEqual(event.raw_line, body.rstrip("\n"))
        self.assertEqual(event.raw_event["group_ref"], oversized_group_ref)

    def test_overlong_msg_id_is_quarantined_not_500(self):
        # msg_id is an unbounded TextField carried by a single-column btree
        # index (Index(fields=["msg_id"])). copy_msg_field() previously only
        # checked that the value was even-length hex, so an otherwise-valid
        # event with a multi-kilobyte hex msg_id passed normalization and was
        # handed verbatim to bulk_create(). On Postgres an index tuple larger
        # than ~2704 bytes is rejected with a DataError ("index row size N
        # exceeds btree version 4 maximum 2704"), which is NOT an IntegrityError
        # and so escapes the ``except IntegrityError`` handler in
        # ingest_audit_log_bytes() -- 500ing the upload and losing the raw
        # evidence. The oversized value must be dropped from the stored indexed
        # column while the verbatim raw line/event are preserved. Regression for
        # marmot-protocol/goggles#56.
        #
        # NOTE: the value must be INCOMPRESSIBLE. Postgres applies the 2704-byte
        # btree limit to the (TOAST-compressed) index tuple, so a repetitive
        # string like "ab" * 3000 compresses well under the limit and does NOT
        # reproduce the crash. A string of distinct hex chunks does not compress
        # and overflows the index exactly as the production payload does.
        raw_token, _token = UploadToken.issue("ios test client")
        oversized_msg_id = "".join(
            hashlib.md5(str(i).encode()).hexdigest() for i in range(200)
        )  # 200 * 32 = 6400 incompressible, even-length hex chars
        self.assertGreater(len(oversized_msg_id), MSG_ID_MAX_LENGTH)
        body = jsonl(
            audit_event(
                0,
                kind={
                    "type": "ingest_entry",
                    "msg_id": oversized_msg_id,
                    "envelope_kind": "group_message",
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
        self.assertIn("msg_id", response.json()["error"])

        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.validation_status, AuditFile.STATUS_INVALID)
        # Raw upload text is preserved intact, not lost to a 500/rollback.
        self.assertEqual(audit_file.raw_text, body)

        event = audit_file.events.get()
        self.assertEqual(event.parse_status, AuditEvent.STATUS_INVALID)
        self.assertIn("msg_id", event.validation_error)
        # The oversized value is dropped from the stored (indexed) column...
        self.assertEqual(event.msg_id, "")
        # ...but the verbatim line/event are preserved as evidence.
        self.assertEqual(event.raw_line, body.rstrip("\n"))
        self.assertEqual(event.raw_event["kind"]["msg_id"], oversized_msg_id)

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

    def test_out_of_range_wall_time_ms_returns_400_and_is_quarantined(self):
        # wall_time_ms = 1e17 fits the bigint column (< 9.2e18) so it stores
        # fine and was previously normalized as *valid*, but it is nonsense as
        # a millis-since-epoch instant (year 3170843). Downstream the server
        # builds a datetime (the groups landing 500) and the timeline JS a Date
        # (blank render). Ingest must bound it to a sane epoch range and
        # quarantine the event instead.
        raw_token, _token = UploadToken.issue("ios test client")
        body = jsonl(audit_event(0, wall_time_ms=100_000_000_000_000_000))

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["validation_status"], "invalid")
        self.assertIn(
            "wall_time_ms must be a non-negative integer within range",
            response.json()["error"],
        )

        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.validation_status, AuditFile.STATUS_INVALID)
        # Raw evidence is preserved rather than lost to a 500.
        self.assertEqual(audit_file.raw_text, body)
        event = audit_file.events.get()
        self.assertEqual(event.parse_status, AuditEvent.STATUS_INVALID)
        self.assertIsNone(event.wall_time_ms)
        self.assertIn(
            "wall_time_ms must be a non-negative integer within range",
            event.validation_error,
        )

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


class HumanActionGroupingTests(TestCase):
    """Regression coverage for goggles#30.

    Human-action events that share no operation_id must NOT be merged solely on
    action type; each operation_id-less action should be its own group.
    """

    def _human_action(self, action="send_message"):
        return {
            "action": action,
            "origin": "local_user",
            "fields": ["body"],
            "component_ids": [32769],
        }

    def test_same_type_actions_without_operation_id_are_distinct_groups(self):
        # Two send_message human actions, neither carrying an operation_id.
        ingest_body(
            jsonl(
                audit_event(
                    0,
                    wall_time_ms=T0,
                    context={"human_action": self._human_action()},
                ),
                audit_event(
                    1,
                    wall_time_ms=T0 + 86_400_000,  # a day later
                    context={"human_action": self._human_action()},
                ),
            )
        )
        group = AuditGroup.objects.get(slug=GROUP_REF)
        events = list(valid_events_for_group(group))

        # Sanity: neither event carries an operation_id.
        self.assertTrue(all(not e.context_operation_id for e in events))

        action_groups = human_action_groups_for_group(events)

        # Each operation_id-less action is its own card (today's bug produced 1).
        self.assertEqual(len(action_groups), 2)
        # Per-action windows are not stretched across the whole span.
        self.assertEqual(action_groups[0]["first_wall_time_ms"], T0)
        self.assertEqual(action_groups[0]["last_wall_time_ms"], T0)
        self.assertEqual(action_groups[1]["first_wall_time_ms"], T0 + 86_400_000)
        self.assertEqual(action_groups[1]["last_wall_time_ms"], T0 + 86_400_000)

    def test_actions_sharing_real_operation_id_still_merge(self):
        # Two events with the SAME real operation_id remain one group.
        shared = {"operation_id": "op-shared", "human_action": self._human_action()}
        ingest_body(
            jsonl(
                audit_event(0, wall_time_ms=T0, context=shared),
                audit_event(1, wall_time_ms=T0 + 1000, context=shared),
            )
        )
        group = AuditGroup.objects.get(slug=GROUP_REF)
        events = list(valid_events_for_group(group))

        action_groups = human_action_groups_for_group(events)

        self.assertEqual(len(action_groups), 1)
        self.assertEqual(action_groups[0]["operation_id"], "op-shared")
        self.assertEqual(action_groups[0]["first_wall_time_ms"], T0)
        self.assertEqual(action_groups[0]["last_wall_time_ms"], T0 + 1000)

    def test_operationless_event_does_not_collide_with_event_prefixed_operation_id(self):
        # Regression for the fallback-key collision: a real operation_id of the
        # literal form "event:<pk>" must not merge with the synthetic key of an
        # operation_id-less event whose DB pk happens to equal <pk>. The two
        # actions are unrelated and must stay in separate groups.
        ingest_body(
            jsonl(
                audit_event(
                    0,
                    wall_time_ms=T0,
                    context={"human_action": self._human_action()},
                )
            )
        )
        group = AuditGroup.objects.get(slug=GROUP_REF)
        operationless = valid_events_for_group(group).get()
        # Sanity: the first event carries no operation_id.
        self.assertFalse(operationless.context_operation_id)

        # Second event carries a real operation_id that collides with the old
        # flat fallback key f"event:{pk}" of the first event.
        colliding_operation_id = f"event:{operationless.pk}"
        ingest_body(
            jsonl(
                audit_event(
                    1,
                    wall_time_ms=T0 + 1000,
                    context={
                        "operation_id": colliding_operation_id,
                        "human_action": self._human_action(),
                    },
                )
            )
        )
        events = list(valid_events_for_group(group))
        self.assertEqual(len(events), 2)
        self.assertEqual(events[1].context_operation_id, colliding_operation_id)

        action_groups = human_action_groups_for_group(events)

        # Two distinct actions → two groups (the flat-string key produced 1).
        self.assertEqual(len(action_groups), 2)
        self.assertEqual(action_groups[0]["first_wall_time_ms"], T0)
        self.assertEqual(action_groups[0]["last_wall_time_ms"], T0)
        self.assertEqual(action_groups[0]["operation_id"], "")
        self.assertEqual(action_groups[1]["first_wall_time_ms"], T0 + 1000)
        self.assertEqual(action_groups[1]["last_wall_time_ms"], T0 + 1000)
        self.assertEqual(action_groups[1]["operation_id"], colliding_operation_id)

    def test_shared_operation_target_count_zero_is_preserved(self):
        # Regression for goggles#16: a real target_count of 0 must survive the
        # grouping merge. The old ``group[...] or event...`` chain dropped a
        # falsy-but-real 0 — either replacing it with a later None (rendered as
        # the en dash) or overwriting it with a subsequent positive value.
        shared = {"operation_id": "op-target-zero"}

        def action(target_count):
            ha = self._human_action(action="remove_member")
            ha["target_count"] = target_count
            return {**shared, "human_action": ha}

        # First event carries a genuine target_count of 0; the second omits it
        # (target_count=None) and a third carries a positive count. The merged
        # group must keep the genuine 0 rather than letting None or 3 win.
        ingest_body(
            jsonl(
                audit_event(0, wall_time_ms=T0, context=action(0)),
                audit_event(1, wall_time_ms=T0 + 1000, context=action(None)),
                audit_event(2, wall_time_ms=T0 + 2000, context=action(3)),
            )
        )
        group = AuditGroup.objects.get(slug=GROUP_REF)
        events = list(valid_events_for_group(group))

        # Sanity: the genuine 0 round-trips through ingest as a real 0, not None.
        self.assertEqual(events[0].human_action_target_count, 0)
        self.assertIsNone(events[1].human_action_target_count)

        action_groups = human_action_groups_for_group(events)

        # All three share one operation_id -> one merged group.
        self.assertEqual(len(action_groups), 1)
        # The genuine first-seen 0 is preserved, not dropped or overwritten.
        self.assertEqual(action_groups[0]["target_count"], 0)


class UploadTokenLifecycleTests(TestCase):
    """Lock in the documented upload-token lifecycle: reusable by default,
    with an optional expiry. See AGENTS.md 'Upload token lifecycle' and
    goggles#32 (docs-vs-behavior mismatch)."""

    def _upload(self, raw_token):
        return self.client.post(
            reverse("api-audit-log-upload"),
            data=representative_audit_log(),
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

    def test_token_is_reusable_across_multiple_uploads(self):
        # The documented contract: a token authenticates every upload it is
        # presented for. mark_used() records last_used_at but never revokes.
        raw_token, token = UploadToken.issue("ios qa")

        first = self._upload(raw_token)
        self.assertEqual(first.status_code, 201)

        second = self._upload(raw_token)
        # Second upload of identical bytes is a dedupe (200), not a 401.
        self.assertEqual(second.status_code, 200)

        token.refresh_from_db()
        self.assertTrue(token.is_active)
        self.assertIsNotNone(token.last_used_at)

    def test_token_with_future_expiry_authenticates(self):
        raw_token, token = UploadToken.issue(
            "ios qa", expires_at=timezone.now() + timedelta(days=1)
        )
        self.assertFalse(token.is_expired())

        response = self._upload(raw_token)
        self.assertEqual(response.status_code, 201)
        self.assertIsNotNone(UploadToken.authenticate(raw_token))

    def test_expired_token_is_rejected_with_401(self):
        raw_token, token = UploadToken.issue(
            "stale device", expires_at=timezone.now() - timedelta(seconds=1)
        )
        self.assertTrue(token.is_expired())
        self.assertIsNone(UploadToken.authenticate(raw_token))

        response = self._upload(raw_token)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(AuditFile.objects.count(), 0)

    def test_token_expiring_between_uploads_stops_authenticating(self):
        # Reusable until the expiry boundary, rejected once past it.
        raw_token, token = UploadToken.issue(
            "ios qa", expires_at=timezone.now() + timedelta(hours=1)
        )
        self.assertEqual(self._upload(raw_token).status_code, 201)

        UploadToken.objects.filter(pk=token.pk).update(
            expires_at=timezone.now() - timedelta(seconds=1)
        )
        self.assertEqual(self._upload(raw_token).status_code, 401)

    def test_default_token_never_expires(self):
        raw_token, token = UploadToken.issue("ios qa")
        self.assertIsNone(token.expires_at)
        self.assertFalse(token.is_expired())
        self.assertIsNotNone(UploadToken.authenticate(raw_token))

    def test_create_upload_token_command_sets_expiry(self):
        out = StringIO()
        before = timezone.now()
        call_command("create_upload_token", "ios qa", "--expires-in-days", "7", stdout=out)
        after = timezone.now()

        token = UploadToken.objects.get(name="ios qa")
        self.assertIsNotNone(token.expires_at)
        self.assertGreaterEqual(token.expires_at, before + timedelta(days=7))
        self.assertLessEqual(token.expires_at, after + timedelta(days=7))
        self.assertIn("expires at", out.getvalue())

    def test_create_upload_token_command_defaults_to_no_expiry(self):
        out = StringIO()
        call_command("create_upload_token", "ios qa", stdout=out)

        token = UploadToken.objects.get(name="ios qa")
        self.assertIsNone(token.expires_at)
        self.assertIn("does not expire", out.getvalue())


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

    def test_local_action_initiator_is_not_an_unconfirmed_engine(self):
        system_action = {"action": "confirm_epoch", "origin": "system"}
        ingest_body(
            jsonl(
                audit_event(
                    0,
                    wall_time_ms=T0,
                    kind={
                        "type": "human_action",
                        "action": "update_group_profile",
                        "origin": "local_user",
                        "phase": "succeeded",
                        "from_epoch": 6,
                        "to_epoch": 7,
                    },
                )
            ),
            source_account_label="Alice",
        )
        ingest_body(
            jsonl(
                audit_event(
                    0,
                    engine_id=ENGINE_BOB,
                    account_ref=ACCOUNT_BOB,
                    wall_time_ms=T0 + 100,
                    human_action=system_action,
                    kind={
                        "type": "epoch_confirmed",
                        "from_epoch": 6,
                        "to_epoch": 7,
                        "pending_kind": "group_evolution",
                    },
                )
            ),
            source_account_label="Bob",
        )
        ingest_body(jsonl(audit_event(0, engine_id=ENGINE_CAROL, wall_time_ms=T0 + 200)))
        group = AuditGroup.objects.get(slug=GROUP_REF)

        ep = payload_for(group)["epochs"][0]

        self.assertEqual(ep["epoch"], 7)
        self.assertEqual(ep["initiator_engines"], [0])
        self.assertEqual(ep["initiators"][0]["action"], "update_group_profile")
        self.assertEqual(ep["initiators"][0]["source"], "human_action")
        self.assertEqual(ep["confirmations"][0]["engine"], 1)
        self.assertEqual(ep["unconfirmed_engines"], [2])

    def test_group_evolution_send_outcome_links_initiator_by_message_epoch(self):
        system_action = {"action": "confirm_epoch", "origin": "system"}
        ingest_body(
            jsonl(
                audit_event(
                    0,
                    wall_time_ms=T0,
                    kind={
                        "type": "send_outcome",
                        "intent_kind": "update_group_data",
                        "result_kind": "group_evolution",
                        "outbound_msg_id": MSG_ID,
                    },
                )
            ),
            source_account_label="Alice",
        )
        ingest_body(
            jsonl(
                audit_event(
                    0,
                    engine_id=ENGINE_BOB,
                    account_ref=ACCOUNT_BOB,
                    wall_time_ms=T0 + 50,
                    human_action=system_action,
                    kind={
                        "type": "ingest_outcome",
                        "msg_id": MSG_ID,
                        "outcome_kind": "processed",
                        "epoch": 7,
                    },
                ),
                audit_event(
                    1,
                    engine_id=ENGINE_BOB,
                    account_ref=ACCOUNT_BOB,
                    wall_time_ms=T0 + 100,
                    human_action=system_action,
                    kind={
                        "type": "epoch_confirmed",
                        "from_epoch": 6,
                        "to_epoch": 7,
                        "pending_kind": "group_evolution",
                    },
                ),
            ),
            source_account_label="Bob",
        )
        group = AuditGroup.objects.get(slug=GROUP_REF)

        ep = payload_for(group)["epochs"][0]

        self.assertEqual(ep["initiator_engines"], [0])
        self.assertEqual(ep["initiators"][0]["source"], "send_outcome")
        self.assertEqual(ep["initiators"][0]["result_kind"], "group_evolution")
        self.assertEqual(ep["confirmations"][0]["engine"], 1)
        self.assertEqual(ep["unconfirmed_engines"], [])

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

    def test_epoch_zero_message_event_buckets_under_epoch_zero(self):
        # Regression for goggles#16: a real epoch of 0 (MLS genesis epoch) must
        # be treated as present. The old `X or Y` chain in event_epoch() dropped
        # the falsy 0, so the message event was lost from message_event_count and
        # the timeline item's epoch came out as None.
        ingest_body(
            jsonl(
                # Confirms epoch 0, creating the epoch-0 bucket.
                epoch_confirmed(0, ENGINE_ALICE, 0, 0, T0),
                # Message event whose only epoch field is the genuine 0.
                audit_event(
                    1,
                    kind={
                        "type": "ingest_outcome",
                        "msg_id": MSG_ID,
                        "outcome_kind": "processed",
                        "epoch": 0,
                    },
                    wall_time_ms=T0 + 10,
                ),
            )
        )
        group = AuditGroup.objects.get(slug=GROUP_REF)

        payload = payload_for(group)
        ep = payload["epochs"][0]

        # Bucket is epoch 0 and the epoch-0 message event is counted there.
        self.assertEqual(ep["epoch"], 0)
        self.assertEqual(ep["message_event_count"], 1)

        # The timeline item for the epoch-0 event renders epoch 0, not None.
        outcome_items = [item for item in payload["items"] if item["type"] == "ingest_outcome"]
        self.assertEqual(len(outcome_items), 1)
        self.assertEqual(outcome_items[0]["epoch"], 0)

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

    def test_peeler_retry_bursts_are_compacted_for_timeline(self):
        terminal_msg_id = "55" * 32
        ingest_body(
            jsonl(
                audit_event(
                    0,
                    kind={
                        "type": "peeler_outcome",
                        "msg_id": MSG_ID,
                        "outcome": "decrypt_failed",
                        "fallback_snapshot_used": False,
                        "detail": "no_matching_epoch",
                    },
                    wall_time_ms=T0 + 100,
                ),
                audit_event(
                    1,
                    kind={
                        "type": "message_state_changed",
                        "msg_id": MSG_ID,
                        "new_state": "peel_deferred",
                        "reason": "persist",
                    },
                    wall_time_ms=T0 + 200,
                ),
                audit_event(
                    2,
                    kind={
                        "type": "peeler_outcome",
                        "msg_id": OTHER_MSG_ID,
                        "outcome": "decrypt_failed",
                        "fallback_snapshot_used": False,
                        "detail": "no_matching_epoch",
                    },
                    wall_time_ms=T0 + 500,
                ),
                audit_event(
                    3,
                    kind={
                        "type": "message_state_changed",
                        "msg_id": OTHER_MSG_ID,
                        "new_state": "peel_deferred",
                        "reason": "peel_failed",
                    },
                    wall_time_ms=T0 + 700,
                ),
                audit_event(
                    4,
                    kind={
                        "type": "message_state_changed",
                        "msg_id": terminal_msg_id,
                        "new_state": "failed",
                        "reason": "terminal",
                    },
                    wall_time_ms=T0 + 800,
                ),
            )
        )
        group = AuditGroup.objects.get(slug=GROUP_REF)

        items = payload_for(group)["items"]
        bursts = [item for item in items if item["type"] == "peeler_retry_burst"]
        failed_items = [
            item
            for item in items
            if item["type"] == "message_state_changed" and item["msg_id"] == terminal_msg_id
        ]

        self.assertEqual(len(bursts), 1)
        burst = bursts[0]
        self.assertEqual(burst["tone"], "warning")
        self.assertNotIn("msg_id", burst)
        self.assertEqual(burst["message_ids"], [MSG_ID, OTHER_MSG_ID])
        self.assertEqual(burst["message_count"], 2)
        self.assertEqual(burst["event_count"], 4)
        self.assertEqual(burst["outcome"], "deferred")
        self.assertIn("decrypt_failed x2", burst["outcome_summary"])
        self.assertIn("peel_deferred x2", burst["outcome_summary"])
        self.assertIn("persist", burst["reason"])
        self.assertIn("peel_failed", burst["reason"])
        self.assertEqual(failed_items[0]["tone"], "error")


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

    def test_out_of_range_stored_wall_time_ms_does_not_500_group_list(self):
        # Defense-in-depth for data stored before the ingest bound existed (or
        # via a future bug): an AuditEvent already in the DB with an
        # out-of-range wall_time_ms. last_activity_ms = Max(wall_time_ms) feeds
        # datetime.fromtimestamp(), which raises "year ... is out of range".
        # The groups landing page is LOGIN_REDIRECT_URL, so an uncaught error
        # 500s it for *every* analyst. It must degrade to "unknown time"
        # instead.
        self.seed_fork_group()
        group = AuditGroup.objects.get(slug=GROUP_REF)
        # Force a stored value past the year-2100 ingest bound (1e17 -> year
        # 3170843), bypassing ingest validation as legacy data would.
        updated = (
            AuditEvent.objects.filter(group=group)
            .order_by("-wall_time_ms")
            .values_list("id", flat=True)[:1]
        )
        AuditEvent.objects.filter(id__in=list(updated)).update(wall_time_ms=100_000_000_000_000_000)

        # group_list_rows() itself must not raise.
        rows = {row.slug: row for row in group_list_rows()}
        self.assertIsNone(rows[GROUP_REF].last_activity)
        self.assertEqual(rows[GROUP_REF].last_activity_ms, 100_000_000_000_000_000)

        # And the actual landing view returns 200, not 500.
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")
        response = self.client.get(reverse("group-list"))
        self.assertEqual(response.status_code, 200)

    def test_group_list_view_counts_multi_group_upload_once_in_header(self):
        ingest_body(
            jsonl(
                audit_event(0, group_ref=GROUP_REF, wall_time_ms=T0),
                audit_event(1, group_ref=OTHER_GROUP_REF, wall_time_ms=T0 + 100),
            )
        )
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

        response = self.client.get(reverse("group-list"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["total_logs"], 1)
        self.assertContains(response, "2 groups · 1 log · chain-of-custody intact")

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
        self.assertContains(response, reverse("group-agent-export", kwargs={"slug": GROUP_REF}))
        self.assertContains(response, "Export JSON")
        payload = response.context["timeline_payload"]
        self.assertEqual(payload["version"], 1)
        self.assertEqual(len(payload["engines"]), 1)
        self.assertEqual(json.loads(json.dumps(payload)), payload)

    def test_group_agent_export_requires_login(self):
        ingest_body(representative_audit_log())

        response = self.client.get(reverse("group-agent-export", kwargs={"slug": GROUP_REF}))

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response["Location"])

    def test_group_agent_export_returns_agent_readable_json(self):
        ingest_body(representative_audit_log(), source_account_label="Alice")
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

        response = self.client.get(reverse("group-agent-export", kwargs={"slug": GROUP_REF}))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertIn("attachment", response["Content-Disposition"])
        self.assertIn(f"{GROUP_REF}-agent-state.json", response["Content-Disposition"])
        payload = response.json()
        self.assertEqual(payload["schema_version"], "goggles-agent-group-state/v1")
        self.assertEqual(payload["group"]["slug"], GROUP_REF)
        self.assertEqual(payload["summary"]["event_count"], 2)
        self.assertEqual(payload["sources"][0]["source_account_label"], "Alice")
        self.assertEqual(payload["timeline"]["version"], 1)
        self.assertEqual(len(payload["events"]), 2)
        self.assertEqual(payload["events"][0]["kind"]["type"], "ingest_entry")
        self.assertIn("line_hash", payload["events"][0]["source"])
        self.assertNotIn("raw_line", payload["events"][0])
        self.assertIn("raw_upload_bodies", payload["sensitivity"]["omits"])

    def test_group_detail_fetches_events_with_bounded_queries(self):
        ingest_body(representative_audit_log(engine_id=ENGINE_ALICE))
        ingest_body(representative_audit_log(engine_id=ENGINE_BOB))
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(reverse("group-detail", kwargs={"slug": GROUP_REF}))

        self.assertEqual(response.status_code, 200)
        self.assertLessEqual(len(ctx.captured_queries), 12)

    def test_group_detail_reuses_message_traces_for_timeline_integrity(self):
        ingest_body(representative_audit_log(engine_id=ENGINE_ALICE))
        ingest_body(representative_audit_log(engine_id=ENGINE_BOB))
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

        with mock.patch.object(
            analysis_module,
            "message_traces_from_events",
            wraps=analysis_module.message_traces_from_events,
        ) as trace_builder:
            response = self.client.get(reverse("group-detail", kwargs={"slug": GROUP_REF}))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(trace_builder.call_count, 1)

    def test_group_detail_query_count_does_not_grow_with_file_count(self):
        # Per-file group_event_count must come from the events prefetch, not a
        # COUNT query per audit file (goggles#18). Prove it by showing the query
        # count is identical whether the group has 2 files or 6: an N+1 would
        # add one query per extra file.
        engines = [
            ENGINE_ALICE,
            ENGINE_BOB,
            ENGINE_CAROL,
            "1111111111111111aaaaaaaaaaaaaaaa",
            "2222222222222222bbbbbbbbbbbbbbbb",
            "3333333333333333cccccccccccccccc",
        ]
        for engine_id in engines[:2]:
            ingest_body(representative_audit_log(engine_id=engine_id))
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

        with CaptureQueriesContext(connection) as few_ctx:
            response_few = self.client.get(reverse("group-detail", kwargs={"slug": GROUP_REF}))
        self.assertEqual(response_few.status_code, 200)
        self.assertEqual(AuditFile.objects.count(), 2)

        for engine_id in engines[2:]:
            ingest_body(representative_audit_log(engine_id=engine_id))
        self.assertEqual(AuditFile.objects.count(), len(engines))

        with CaptureQueriesContext(connection) as many_ctx:
            response_many = self.client.get(reverse("group-detail", kwargs={"slug": GROUP_REF}))
        self.assertEqual(response_many.status_code, 200)

        # Confirm the per-file count is actually rendered (the value the N+1
        # was computing), so we are guarding a live code path.
        for row in response_many.context["audit_files"]:
            self.assertEqual(row["group_event_count"], 2)

        self.assertEqual(
            len(many_ctx.captured_queries),
            len(few_ctx.captured_queries),
            "group detail issues an extra query per audit file — the events "
            "prefetch is being defeated (goggles#18 N+1 regression)",
        )


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


class DebugFailClosedSettingsTests(SimpleTestCase):
    """Regression tests for goggles#20.

    A missing ``DJANGO_DEBUG`` must fail *closed* (production-safe), so an
    operator has to opt in to debug mode rather than opt out of it. We
    re-execute the real ``config/settings.py`` source in an isolated namespace
    under a controlled environment, which lets us probe the ``DEBUG`` default
    and the production guards without disturbing the already-imported
    process-wide ``django.conf.settings``.
    """

    SETTINGS_PATH = Path(settings_module.__file__).resolve()

    # Environment keys the settings module reads; cleared for a clean slate so a
    # stray DJANGO_* var in the test runner's environment can't mask the default.
    _MANAGED_PREFIXES = ("DJANGO_",)
    _MANAGED_KEYS = ("DATABASE_URL",)

    # A representative production-style environment, deliberately missing
    # DJANGO_DEBUG so we can assert the default rather than an explicit value.
    _PROD_ENV = {
        "DJANGO_SECRET_KEY": "x" * 64,
        "DJANGO_ALLOWED_HOSTS": "goggles.example.com",
        "DJANGO_CSRF_TRUSTED_ORIGINS": "https://goggles.example.com",
        "DATABASE_URL": "postgres://goggles:secret@db:5432/goggles",
    }

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._settings_code = compile(cls.SETTINGS_PATH.read_text(), str(cls.SETTINGS_PATH), "exec")

    @contextlib.contextmanager
    def _clean_env(self, **overrides):
        saved = dict(os.environ)
        try:
            for key in list(os.environ):
                if key.startswith(self._MANAGED_PREFIXES) or key in self._MANAGED_KEYS:
                    del os.environ[key]
            for key, value in overrides.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
            yield
        finally:
            os.environ.clear()
            os.environ.update(saved)

    def _load_settings(self):
        namespace = {
            "__file__": str(self.SETTINGS_PATH),
            "__name__": "config._settings_under_test",
        }
        exec(self._settings_code, namespace)  # noqa: S102 - trusted in-repo source
        return namespace

    def test_missing_django_debug_fails_closed_to_production(self):
        # The core guarantee: with a complete production-style environment but
        # DJANGO_DEBUG entirely unset, the app must NOT boot in debug mode.
        with self._clean_env(**self._PROD_ENV):
            ns = self._load_settings()
        self.assertIs(ns["DEBUG"], False)
        # Production cookie/HSTS hardening must follow from the safe default.
        self.assertTrue(ns["SESSION_COOKIE_SECURE"])
        self.assertTrue(ns["CSRF_COOKIE_SECURE"])
        self.assertEqual(ns["SECURE_HSTS_SECONDS"], 31536000)

    def test_missing_django_debug_keeps_production_guards_active(self):
        # With DJANGO_DEBUG unset and the production secrets absent, the guards
        # gated on `not DEBUG` must fire instead of silently booting with the
        # dev SECRET_KEY and SQLite fallback.
        with self._clean_env():
            with self.assertRaises(ImproperlyConfigured):
                self._load_settings()

    def test_explicit_opt_in_enables_debug(self):
        # Local development / CI opt in with DJANGO_DEBUG=1; that must still work
        # and must not trip the production guards.
        with self._clean_env(DJANGO_DEBUG="1"):
            ns = self._load_settings()
        self.assertIs(ns["DEBUG"], True)

    def test_explicit_opt_out_value_disables_debug(self):
        # An explicit falsey value is honored just like an absent var (closed).
        with self._clean_env(DJANGO_DEBUG="0", **self._PROD_ENV):
            ns = self._load_settings()
        self.assertIs(ns["DEBUG"], False)
