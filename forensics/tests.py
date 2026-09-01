import contextlib
import hashlib
import json
import os
from datetime import timedelta
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth.models import User
from django.core.exceptions import ImproperlyConfigured, RequestDataTooBig
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.test import (
    RequestFactory,
    SimpleTestCase,
    TestCase,
    TransactionTestCase,
    override_settings,
)
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone

from config import settings as settings_module

from . import analysis as analysis_module
from . import ingest as ingest_module
from . import projections as projections_module
from .analysis import (
    EXPORT_SENSITIVITY,
    audit_files_for_group,
    display_group_ref,
    group_list_rows,
    human_action_groups_for_group,
    timeline_payload_for_group,
    valid_events_for_group,
)
from .ingest import (
    MSG_ID_MAX_LENGTH,
    audit_event_batch_size,
    group_ref_max_length,
    ingest_audit_log_bytes,
)
from .management.commands.prune_audit_data import VACUUM_TABLES, vacuum_audit_data
from .models import (
    AnalysisRun,
    AuditEvent,
    AuditFile,
    AuditGroup,
    ConvergenceCandidate,
    ConvergenceRuleEvaluation,
    ConvergenceRun,
    DeliveryArtifact,
    DeliveryObservation,
    EpochStateTransition,
    NetworkObservation,
    PersonalAccessToken,
    RecipientExpectation,
    StateDelta,
    UploadToken,
)
from .seed_data import SCENARIO_GROUPS, build_dev_scenario, group_ref_for
from .streaming import ExportSection, stream_ndjson
from .token_crypto import MAX_TOKEN_EXPIRY_DAYS, expiry_from_days
from .views import (
    AUDIT_FILE_EVENT_PAGE_SIZE,
    GROUP_DETAIL_TAB_EVENT_LIMIT,
    GROUP_EPOCH_FIELDS,
    GROUP_EXPORT_SCHEMA_VERSION,
    GROUP_PROJECTION_API_DEFAULT_LIMIT,
    RAW_TEXT_PREVIEW_CHARS,
    audit_bytes_from_request,
    client_ip,
    delivery_identity_index,
    group_api_payload,
    group_detail_shell_context,
    group_engine_rows,
    group_epoch_count,
    group_overview_context,
    group_summary_context,
    groups_for_audit_file,
    paginated_payloads,
    saved_report_projection_summary,
    valid_group_event_queryset,
)

SCHEMA_VERSION = "marmot-forensics-audit/v1"
SCHEMA_VERSION_V2 = "marmot-forensics-audit/v2"
SCHEMA_VERSION_V3 = "marmot-forensics-audit/v3"
ENGINE_ALICE = "0123456789abcdef0123456789abcdef"
ENGINE_BOB = "abcdef0123456789abcdef0123456789"
ACCOUNT_ALICE = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ACCOUNT_BOB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
GROUP_REF = "11" * 32
OTHER_GROUP_REF = "44" * 32
THIRD_GROUP_REF = "77" * 32
MSG_ID = "22" * 32
OTHER_MSG_ID = "33" * 32
DIGEST_A = "aa" * 32
DIGEST_B = "bb" * 32

HEAVY_EVENT_SELECT_COLUMNS = {
    field: f'"forensics_auditevent"."{field}"'
    for field in (
        "raw_line",
        "raw_event",
        "raw_kind",
        "raw_context",
        "context_human_action",
        "context_transport",
        "context_engine",
        "context_group",
        "context_convergence",
        "context_source",
    )
}
HEAVY_BULK_SELECT_COLUMNS = (
    '"forensics_auditfile"."raw_text"',
    *HEAVY_EVENT_SELECT_COLUMNS.values(),
)


def heavy_bulk_selects(captured_queries, *, allowed_columns=()):
    prohibited_columns = set(HEAVY_BULK_SELECT_COLUMNS) - set(allowed_columns)
    return [
        query["sql"]
        for query in captured_queries
        if query["sql"].lstrip().upper().startswith("SELECT")
        and any(column in query["sql"] for column in prohibited_columns)
    ]


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


def audit_event_v2(
    seq,
    engine_id=ENGINE_ALICE,
    group_ref=GROUP_REF,
    account_ref=ACCOUNT_ALICE,
    kind=None,
    wall_time_ms=None,
    context=None,
    audit_data_mode="obfuscated_sensitive_data",
    recorder_session_id="session-a",
):
    return {
        "schema_version": SCHEMA_VERSION_V2,
        "seq": seq,
        "wall_time_ms": wall_time_ms or 1_700_000_000_000 + seq,
        "recorder_session_id": recorder_session_id,
        "audit_data_mode": audit_data_mode,
        "account_ref": account_ref,
        "engine_id": engine_id,
        "group_ref": group_ref,
        "context": context if context is not None else {"operation_id": f"op-v2-{seq}"},
        "kind": kind or {"type": "recorder_started", "recorder": "mdk"},
    }


def audit_event_v3(
    seq,
    engine_id=ENGINE_ALICE,
    group_ref=GROUP_REF,
    account_ref=ACCOUNT_ALICE,
    kind=None,
    wall_time_ms=None,
    context=None,
    recorder_session_id="session-v3-a",
):
    return {
        "schema_version": SCHEMA_VERSION_V3,
        "seq": seq,
        "wall_time_ms": wall_time_ms or 1_700_000_100_000 + seq,
        "recorder_session_id": recorder_session_id,
        "account_ref": account_ref,
        "engine_id": engine_id,
        "group_ref": group_ref,
        "context": context if context is not None else {"operation_id": f"op-v3-{seq}"},
        "kind": kind or {"type": "recorder_started", "recorder": "jsonl"},
    }


def jsonl(*events):
    return "\n".join(json.dumps(event, separators=(",", ":")) for event in events) + "\n"


NORMALIZED_EVENT_BASE_FIELDS = frozenset(
    {
        "account_ref",
        "audit_data_mode",
        "engine_id",
        "event_type",
        "group_ref",
        "raw_context",
        "raw_kind",
        "recorder_session_id",
        "schema_version",
        "seq",
        "wall_time_ms",
    }
)

NORMALIZED_KIND_EXAMPLES = (
    (
        "ingest_entry",
        {
            "type": "ingest_entry",
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
            "stale_reason": "none",
            "epoch": 7,
        },
    ),
    ("send_entry", {"type": "send_entry", "intent_kind": "group_message"}),
    (
        "send_outcome",
        {
            "type": "send_outcome",
            "intent_kind": "group_message",
            "result_kind": "published",
            "outbound_msg_id": OTHER_MSG_ID,
            "outbound_welcome_msg_ids": [MSG_ID, OTHER_MSG_ID],
        },
    ),
    (
        "human_action",
        {
            "type": "human_action",
            "action": "update_group_profile",
            "origin": "local_user",
            "phase": "applied",
            "fields": ["name"],
            "component_ids": [32769],
            "target_count": 2,
            "message_ids": [MSG_ID],
            "from_epoch": 3,
            "to_epoch": 4,
        },
    ),
    (
        "publish_attempt",
        {
            "type": "publish_attempt",
            "msg_id": MSG_ID,
            "target_kind": "relay_set",
            "required_acks": 2,
            "relay_urls": ["wss://relay.example"],
        },
    ),
    (
        "publish_outcome",
        {
            "type": "publish_outcome",
            "msg_id": MSG_ID,
            "target_kind": "relay_set",
            "required_acks": 2,
            "accepted_relay_urls": ["wss://relay.example"],
            "failed_relays": ["wss://relay.invalid"],
            "met_required_acks": True,
        },
    ),
    (
        "publish_failure",
        {
            "type": "publish_failure",
            "msg_id": MSG_ID,
            "target_kind": "relay_set",
            "required_acks": 2,
            "reason": "relay_timeout",
            "detail": "relay did not ack before timeout",
            "relay_urls": ["wss://relay.example"],
        },
    ),
    (
        "epoch_confirmed",
        {"type": "epoch_confirmed", "from_epoch": 6, "to_epoch": 7, "pending_kind": "commit"},
    ),
    (
        "epoch_rolled_back",
        {
            "type": "epoch_rolled_back",
            "pending_epoch": 8,
            "restored_epoch": 7,
            "pending_kind": "commit",
        },
    ),
    (
        "snapshot_created",
        {
            "type": "snapshot_created",
            "snapshot_name": "before-rewind",
            "source_epoch": 7,
            "reason": "audit",
        },
    ),
    (
        "fork_resolution",
        {
            "type": "fork_resolution",
            "source_epoch": 7,
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
            "current_tip_epoch": 9,
            "candidate_count": 3,
            "eligible_count": 2,
            "max_rewind_commits": 4,
            "selected_branch_id": "branch-a",
            "selected_fork_epoch": 8,
            "selected_tip_epoch": 9,
        },
    ),
    (
        "peeler_outcome",
        {
            "type": "peeler_outcome",
            "msg_id": MSG_ID,
            "outcome": "success",
            "fallback_snapshot_used": False,
            "detail": "decrypted",
        },
    ),
    (
        "auto_commit_decision",
        {
            "type": "auto_commit_decision",
            "proposal_kind": "name_change",
            "decision": "accept",
            "reason": "local_user",
        },
    ),
    (
        "message_state_changed",
        {
            "type": "message_state_changed",
            "msg_id": MSG_ID,
            "new_state": "processed",
            "reason": "acked",
        },
    ),
    ("rejection", {"type": "rejection", "msg_id": MSG_ID, "reason": "malformed"}),
)


def representative_audit_log(engine_id=ENGINE_ALICE, source=None):
    # Account identity (account_label / account_pubkey_hex) rides in the JSONL
    # body's source_context, not in upload headers. Pass ``source`` to embed it.
    context = None
    if source is not None:
        context = {
            "operation_id": "op-source",
            "human_action": {
                "action": "update_group_profile",
                "origin": "local_user",
                "fields": ["name"],
                "component_ids": [32769],
            },
            "source": source,
        }
    return jsonl(
        audit_event(
            0,
            engine_id=engine_id,
            context=context,
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
            context=context,
            kind={
                "type": "ingest_outcome",
                "msg_id": MSG_ID,
                "outcome_kind": "processed",
                "epoch": 7,
            },
        ),
    )


class NormalizedFieldConfigurationTests(SimpleTestCase):
    def test_persisted_normalized_fields_match_pinned_snapshot(self):
        """Pin the persisted normalized-field set in both directions.

        persisted_normalized_fields() derives its set from the AuditEvent model
        (concrete columns minus NON_NORMALIZED_AUDIT_EVENT_FIELDS). That derivation
        only guards the silent-drop direction. Pinning the result against an
        explicit snapshot also guards the reverse, more dangerous direction for a
        forensic tool: a new bookkeeping column added to AuditEvent but omitted
        from NON_NORMALIZED_AUDIT_EVENT_FIELDS would be auto-included in the
        persisted set, silently copied from parsed.normalized, and surfaced in the
        agent-state export -- with no other test failing. The snapshot forces any
        such column add/remove to come with a conscious edit and reviewer
        attention on whether the column is normalized or bookkeeping (goggles#85).
        """
        from . import normalized_fields as normalized_field_config

        persisted = normalized_field_config.persisted_normalized_fields()

        self.assertEqual(
            persisted,
            normalized_field_config.EXPECTED_PERSISTED_NORMALIZED_FIELDS,
            "persisted_normalized_fields() drifted from its pinned snapshot. An "
            "AuditEvent column was added or removed: if it is a normalized value, "
            "update EXPECTED_PERSISTED_NORMALIZED_FIELDS; if it is ingestion "
            "bookkeeping, add it to NON_NORMALIZED_AUDIT_EVENT_FIELDS so it does "
            "not leak into the agent-state export (goggles#85).",
        )

    def test_non_normalized_exclusion_set_actually_excludes_bookkeeping_columns(self):
        """Assert the exclusion set's *contents*, not the impl formula.

        The previous test re-derived the implementation formula (concrete columns
        minus the exclusion set) and asserted it equals the implementation, which
        is tautological and gives false confidence about what the exclusion set
        contains. Anchor the actual bookkeeping columns instead so dropping one
        from NON_NORMALIZED_AUDIT_EVENT_FIELDS (which would leak it into the
        export) fails here.
        """
        from . import normalized_fields as normalized_field_config

        concrete_field_names = {field.name for field in AuditEvent._meta.local_concrete_fields}
        non_normalized = normalized_field_config.NON_NORMALIZED_AUDIT_EVENT_FIELDS

        # Every declared bookkeeping field must be a real AuditEvent column (so a
        # renamed/removed column can't leave a stale exclusion that masks a leak).
        self.assertLessEqual(non_normalized, concrete_field_names)

        # Columns that carry raw evidence, identity, ingest provenance, or
        # ORM/bookkeeping state must never be treated as persisted normalized
        # values -- they must not surface under event["normalized"].
        required_bookkeeping = {
            "id",
            "group",
            "audit_file",
            "raw_line",
            "raw_event",
            "raw_kind",
            "raw_context",
            "parse_status",
            "validation_error",
            "account_ref",
            "engine_id",
            "group_ref",
            "event_type",
            "created_at",
        }
        self.assertEqual(
            required_bookkeeping - non_normalized,
            set(),
            "A bookkeeping/identity/raw-evidence column is missing from "
            "NON_NORMALIZED_AUDIT_EVENT_FIELDS and would leak into the "
            "agent-state export (goggles#85).",
        )

        # None of the pinned normalized fields may also be marked bookkeeping.
        self.assertEqual(
            set(normalized_field_config.EXPECTED_PERSISTED_NORMALIZED_FIELDS) & non_normalized,
            set(),
        )

    def test_persisted_field_set_is_ingest_normalized_fields(self):
        from . import normalized_fields as normalized_field_config

        persisted = normalized_field_config.persisted_normalized_fields()
        self.assertEqual(len(persisted), len(set(persisted)))
        self.assertEqual(ingest_module.normalized_fields(), persisted)

    def test_agent_export_fields_are_persisted_fields_minus_documented_exclusions(self):
        from . import normalized_fields as normalized_field_config

        persisted = normalized_field_config.persisted_normalized_fields()
        export_excluded = normalized_field_config.AGENT_EXPORT_NORMALIZED_FIELD_EXCLUDE
        export_extra = normalized_field_config.AGENT_EXPORT_NORMALIZED_FIELD_EXTRA
        expected_export_fields = tuple(
            field for field in persisted if field not in export_excluded
        ) + tuple(export_extra)

        self.assertLessEqual(export_excluded, set(persisted))
        self.assertLessEqual(set(export_extra), {field.name for field in AuditEvent._meta.fields})
        self.assertEqual(analysis_module.AGENT_EXPORT_NORMALIZED_FIELDS, expected_export_fields)

    def test_every_normalized_key_produced_by_known_kinds_is_persisted(self):
        persisted_fields = set(ingest_module.normalized_fields())
        produced_fields = set()

        for event_type, kind in NORMALIZED_KIND_EXAMPLES:
            with self.subTest(event_type=event_type):
                event = audit_event(
                    100,
                    context={
                        "operation_id": "op-normalized-field-coverage",
                        "human_action": {
                            "action": "update_group_profile",
                            "origin": "local_user",
                            "phase": "applied",
                            "fields": ["name"],
                            "component_ids": [32769],
                            "target_count": 2,
                            "message_ids": [MSG_ID],
                            "from_epoch": 1,
                            "to_epoch": 2,
                        },
                        "transport": {"relay_urls": ["wss://relay.example"]},
                        "engine": {"id": ENGINE_ALICE},
                        "group": {"epoch": 7},
                    },
                    kind=kind,
                )
                normalized, errors = ingest_module.normalize_event(event)

                self.assertEqual(errors, [])
                self.assertEqual(normalized["event_type"], event_type)
                produced_fields.update(set(normalized) - NORMALIZED_EVENT_BASE_FIELDS)

        self.assertEqual(sorted(produced_fields - persisted_fields), [])


class SavedReportProjectionSummaryTests(SimpleTestCase):
    def test_summary_includes_nested_action_counts_and_pagination_flags(self):
        summary = saved_report_projection_summary(
            {
                "projection": {
                    "delivery_artifacts": [{"artifact_id": MSG_ID}],
                    "action_attribution": {
                        "user_actions": [{"action": "send_message"}],
                        "system_attribution": [{"action": "background_sync"}],
                        "other_attribution": [],
                    },
                    "pagination": {
                        "delivery_artifacts": {"has_more": True, "next_offset": 500},
                        "action_attribution": {
                            "user_actions": {"has_more": False, "next_offset": None},
                            "system_attribution": {"has_more": True, "next_offset": 500},
                            "other_attribution": {"has_more": False, "next_offset": None},
                        },
                    },
                }
            }
        )

        rows = {row["label"]: row for row in summary}
        self.assertEqual(rows["Delivery artifacts"]["count"], 1)
        self.assertTrue(rows["Delivery artifacts"]["has_more"])
        self.assertEqual(rows["Delivery artifacts"]["next_offset"], 500)
        self.assertEqual(rows["User actions"]["count"], 1)
        self.assertFalse(rows["User actions"]["has_more"])
        self.assertEqual(rows["System attribution"]["count"], 1)
        self.assertTrue(rows["System attribution"]["has_more"])


class ProjectionPaginationTests(TestCase):
    def test_filtered_payload_pagination_stops_after_page_plus_one_match(self):
        class FakeQuerySet:
            def __init__(self, items):
                self.items = items
                self.iterator_chunk_sizes = []

            def order_by(self, *fields):
                return self

            def __iter__(self):
                return iter(self.items)

            def iterator(self, chunk_size=None):
                if chunk_size is None or chunk_size < 1:
                    raise AssertionError("iterator chunk_size must be a positive integer")
                self.iterator_chunk_sizes.append(chunk_size)
                return iter(self.items)

        built = []

        def payload_factory(value):
            built.append(value)
            return {"value": value, "severity": "warning"}

        queryset = FakeQuerySet(list(range(5)))

        page, pagination = paginated_payloads(
            queryset,
            order_by=("value",),
            filters={"limit": 1, "offset": 0, "severity": "warning"},
            payload_factory=payload_factory,
            severity_factory=lambda payload: payload["severity"],
        )

        self.assertEqual(page, [{"value": 0, "severity": "warning"}])
        self.assertEqual(built, [0, 1])
        self.assertEqual(len(queryset.iterator_chunk_sizes), 1)
        self.assertGreaterEqual(queryset.iterator_chunk_sizes[0], 1)
        self.assertEqual(
            pagination,
            {"limit": 1, "offset": 0, "returned": 1, "has_more": True, "next_offset": 1},
        )

    def test_filtered_payload_pagination_applies_offset_after_filter_matches(self):
        class FakeQuerySet:
            def __init__(self, items):
                self.items = items

            def order_by(self, *fields):
                return self

            def __iter__(self):
                return iter(self.items)

            def iterator(self, chunk_size=None):
                if chunk_size is None or chunk_size < 1:
                    raise AssertionError("iterator chunk_size must be a positive integer")
                return iter(self.items)

        built = []

        def payload_factory(value):
            built.append(value)
            return {"value": value, "severity": "warning"}

        page, pagination = paginated_payloads(
            FakeQuerySet(list(range(8))),
            order_by=("value",),
            filters={"limit": 2, "offset": 1, "severity": ""},
            payload_factory=payload_factory,
            severity_factory=lambda payload: payload["severity"],
            payload_filter=lambda payload, filters: payload["value"] % 2 == 0,
        )

        self.assertEqual(
            page,
            [
                {"value": 2, "severity": "warning"},
                {"value": 4, "severity": "warning"},
            ],
        )
        self.assertEqual(built, [0, 1, 2, 3, 4, 5, 6])
        self.assertEqual(
            pagination,
            {"limit": 2, "offset": 1, "returned": 2, "has_more": True, "next_offset": 3},
        )

    def test_convergence_list_without_message_filter_paginates_before_payload_build(self):
        group = AuditGroup.objects.create(
            name="Paged convergence group",
            slug="paged-convergence-group",
            group_ref=GROUP_REF,
        )
        for i in range(3):
            ConvergenceRun.objects.create(
                group=group,
                run_id=f"run-{i:03d}",
                engine_id=ENGINE_ALICE,
                phase="selected",
                started_at_ms=1_700_000_000_000 + i,
            )
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")
        built = []

        def lightweight_convergence_payload(run):
            built.append(run.run_id)
            return {
                "run_id": run.run_id,
                "phase": run.phase,
                "error_kinds": [],
                "losing_branch_ids": [],
                "selected_branch_id": "",
                "candidates": [],
                "rule_evaluations": [],
                "evidence_refs": [],
            }

        with mock.patch(
            "forensics.views.convergence_run_payload",
            side_effect=lightweight_convergence_payload,
        ):
            response = self.client.get(
                reverse("api-group-convergence-runs", kwargs={"slug": group.slug}),
                {"limit": "1"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(built, ["run-000"])
        payload = response.json()
        self.assertEqual([run["run_id"] for run in payload["convergence_runs"]], ["run-000"])
        self.assertEqual(
            payload["pagination"],
            {"limit": 1, "offset": 0, "returned": 1, "has_more": True, "next_offset": 1},
        )


class AuditEventIndexTests(TestCase):
    def test_line_hash_engine_id_index_exists_in_database(self):
        index_name = "forensics_a_line_hash_eng_idx"
        declared_index = next(
            (index for index in AuditEvent._meta.indexes if index.name == index_name), None
        )

        if declared_index is None:
            self.fail(f"{index_name} missing from AuditEvent.Meta.indexes")
        else:
            self.assertEqual(tuple(declared_index.fields), ("line_hash", "engine_id"))
        with connection.cursor() as cursor:
            constraints = connection.introspection.get_constraints(
                cursor, AuditEvent._meta.db_table
            )
        database_index = constraints.get(index_name)

        if database_index is None:
            self.fail(f"{index_name} missing from database constraints")
        else:
            self.assertTrue(database_index["index"])
            self.assertEqual(tuple(database_index["columns"]), ("line_hash", "engine_id"))


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

    def test_legacy_token_survives_direct_fresh_hash_key_cutover(self):
        # A token issued under the SECRET_KEY fallback keeps working when an
        # operator sets a fresh GOGGLES_TOKEN_HASH_KEY while the old SECRET_KEY
        # is still configured; authenticate() rekeys the row on first use.
        with override_settings(
            SECRET_KEY="current-signing-key",
            GOGGLES_TOKEN_HASH_KEY="current-signing-key",  # fallback state
        ):
            raw_token, token = UploadToken.issue("legacy device")

        with override_settings(
            SECRET_KEY="current-signing-key",
            GOGGLES_TOKEN_HASH_KEY="brand-new-dedicated-key",
        ):
            authenticated = UploadToken.authenticate(raw_token)

        self.assertIsNotNone(authenticated)
        self.assertEqual(authenticated.pk, token.pk)

    def test_legacy_secret_key_token_hash_is_rekeyed_on_successful_authentication(self):
        # A token issued before GOGGLES_TOKEN_HASH_KEY existed is stored under
        # the SECRET_KEY fallback. Once a dedicated key is configured, the next
        # successful authentication should migrate that row to the dedicated key
        # so clients do not need a forced raw-token rotation.
        with override_settings(
            SECRET_KEY="current-signing-key",
            GOGGLES_TOKEN_HASH_KEY="current-signing-key",
        ):
            raw_token, token = UploadToken.issue("legacy device")
            legacy_hash = token.token_hash

        with override_settings(
            SECRET_KEY="current-signing-key",
            GOGGLES_TOKEN_HASH_KEY="fresh-dedicated-token-key",
        ):
            authenticated = UploadToken.authenticate(raw_token)
            token.refresh_from_db()
            migrated_hash = UploadToken.hash_secret(raw_token.split("_", 2)[2])

        self.assertIsNotNone(authenticated)
        self.assertEqual(authenticated.pk, token.pk)
        self.assertNotEqual(token.token_hash, legacy_hash)
        self.assertEqual(token.token_hash, migrated_hash)

    def test_rekeyed_legacy_token_survives_later_secret_key_rotation(self):
        with override_settings(
            SECRET_KEY="current-signing-key",
            GOGGLES_TOKEN_HASH_KEY="current-signing-key",
        ):
            raw_token, token = UploadToken.issue("legacy device")

        with override_settings(
            SECRET_KEY="current-signing-key",
            GOGGLES_TOKEN_HASH_KEY="fresh-dedicated-token-key",
        ):
            self.assertIsNotNone(UploadToken.authenticate(raw_token))

        with override_settings(
            SECRET_KEY="rotated-signing-key",
            GOGGLES_TOKEN_HASH_KEY="fresh-dedicated-token-key",
        ):
            authenticated = UploadToken.authenticate(raw_token)

        self.assertIsNotNone(authenticated)
        self.assertEqual(authenticated.pk, token.pk)

    def test_expired_legacy_token_is_rejected_without_rekeying(self):
        with override_settings(
            SECRET_KEY="current-signing-key",
            GOGGLES_TOKEN_HASH_KEY="current-signing-key",
        ):
            raw_token, token = UploadToken.issue(
                "expired legacy device",
                expires_at=timezone.now() - timedelta(minutes=1),
            )
            legacy_hash = token.token_hash

        with override_settings(
            SECRET_KEY="current-signing-key",
            GOGGLES_TOKEN_HASH_KEY="fresh-dedicated-token-key",
        ):
            authenticated = UploadToken.authenticate(raw_token)
            token.refresh_from_db()
            dedicated_hash = UploadToken.hash_secret(raw_token.split("_", 2)[2])

        self.assertIsNone(authenticated)
        self.assertEqual(token.token_hash, legacy_hash)
        self.assertNotEqual(token.token_hash, dedicated_hash)

    def test_foreign_key_token_hash_is_rejected_without_rekeying(self):
        with override_settings(
            SECRET_KEY="current-signing-key",
            GOGGLES_TOKEN_HASH_KEY="current-signing-key",
        ):
            raw_token, token = UploadToken.issue("foreign-key legacy device")
            secret = raw_token.split("_", 2)[2]
            foreign_key_hash = UploadToken.hash_secret(secret, key="neither-current-nor-legacy")
            token.token_hash = foreign_key_hash
            token.save(update_fields=["token_hash"])

        with override_settings(
            SECRET_KEY="current-signing-key",
            GOGGLES_TOKEN_HASH_KEY="fresh-dedicated-token-key",
        ):
            authenticated = UploadToken.authenticate(raw_token)
            token.refresh_from_db()

        self.assertIsNone(authenticated)
        self.assertEqual(token.token_hash, foreign_key_hash)


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

    @override_settings(
        GOGGLES_MAX_DUMP_BYTES=1024,
        DATA_UPLOAD_MAX_MEMORY_SIZE=1024,
        FILE_UPLOAD_MAX_MEMORY_SIZE=1024,
        DATA_UPLOAD_MAX_NUMBER_FILES=1,
    )
    def test_api_rejects_many_sub_threshold_files_without_saving(self):
        # Each individual part is comfortably under GOGGLES_MAX_DUMP_BYTES, so a
        # per-file cap alone would accept them and buffer their sum in memory.
        # DATA_UPLOAD_MAX_NUMBER_FILES=1 must reject the request before the view
        # body runs (regression for the multi-file memory-exhaustion bug).
        raw_token, _token = UploadToken.issue("ios test client")
        files = {
            f"audit_log_{index}": SimpleUploadedFile(
                f"audit-{index}.jsonl",
                b"x" * 100,
                content_type="application/x-ndjson",
            )
            for index in range(5)
        }

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=files,
            HTTP_AUTHORIZATION="Bearer " + raw_token,
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json()["error"], "audit log exceeds maximum upload size")
        self.assertEqual(AuditFile.objects.count(), 0)
        self.assertEqual(AuditEvent.objects.count(), 0)

    @override_settings(
        GOGGLES_MAX_DUMP_BYTES=150,
        DATA_UPLOAD_MAX_MEMORY_SIZE=1024,
        FILE_UPLOAD_MAX_MEMORY_SIZE=1024,
        DATA_UPLOAD_MAX_NUMBER_FILES=10,
    )
    def test_api_rejects_aggregate_over_cap_across_files_without_saving(self):
        # Defense in depth: even when the file *count* is allowed, the handler's
        # cumulative byte counter (not reset per file) must reject a request
        # whose parts each pass the per-file check but together exceed the cap.
        raw_token, _token = UploadToken.issue("ios test client")
        files = {
            f"audit_log_{index}": SimpleUploadedFile(
                f"audit-{index}.jsonl",
                b"x" * 100,
                content_type="application/x-ndjson",
            )
            for index in range(3)
        }

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=files,
            HTTP_AUTHORIZATION="Bearer " + raw_token,
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

    def test_upload_source_metadata_is_saved(self):
        # Account identity is backfilled from the body's source_context; only the
        # device label, platform, and app version still arrive as headers.
        raw_token, _token = UploadToken.issue("alice iphone")

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=representative_audit_log(
                source={"account_label": "Alice", "account_pubkey_hex": "aa" * 32}
            ),
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
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
                "account_pubkey_hex": "aa" * 32,
            },
        )

        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.source_account_label, "Alice")
        self.assertEqual(audit_file.source_account_pubkey_hex, "aa" * 32)
        self.assertEqual(audit_file.source_device_label, "Alice iPhone")
        self.assertEqual(audit_file.source_platform, "ios")
        self.assertEqual(audit_file.source_app_version, "2026.6.8")

    def test_upload_ignores_legacy_account_label_header(self):
        # The X-Goggles-Account-Label header is no longer read; identity must
        # come from the body. A stray header alongside a body label must not win.
        raw_token, _token = UploadToken.issue("legacy client")

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=representative_audit_log(source={"account_label": "Body Alice"}),
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
            HTTP_X_GOGGLES_ACCOUNT_LABEL="Header Alice",
        )

        self.assertEqual(response.status_code, 201)
        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.source_account_label, "Body Alice")

    def test_v2_upload_builds_audit_projections(self):
        raw_token, _token = UploadToken.issue("v2 test client")
        body = jsonl(
            audit_event_v2(
                0,
                kind={
                    "type": "transport_received",
                    "msg_id": MSG_ID,
                    "transport": {
                        "transport": "nostr",
                        "delivery_plane": "relay",
                        "relay_url": "wss://relay.example",
                        "nostr_event_id": DIGEST_A,
                        "nostr_kind": 445,
                        "welcome_nostr_event_id": DIGEST_B,
                        "welcome_rumor_event_id": DIGEST_A,
                        "welcome_key_package_tag": "kp:alice:1",
                    },
                    "payload_len": 42,
                    "payload_digest": DIGEST_A,
                },
            ),
            audit_event_v2(
                1,
                audit_data_mode="full_data",
                kind={
                    "type": "message_content_decoded",
                    "msg_id": MSG_ID,
                    "artifact_kind": "application_message",
                    "author": {
                        "member_ref": ACCOUNT_ALICE,
                        "account_pubkey_hex": "aa" * 32,
                    },
                    "decoded_payload": {
                        "content_type": "text/plain",
                        "text": "hello from Alice",
                    },
                    "decoded_app_event": {
                        "format": "nostr",
                        "kind": 445,
                        "content": "hello from Alice",
                        "pubkey_hex": "aa" * 32,
                    },
                },
            ),
            audit_event_v2(
                2,
                kind={
                    "type": "recipient_expectation",
                    "msg_id": MSG_ID,
                    "expectation": {
                        "artifact_kind": "application_message",
                        "recipient_scope": "all_other_current_group_members",
                        "membership_epoch": 7,
                        "expected_member_refs": [ACCOUNT_BOB],
                        "expected_pubkeys_hex": ["cc" * 32],
                        "expected_count": 2,
                    },
                },
            ),
            audit_event_v2(
                3,
                context={
                    "operation_id": "op-local-send",
                    "human_action": {
                        "action": "send_message",
                        "origin": "local_user",
                        "phase": "requested",
                        "message_ids": [OTHER_MSG_ID],
                    },
                },
                kind={
                    "type": "send_outcome",
                    "intent_kind": "send_message",
                    "result_kind": "published",
                    "outbound_messages": [
                        {
                            "msg_id": OTHER_MSG_ID,
                            "artifact_kind": "application_message",
                            "recipient_expectation": {
                                "artifact_kind": "application_message",
                                "recipient_scope": "all_other_current_group_members",
                                "expected_count": 1,
                            },
                        }
                    ],
                },
            ),
            audit_event_v2(
                4,
                context={"convergence": {"run_id": "run-1", "phase": "evaluating"}},
                kind={
                    "type": "convergence_run_state",
                    "phase": "evaluating",
                    "current_tip_epoch": 7,
                },
            ),
            audit_event_v2(
                5,
                context={"convergence": {"run_id": "run-1", "phase": "selected"}},
                kind={
                    "type": "convergence_decision",
                    "current_tip_epoch": 7,
                    "max_rewind_commits": 5,
                    "selected_branch_id": "branch-a",
                    "selected_fork_epoch": 6,
                    "selected_tip_epoch": 8,
                    "candidates": [
                        {
                            "branch_id": "branch-a",
                            "fork_epoch": 6,
                            "tip_epoch": 8,
                            "eligible": True,
                            "commit_ids": [MSG_ID],
                            "score": {
                                "valid_commit_depth": 2,
                                "effective_commit_depth": 2,
                                "witness_quorum_met": True,
                                "app_witness_score": 9,
                                "tip_priority": "app_witness",
                            },
                        },
                        {
                            "branch_id": "branch-b",
                            "fork_epoch": 6,
                            "tip_epoch": 7,
                            "eligible": False,
                            "rejection_reasons": ["lower_weight"],
                            "score": {
                                "valid_commit_depth": 1,
                                "effective_commit_depth": 1,
                                "witness_quorum_met": False,
                                "app_witness_score": 2,
                                "tip_priority": "stale",
                            },
                        },
                    ],
                    "rule_trace": [
                        {
                            "rule_name": "highest_weight",
                            "scope": "candidate_pair",
                            "candidate_branch_id": "branch-a",
                            "other_candidate_branch_id": "branch-b",
                            "inputs": {"branch_a_weight": 9, "branch_b_weight": 2},
                            "result": {"winner": "branch-a"},
                            "decisive": True,
                            "selected_branch_id": "branch-a",
                        }
                    ],
                },
            ),
            audit_event_v2(
                6,
                audit_data_mode="full_data",
                kind={
                    "type": "group_state_changed",
                    "epoch": 8,
                    "change_kind": "group_renamed",
                    "actor_member_ref": ACCOUNT_ALICE,
                    "origin_commit_id": MSG_ID,
                    "fields": ["name"],
                    "value": {"digest": DIGEST_B, "text": "Launch room"},
                },
            ),
            audit_event_v2(
                7,
                kind={
                    "type": "epoch_state_changed",
                    "previous_state": "pending",
                    "new_state": "committed",
                    "epoch": 8,
                    "reason": "winning_commit_applied",
                    "pending_ref": 8,
                    "pending_kind": "commit",
                },
            ),
            audit_event_v2(
                8,
                kind={
                    "type": "publish_failure",
                    "msg_id": MSG_ID,
                    "target_kind": "application_message",
                    "required_acks": 2,
                    "relay_url": "wss://relay.example",
                    "stage": "relay_publish",
                    "reason": "relay_error",
                },
            ),
            audit_event_v2(
                9,
                audit_data_mode="full_data",
                recorder_session_id="session-a-full",
                kind={
                    "type": "audit_data_mode_changed",
                    "previous_mode": "obfuscated_sensitive_data",
                    "new_mode": "full_data",
                    "reason": "forensic_capture_enabled",
                    "recorder_restarted": True,
                },
            ),
            audit_event_v2(
                10,
                audit_data_mode="full_data",
                context={
                    "operation_id": "op-system-recorder",
                    "human_action": {
                        "action": "background_sync",
                        "origin": "system",
                        "phase": "observed",
                    },
                    "source": {
                        "account_pubkey_hex": "aa" * 32,
                        "device_id": "device-1",
                        "device_name": "Alice MacBook",
                    },
                },
                kind={
                    "type": "recorder_health",
                    "serialization_failures": 0,
                    "write_failures": 0,
                    "flush_failures": 0,
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
        self.assertEqual(response.json()["schema_versions"], [SCHEMA_VERSION_V2])
        self.assertEqual(
            response.json()["audit_data_modes"],
            ["full_data", "obfuscated_sensitive_data"],
        )
        # Account pubkey is backfilled from the body's source_context.
        self.assertEqual(response.json()["source"]["account_pubkey_hex"], "aa" * 32)

        bob_response = self.client.post(
            reverse("api-audit-log-upload"),
            data=jsonl(
                audit_event_v2(
                    0,
                    engine_id=ENGINE_BOB,
                    account_ref=ACCOUNT_BOB,
                    recorder_session_id="session-b",
                    context={"source": {"account_label": "Bob", "device_name": "Bob laptop"}},
                    kind={"type": "recorder_started", "recorder": "mdk"},
                )
            ),
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )
        self.assertEqual(bob_response.status_code, 201)

        audit_file = AuditFile.objects.get(source_account_pubkey_hex="aa" * 32)
        self.assertEqual(audit_file.source_account_pubkey_hex, "aa" * 32)

        group = AuditGroup.objects.get(slug=GROUP_REF)
        artifact = DeliveryArtifact.objects.get(group=group, artifact_id=MSG_ID)
        self.assertEqual(artifact.artifact_kind, "application_message")
        self.assertEqual(artifact.decoded_payload["text"], "hello from Alice")
        self.assertEqual(artifact.recipient_expectations.get().expected_count, 2)
        self.assertEqual(DeliveryArtifact.objects.filter(group=group).count(), 2)
        self.assertEqual(
            NetworkObservation.objects.get(group=group, phase="transport_received").relay_url,
            "wss://relay.example",
        )
        run = ConvergenceRun.objects.get(group=group, run_id="run-1")
        self.assertEqual(run.selected_branch_id, "branch-a")
        self.assertEqual(ConvergenceCandidate.objects.filter(run=run).count(), 2)
        self.assertEqual(ConvergenceRuleEvaluation.objects.get(run=run).rule_name, "highest_weight")
        self.assertEqual(StateDelta.objects.get(group=group).value["text"], "Launch room")
        self.assertEqual(EpochStateTransition.objects.get(group=group).new_state, "committed")

        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")
        with CaptureQueriesContext(connection) as projection_api_queries:
            api_response = self.client.get(
                reverse("api-group-projections", kwargs={"slug": group.slug}),
                {"engine_id": ENGINE_ALICE},
            )

        self.assertEqual(api_response.status_code, 200)
        payload = api_response.json()
        self.assertEqual(
            heavy_bulk_selects(
                projection_api_queries.captured_queries,
                allowed_columns=(
                    HEAVY_EVENT_SELECT_COLUMNS["raw_kind"],
                    HEAVY_EVENT_SELECT_COLUMNS["context_source"],
                ),
            ),
            [],
        )
        self.assertEqual(payload["schema_version"], "goggles-audit-projections/v1")
        self.assertEqual(payload["filters"]["engine_id"], ENGINE_ALICE)
        self.assertEqual(payload["pagination"]["delivery_artifacts"]["limit"], 100)
        self.assertEqual(
            payload["delivery_artifacts"][0]["decoded_payload"]["text"], "hello from Alice"
        )
        self.assertIn(
            "decoded_payload",
            payload["delivery_artifacts"][0]["sensitivity"]["sensitive_field_paths"],
        )
        self.assertEqual(payload["network_observations"][0]["relay_url"], "wss://relay.example")
        self.assertEqual(
            payload["network_observations"][0]["welcome_nostr_event_id"],
            DIGEST_B,
        )
        self.assertEqual(
            payload["network_observations"][0]["welcome_rumor_event_id"],
            DIGEST_A,
        )
        self.assertEqual(
            payload["network_observations"][0]["welcome_key_package_tag"],
            "kp:alice:1",
        )
        self.assertIn(
            "nostr_event_id",
            payload["network_observations"][0]["sensitivity"]["sensitive_field_paths"],
        )
        self.assertIn(
            "welcome_nostr_event_id",
            payload["network_observations"][0]["sensitivity"]["sensitive_field_paths"],
        )
        self.assertEqual(payload["convergence_runs"][0]["selected_branch_id"], "branch-a")
        self.assertEqual(payload["state_deltas"][0]["value"]["text"], "Launch room")
        mode_change = payload["audit_data_mode_changes"][0]
        self.assertEqual(mode_change["previous_mode"], "obfuscated_sensitive_data")
        self.assertEqual(mode_change["new_mode"], "full_data")
        self.assertEqual(mode_change["reason"], "forensic_capture_enabled")
        self.assertTrue(mode_change["recorder_restarted"])
        self.assertEqual(mode_change["severity"], "warning")
        self.assertTrue(mode_change["evidence_ref"])
        self.assertEqual(
            payload["action_attribution"]["user_actions"][0]["action"],
            "send_message",
        )
        self.assertEqual(
            payload["pagination"]["action_attribution"]["user_actions"]["returned"],
            1,
        )

        group_response = self.client.get(reverse("api-group-detail", kwargs={"slug": group.slug}))
        self.assertEqual(group_response.status_code, 200)
        self.assertTrue(group_response.json()["classification"]["contains_full_data"])

        group_list_response = self.client.get(reverse("api-group-list"))
        self.assertEqual(group_list_response.status_code, 200)
        self.assertEqual(group_list_response.json()["groups"][0]["slug"], group.slug)

        delivery_page_response = self.client.get(
            reverse("api-group-delivery", kwargs={"slug": group.slug}),
            {"limit": "1", "offset": "0"},
        )
        self.assertEqual(delivery_page_response.status_code, 200)
        self.assertEqual(delivery_page_response.json()["pagination"]["returned"], 1)
        self.assertTrue(delivery_page_response.json()["pagination"]["has_more"])
        self.assertEqual(delivery_page_response.json()["pagination"]["next_offset"], 1)

        delivery_all_response = self.client.get(
            reverse("api-group-delivery", kwargs={"slug": group.slug})
        )
        self.assertEqual(delivery_all_response.status_code, 200)
        delivery_by_id = {
            artifact["artifact_id"]: artifact
            for artifact in delivery_all_response.json()["delivery_artifacts"]
        }
        send_count_row = next(
            row
            for row in delivery_by_id[OTHER_MSG_ID]["recipient_matrix"]
            if row["recipient_type"] == "count_only"
        )
        self.assertEqual(send_count_row["status"], "missing_count_inferred")
        self.assertEqual(send_count_row["expected_count"], 1)
        self.assertEqual(send_count_row["observed_count"], 0)
        self.assertEqual(send_count_row["missing_count"], 1)
        self.assertEqual(send_count_row["excluded_observation_count"], 1)
        self.assertEqual(delivery_by_id[OTHER_MSG_ID]["severity"], "warning")

        delivery_warning_response = self.client.get(
            reverse("api-group-delivery", kwargs={"slug": group.slug}),
            {"severity": "warning"},
        )
        self.assertEqual(delivery_warning_response.status_code, 200)
        warning_artifacts = delivery_warning_response.json()["delivery_artifacts"]
        self.assertCountEqual(
            [artifact["artifact_id"] for artifact in warning_artifacts],
            [MSG_ID, OTHER_MSG_ID],
        )
        self.assertTrue(all(artifact["severity"] == "warning" for artifact in warning_artifacts))

        delivery_response = self.client.get(
            reverse("api-group-delivery", kwargs={"slug": group.slug}),
            {"audit_data_mode": "full_data"},
        )
        self.assertEqual(delivery_response.status_code, 200)
        delivery_payload = delivery_response.json()
        self.assertEqual(len(delivery_payload["delivery_artifacts"]), 1)
        delivery_artifact = delivery_payload["delivery_artifacts"][0]
        self.assertEqual(delivery_artifact["artifact_id"], MSG_ID)
        self.assertTrue(delivery_artifact["evidence_refs"])
        self.assertTrue(delivery_artifact["engine_observations"][0]["evidence_refs"])
        self.assertTrue(delivery_artifact["recipient_expectations"][0]["evidence_ref"])
        self.assertTrue(delivery_artifact["sensitivity"]["contains_full_data"])
        self.assertEqual(
            delivery_artifact["sensitivity"]["authorization"]["required"],
            "authenticated_internal_user",
        )
        self.assertIn(
            "decoded_app_event",
            delivery_artifact["sensitivity"]["sensitive_field_paths"],
        )
        observation_states = {
            state["state"]: state for state in delivery_artifact["engine_observations"][0]["states"]
        }
        self.assertTrue(observation_states["transport_received"]["evidence_ref"])
        self.assertTrue(observation_states["decoded"]["evidence_ref"])
        self.assertTrue(observation_states["publish:failed"]["evidence_ref"])
        matrix = {
            (row["recipient_type"], row["recipient_id"]): row
            for row in delivery_artifact["recipient_matrix"]
        }
        self.assertEqual(matrix[("member_ref", ACCOUNT_BOB)]["status"], "missing_inferred")
        self.assertEqual(
            matrix[("pubkey_hex", "cc" * 32)]["status"],
            "unobserved_no_uploaded_engine",
        )
        self.assertTrue(
            any(
                row["status"] == "observed_not_expected"
                for row in delivery_artifact["recipient_matrix"]
            )
        )

        delivery_detail_response = self.client.get(
            reverse(
                "api-group-delivery-artifact",
                kwargs={"slug": group.slug, "artifact_id": MSG_ID},
            )
        )
        self.assertEqual(delivery_detail_response.status_code, 200)
        self.assertEqual(
            delivery_detail_response.json()["delivery_artifact"]["decoded_payload"]["text"],
            "hello from Alice",
        )
        delivery_tab_response = self.client.get(
            reverse("group-tab", kwargs={"slug": group.slug, "tab": "delivery"})
        )
        message_trace_url = reverse("api-message-detail", kwargs={"message_id": MSG_ID})
        other_message_trace_url = reverse(
            "api-message-detail",
            kwargs={"message_id": OTHER_MSG_ID},
        )
        self.assertContains(delivery_tab_response, "missing inferred")
        self.assertContains(delivery_tab_response, "missing count inferred")
        self.assertContains(delivery_tab_response, "0/1 observed")
        self.assertContains(delivery_tab_response, "no uploaded engine")
        self.assertContains(delivery_tab_response, "delivery gap inferred")
        self.assertContains(delivery_tab_response, "Engine delivery matrix")
        self.assertContains(delivery_tab_response, "Alice MacBook")
        self.assertContains(delivery_tab_response, "Bob laptop")
        self.assertContains(delivery_tab_response, "decrypted content")
        self.assertContains(delivery_tab_response, message_trace_url)
        self.assertContains(delivery_tab_response, "/api/v1/events/")
        self.assertContains(delivery_tab_response, "Engine state trail")
        self.assertContains(delivery_tab_response, "publish:failed")

        network_response = self.client.get(
            reverse("api-group-network", kwargs={"slug": group.slug}),
            {"message_id": MSG_ID},
        )
        self.assertEqual(network_response.status_code, 200)
        self.assertEqual(network_response.json()["network_observations"][0]["message_id"], MSG_ID)
        self.assertTrue(network_response.json()["network_observations"][0]["evidence_ref"])

        network_tab_response = self.client.get(
            reverse("group-tab", kwargs={"slug": group.slug, "tab": "network"})
        )
        self.assertContains(network_tab_response, message_trace_url)
        self.assertContains(network_tab_response, "/api/v1/events/")

        network_error_response = self.client.get(
            reverse("api-group-network", kwargs={"slug": group.slug}),
            {"severity": "error"},
        )
        self.assertEqual(network_error_response.status_code, 200)
        error_network = network_error_response.json()["network_observations"]
        self.assertEqual(len(error_network), 1)
        self.assertEqual(error_network[0]["phase"], "publish_failure")
        self.assertEqual(error_network[0]["severity"], "error")

        convergence_response = self.client.get(
            reverse("api-group-convergence-runs", kwargs={"slug": group.slug})
        )
        self.assertEqual(convergence_response.status_code, 200)
        self.assertEqual(
            convergence_response.json()["convergence_runs"][0]["rule_evaluations"][0]["rule_name"],
            "highest_weight",
        )
        convergence_payload = convergence_response.json()["convergence_runs"][0]
        candidate_scores = {
            candidate["branch_id"]: candidate["score"]
            for candidate in convergence_payload["candidates"]
        }
        self.assertEqual(candidate_scores["branch-a"]["app_witness_score"], 9)
        self.assertTrue(convergence_payload["evidence_refs"])
        self.assertTrue(convergence_payload["candidates"][0]["evidence_refs"])
        self.assertTrue(convergence_payload["rule_evaluations"][0]["evidence_refs"])

        convergence_message_response = self.client.get(
            reverse("api-group-convergence-runs", kwargs={"slug": group.slug}),
            {"message_id": MSG_ID},
        )
        self.assertEqual(convergence_message_response.status_code, 200)
        self.assertEqual(
            convergence_message_response.json()["convergence_runs"][0]["run_id"],
            "run-1",
        )

        convergence_epoch_response = self.client.get(
            reverse("api-group-convergence-runs", kwargs={"slug": group.slug}),
            {"epoch": "6"},
        )
        self.assertEqual(convergence_epoch_response.status_code, 200)
        self.assertEqual(
            convergence_epoch_response.json()["convergence_runs"][0]["selected_branch_id"],
            "branch-a",
        )

        convergence_miss_response = self.client.get(
            reverse("api-group-convergence-runs", kwargs={"slug": group.slug}),
            {"message_id": OTHER_MSG_ID},
        )
        self.assertEqual(convergence_miss_response.status_code, 200)
        self.assertEqual(convergence_miss_response.json()["convergence_runs"], [])

        convergence_tab_response = self.client.get(
            reverse("group-tab", kwargs={"slug": group.slug, "tab": "convergence"})
        )
        self.assertContains(convergence_tab_response, "branch-graph")
        self.assertContains(convergence_tab_response, "selected")
        self.assertContains(convergence_tab_response, "rejected")
        self.assertContains(convergence_tab_response, message_trace_url)
        self.assertContains(convergence_tab_response, "/api/v1/events/")
        self.assertContains(convergence_tab_response, "Candidate scoring")
        self.assertContains(convergence_tab_response, "app witness 9")
        self.assertContains(convergence_tab_response, "Rule trace")
        self.assertContains(convergence_tab_response, "branch_a_weight 9")
        self.assertContains(convergence_tab_response, "winner branch-a")

        convergence_detail_response = self.client.get(
            reverse(
                "api-group-convergence-run",
                kwargs={"slug": group.slug, "run_id": "run-1"},
            )
        )
        self.assertEqual(convergence_detail_response.status_code, 200)
        self.assertEqual(
            convergence_detail_response.json()["convergence_run"]["selected_branch_id"],
            "branch-a",
        )

        state_response = self.client.get(
            reverse("api-group-state", kwargs={"slug": group.slug}),
            {"epoch": "8"},
        )
        self.assertEqual(state_response.status_code, 200)
        state_payload = state_response.json()
        self.assertEqual(state_payload["state_deltas"][0]["change_kind"], "group_renamed")
        self.assertTrue(state_payload["state_deltas"][0]["evidence_ref"])
        self.assertTrue(state_payload["state_deltas"][0]["sensitivity"]["contains_full_data"])
        self.assertIn(
            "value.text",
            state_payload["state_deltas"][0]["sensitivity"]["sensitive_field_paths"],
        )
        self.assertTrue(state_payload["epoch_state_transitions"][0]["evidence_ref"])

        state_message_response = self.client.get(
            reverse("api-group-state", kwargs={"slug": group.slug}),
            {"message_id": MSG_ID},
        )
        self.assertEqual(state_message_response.status_code, 200)
        self.assertEqual(
            state_message_response.json()["state_deltas"][0]["origin_commit_id"],
            MSG_ID,
        )
        self.assertEqual(state_message_response.json()["epoch_state_transitions"], [])

        state_other_message_response = self.client.get(
            reverse("api-group-state", kwargs={"slug": group.slug}),
            {"message_id": OTHER_MSG_ID},
        )
        self.assertEqual(state_other_message_response.status_code, 200)
        self.assertEqual(state_other_message_response.json()["state_deltas"], [])

        state_bob_response = self.client.get(
            reverse("api-group-state", kwargs={"slug": group.slug}),
            {"engine_id": ENGINE_BOB},
        )
        self.assertEqual(state_bob_response.status_code, 200)
        self.assertEqual(state_bob_response.json()["state_deltas"], [])

        state_tab_response = self.client.get(
            reverse("group-tab", kwargs={"slug": group.slug, "tab": "state"})
        )
        self.assertContains(state_tab_response, "full data")
        self.assertContains(state_tab_response, message_trace_url)
        self.assertContains(state_tab_response, "/api/v1/events/")

        projection_download_response = self.client.get(
            reverse("api-group-projections", kwargs={"slug": group.slug}),
            {"download": "1"},
        )
        self.assertEqual(projection_download_response.status_code, 200)
        self.assertIn("attachment", projection_download_response["Content-Disposition"])

        agent_export_response = self.client.get(
            reverse("group-agent-export", kwargs={"slug": group.slug})
        )
        self.assertEqual(agent_export_response.status_code, 200)
        self.assertEqual(
            agent_export_response.json()["derived_projections"]["delivery_artifacts"][0][
                "artifact_id"
            ],
            MSG_ID,
        )
        self.assertEqual(
            agent_export_response.json()["derived_projections"]["action_attribution"][
                "user_actions"
            ][0]["action"],
            "send_message",
        )

        exports_tab_response = self.client.get(
            reverse("group-tab", kwargs={"slug": group.slug, "tab": "exports"})
        )
        self.assertContains(exports_tab_response, "Download JSON")
        self.assertContains(exports_tab_response, "Actions")
        self.assertContains(exports_tab_response, "Full data auditing evidence is present")
        self.assertContains(exports_tab_response, "Saved reports")

        save_report_response = self.client.post(
            reverse("create-saved-report", kwargs={"slug": group.slug}),
            {
                "title": "Launch room report",
                "notes": "Alice send path and convergence look correct.",
            },
        )
        saved_report = AnalysisRun.objects.get(group=group)
        self.assertRedirects(
            save_report_response,
            reverse("saved-report-detail", kwargs={"pk": saved_report.pk}),
        )
        self.assertEqual(saved_report.created_by.username, "analyst")
        self.assertEqual(saved_report.title, "Launch room report")
        self.assertEqual(saved_report.notes, "Alice send path and convergence look correct.")
        self.assertEqual(
            saved_report.report_json["projection"]["delivery_artifacts"][0]["artifact_id"],
            MSG_ID,
        )
        self.assertEqual(
            saved_report.report_json["projection"]["action_attribution"]["system_attribution"][0][
                "action"
            ],
            "background_sync",
        )

        saved_report_response = self.client.get(
            reverse("saved-report-detail", kwargs={"pk": saved_report.pk})
        )
        self.assertContains(saved_report_response, "Launch room report")
        self.assertContains(saved_report_response, "Alice send path")
        self.assertContains(saved_report_response, "Audit mode changes")
        self.assertContains(saved_report_response, "User actions")
        self.assertContains(saved_report_response, "System attribution")

        saved_report_json_response = self.client.get(
            reverse("saved-report-json", kwargs={"pk": saved_report.pk})
        )
        self.assertEqual(saved_report_json_response.status_code, 200)
        self.assertEqual(
            saved_report_json_response.json()["schema_version"],
            "goggles-saved-investigation/v1",
        )

        engines_response = self.client.get(
            reverse("api-group-engines", kwargs={"slug": group.slug})
        )
        self.assertEqual(engines_response.status_code, 200)
        engines_by_id = {
            engine["engine_id"]: engine for engine in engines_response.json()["engines"]
        }
        self.assertEqual(engines_response.json()["engines"][0]["engine_id"], ENGINE_ALICE)
        self.assertEqual(
            engines_by_id[ENGINE_ALICE]["source_metadata"]["device_ids"],
            ["device-1"],
        )
        self.assertEqual(
            engines_by_id[ENGINE_ALICE]["source_metadata"]["device_names"],
            ["Alice MacBook"],
        )
        self.assertEqual(
            engines_by_id[ENGINE_ALICE]["source_metadata"]["account_pubkeys_hex"],
            ["aa" * 32],
        )
        self.assertIn(
            "source_metadata.account_pubkeys_hex",
            engines_by_id[ENGINE_ALICE]["sensitivity"]["sensitive_field_paths"],
        )
        self.assertEqual(
            engines_by_id[ENGINE_BOB]["source_metadata"]["account_labels"],
            ["Bob"],
        )
        self.assertEqual(
            engines_by_id[ENGINE_BOB]["source_metadata"]["device_names"],
            ["Bob laptop"],
        )

        actions_response = self.client.get(
            reverse("api-group-actions", kwargs={"slug": group.slug})
        )
        self.assertEqual(actions_response.status_code, 200)
        actions_payload = actions_response.json()
        self.assertEqual(actions_payload["schema_version"], "goggles-action-attribution/v1")
        origin_counts = {
            row["origin"]: (row["attribution_kind"], row["count"])
            for row in actions_payload["origin_counts"]
        }
        self.assertEqual(origin_counts["local_user"], ("user", 1))
        self.assertEqual(origin_counts["system"], ("system", 1))
        user_action = actions_payload["user_actions"][0]
        self.assertEqual(user_action["attribution_kind"], "user")
        self.assertEqual(user_action["origin"], "local_user")
        self.assertEqual(user_action["action"], "send_message")
        self.assertEqual(user_action["message_ids"], [OTHER_MSG_ID])
        self.assertEqual(user_action["events"][0]["event_type"], "send_outcome")
        self.assertTrue(user_action["evidence_refs"])
        self.assertNotIn("raw_line", user_action["events"][0])
        system_action = actions_payload["system_attribution"][0]
        self.assertEqual(system_action["attribution_kind"], "system")
        self.assertEqual(system_action["origin"], "system")
        self.assertEqual(system_action["action"], "background_sync")
        self.assertEqual(system_action["events"][0]["event_type"], "recorder_health")

        system_actions_response = self.client.get(
            reverse("api-group-actions", kwargs={"slug": group.slug}),
            {"origin": "system"},
        )
        self.assertEqual(system_actions_response.status_code, 200)
        self.assertEqual(system_actions_response.json()["user_actions"], [])
        self.assertEqual(
            system_actions_response.json()["system_attribution"][0]["action"],
            "background_sync",
        )

        message_actions_response = self.client.get(
            reverse("api-group-actions", kwargs={"slug": group.slug}),
            {"message_id": OTHER_MSG_ID},
        )
        self.assertEqual(message_actions_response.status_code, 200)
        self.assertEqual(
            message_actions_response.json()["user_actions"][0]["action"], "send_message"
        )
        self.assertEqual(message_actions_response.json()["system_attribution"], [])

        system_projection_response = self.client.get(
            reverse("api-group-projections", kwargs={"slug": group.slug}),
            {"origin": "system"},
        )
        self.assertEqual(system_projection_response.status_code, 200)
        self.assertEqual(
            system_projection_response.json()["action_attribution"]["user_actions"],
            [],
        )
        self.assertEqual(
            system_projection_response.json()["action_attribution"]["system_attribution"][0][
                "action"
            ],
            "background_sync",
        )

        overview_response = self.client.get(
            reverse("group-tab", kwargs={"slug": group.slug, "tab": "overview"})
        )
        self.assertContains(overview_response, "Engines and devices")
        self.assertContains(overview_response, "Action attribution")
        self.assertContains(overview_response, "User actions")
        self.assertContains(overview_response, "System attribution")
        self.assertContains(overview_response, "Send Message")
        self.assertContains(overview_response, other_message_trace_url)
        self.assertContains(overview_response, "Background Sync")
        self.assertContains(overview_response, "Audit data mode changes")
        self.assertContains(overview_response, "forensic_capture_enabled")
        self.assertContains(overview_response, "session-a-full")
        self.assertContains(overview_response, "Alice MacBook")
        self.assertContains(overview_response, "device-1")
        self.assertContains(overview_response, "Bob laptop")

        account_groups_response = self.client.get(
            reverse("api-account-groups", kwargs={"account_ref": ACCOUNT_ALICE})
        )
        self.assertEqual(account_groups_response.status_code, 200)
        self.assertEqual(account_groups_response.json()["groups"][0]["slug"], group.slug)

        account_investigation_response = self.client.get(
            reverse("account-investigation", kwargs={"account_ref": ACCOUNT_ALICE})
        )
        self.assertEqual(account_investigation_response.status_code, 200)
        self.assertContains(account_investigation_response, "Cross-group investigation")
        self.assertContains(account_investigation_response, ACCOUNT_ALICE)
        self.assertContains(account_investigation_response, "Open JSON")

        engine_groups_response = self.client.get(
            reverse("api-engine-groups", kwargs={"engine_id": ENGINE_ALICE})
        )
        self.assertEqual(engine_groups_response.status_code, 200)
        self.assertEqual(engine_groups_response.json()["groups"][0]["slug"], group.slug)

        engine_investigation_response = self.client.get(
            reverse("engine-investigation", kwargs={"engine_id": ENGINE_ALICE})
        )
        self.assertEqual(engine_investigation_response.status_code, 200)
        self.assertContains(engine_investigation_response, ENGINE_ALICE)
        self.assertContains(engine_investigation_response, "Export")

        evidence_list_response = self.client.get(
            reverse("api-group-evidence", kwargs={"slug": group.slug}),
            {"event_type": "audit_data_mode_changed"},
        )
        self.assertEqual(evidence_list_response.status_code, 200)
        evidence_list_payload = evidence_list_response.json()
        self.assertEqual(evidence_list_payload["schema_version"], "goggles-evidence-list/v1")
        self.assertEqual(evidence_list_payload["pagination"]["returned"], 1)
        evidence_row = evidence_list_payload["evidence"][0]
        self.assertEqual(evidence_row["event_type"], "audit_data_mode_changed")
        self.assertTrue(evidence_row["evidence_ref"]["line_hash"])
        self.assertTrue(evidence_row["evidence_ref"]["api_path"])
        self.assertIn("source_file", evidence_row)
        self.assertNotIn("raw_line", evidence_row)
        self.assertNotIn("raw_event", evidence_row)

        evidence_tab_response = self.client.get(
            reverse("group-tab", kwargs={"slug": group.slug, "tab": "evidence"})
        )
        self.assertContains(
            evidence_tab_response, reverse("api-group-evidence", kwargs={"slug": group.slug})
        )
        self.assertContains(evidence_tab_response, message_trace_url)
        self.assertContains(evidence_tab_response, "JSON")

        evidence_response = self.client.get(delivery_artifact["evidence_refs"][0]["api_path"])
        self.assertEqual(evidence_response.status_code, 200)
        self.assertEqual(evidence_response.json()["evidence_ref"]["audit_file_id"], audit_file.id)
        self.assertIn(
            "raw_line",
            evidence_response.json()["sensitivity"]["sensitive_field_paths"],
        )
        self.assertIn("raw_line", evidence_response.json()["event"])

    def test_v3_upload_builds_safe_only_projections_and_v2_still_uploads(self):
        raw_token, _token = UploadToken.issue("v2 and v3 test client")
        v3_body = jsonl(
            audit_event_v3(
                0,
                kind={
                    "type": "source_context",
                    "source": {
                        "account_label": "Alice",
                        "device_name": "Alice laptop",
                        "platform": "macos",
                    },
                },
            ),
            audit_event_v3(
                1,
                kind={
                    "type": "transport_received",
                    "msg_id": MSG_ID,
                    "transport": {
                        "transport": "nostr",
                        "delivery_plane": "relay",
                        "relay_url": "wss://relay.example",
                        "nostr_event_id": DIGEST_A,
                    },
                    "payload_len": 42,
                    "payload_digest": DIGEST_B,
                },
            ),
            audit_event_v3(
                2,
                kind={
                    "type": "recipient_expectation",
                    "msg_id": MSG_ID,
                    "expectation": {
                        "artifact_kind": "application_message",
                        "recipient_scope": "all_other_current_group_members",
                        "membership_epoch": 7,
                        "expected_member_refs": [ACCOUNT_BOB],
                        "expected_count": 1,
                    },
                },
            ),
            audit_event_v3(
                3,
                context={"convergence": {"run_id": "run-v3", "phase": "selected"}},
                kind={
                    "type": "convergence_decision",
                    "current_tip_epoch": 7,
                    "max_rewind_commits": 5,
                    "selected_branch_id": "branch-a",
                    "selected_fork_epoch": 6,
                    "selected_tip_epoch": 8,
                    "decisive_rule": "witness_quorum_met",
                    "candidates": [
                        {
                            "branch_id": "branch-a",
                            "fork_epoch": 6,
                            "tip_epoch": 8,
                            "eligible": True,
                            "commit_ids": [MSG_ID],
                            "score": {
                                "valid_commit_depth": 2,
                                "witness_quorum_met": True,
                            },
                        }
                    ],
                },
            ),
            audit_event_v3(
                4,
                kind={
                    "type": "group_state_changed",
                    "epoch": 8,
                    "change_kind": "group_disbanded",
                    "origin_commit_id": MSG_ID,
                    "fields": ["group_status"],
                    "value": {"digest": DIGEST_A, "len": 9},
                },
            ),
            audit_event_v3(
                5,
                kind={
                    "type": "sync_drain",
                    "duration_ms": 25,
                    "deliveries": 3,
                    "skipped": 1,
                },
            ),
        )

        v3_response = self.client.post(
            reverse("api-audit-log-upload"),
            data=v3_body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(v3_response.status_code, 201)
        self.assertEqual(v3_response.json()["schema_versions"], [SCHEMA_VERSION_V3])
        self.assertEqual(v3_response.json()["audit_data_modes"], ["safe_only"])
        self.assertEqual(v3_response.json()["source"]["account_label"], "Alice")
        v3_file = AuditFile.objects.get(schema_versions=[SCHEMA_VERSION_V3])
        self.assertEqual(v3_file.validation_status, AuditFile.STATUS_VALID)
        self.assertNotIn("audit_data_mode", v3_file.events.first().raw_event)
        self.assertTrue(
            v3_file.events.filter(
                event_type="sync_drain",
                parse_status=AuditEvent.STATUS_VALID,
            ).exists()
        )

        group = AuditGroup.objects.get(slug=GROUP_REF)
        artifact = DeliveryArtifact.objects.get(group=group, artifact_id=MSG_ID)
        self.assertEqual(artifact.audit_data_modes, ["safe_only"])
        self.assertEqual(artifact.recipient_expectations.get().expected_member_refs, [ACCOUNT_BOB])
        self.assertEqual(
            NetworkObservation.objects.get(group=group, phase="transport_received").relay_url,
            "wss://relay.example",
        )
        run = ConvergenceRun.objects.get(group=group, run_id="run-v3")
        self.assertEqual(run.selected_branch_id, "branch-a")
        decisive_rule = ConvergenceRuleEvaluation.objects.get(run=run)
        self.assertEqual(decisive_rule.rule_name, "witness_quorum_met")
        self.assertTrue(decisive_rule.decisive)
        self.assertEqual(decisive_rule.selected_branch_id, "branch-a")
        delta = StateDelta.objects.get(group=group)
        self.assertEqual(delta.change_kind, "group_disbanded")
        self.assertEqual(delta.value, {"digest": DIGEST_A, "len": 9})
        self.assertEqual(delta.audit_data_mode, "safe_only")

        v2_response = self.client.post(
            reverse("api-audit-log-upload"),
            data=jsonl(
                audit_event_v2(
                    0,
                    engine_id=ENGINE_BOB,
                    account_ref=ACCOUNT_BOB,
                    kind={"type": "recorder_started", "recorder": "jsonl"},
                )
            ),
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(v2_response.status_code, 201)
        self.assertEqual(v2_response.json()["schema_versions"], [SCHEMA_VERSION_V2])
        self.assertEqual(v2_response.json()["audit_data_modes"], ["obfuscated_sensitive_data"])
        self.assertEqual(AuditFile.objects.filter(groups=group).count(), 2)

    def test_v3_only_peeler_outcomes_preserve_v2_validation(self):
        for outcome in ("invalid_signature", "wrong_recipient"):
            kind = {
                "type": "peeler_outcome",
                "msg_id": MSG_ID,
                "outcome": outcome,
                "fallback_snapshot_used": False,
            }
            with self.subTest(schema_version=SCHEMA_VERSION_V3, outcome=outcome):
                normalized, errors = ingest_module.normalize_event(audit_event_v3(0, kind=kind))
                self.assertEqual(errors, [])
                self.assertEqual(normalized["outcome"], outcome)

            with self.subTest(schema_version=SCHEMA_VERSION_V2, outcome=outcome):
                _normalized, errors = ingest_module.normalize_event(audit_event_v2(0, kind=kind))
                self.assertIn("outcome must be a known peeler outcome", errors)

    def test_v2_message_ids_must_be_canonical_64_hex_ids(self):
        raw_token, _token = UploadToken.issue("v2 strict message ids")
        body = jsonl(
            audit_event_v2(
                0,
                kind={
                    "type": "message_state_changed",
                    "msg_id": "abcd",
                    "new_state": "processed",
                    "reason": "short_id_regression",
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
        self.assertIn("msg_id must be 64 hex characters", response.json()["error"])
        event = AuditEvent.objects.get()
        self.assertEqual(event.msg_id, "")
        self.assertEqual(event.raw_event["kind"]["msg_id"], "abcd")

    def test_v3_message_ids_must_be_canonical_64_hex_ids(self):
        raw_token, _token = UploadToken.issue("v3 strict message ids")
        body = jsonl(
            audit_event_v3(
                0,
                kind={
                    "type": "message_state_changed",
                    "msg_id": "abcd",
                    "new_state": "processed",
                    "reason": "short_id_regression",
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
        self.assertIn("msg_id must be 64 hex characters", response.json()["error"])
        event = AuditEvent.objects.get()
        self.assertEqual(event.audit_data_mode, "safe_only")
        self.assertEqual(event.msg_id, "")
        self.assertEqual(event.raw_event["kind"]["msg_id"], "abcd")

    def test_context_subobjects_must_be_objects_when_present(self):
        raw_token, _token = UploadToken.issue("v2 strict context")
        body = jsonl(
            audit_event_v2(
                0,
                context={"source": "alice laptop", "convergence": ["run-1"]},
                kind={"type": "recorder_started", "recorder": "mdk"},
            )
        )

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 400)
        error = response.json()["error"]
        self.assertIn("context.source must be an object when present", error)
        self.assertIn("context.convergence must be an object when present", error)
        event = AuditEvent.objects.get()
        self.assertEqual(event.context_source, {})
        self.assertEqual(event.context_convergence, {})
        self.assertEqual(event.raw_context["source"], "alice laptop")

    def test_v2_state_delta_preserves_membership_change_source(self):
        raw_token, _token = UploadToken.issue("v2 membership source")
        body = jsonl(
            audit_event_v2(
                0,
                audit_data_mode="full_data",
                kind={
                    "type": "group_state_changed",
                    "epoch": 8,
                    "change_kind": "member_removed",
                    "membership_change_source": "convergence",
                    "subject_member_ref": ACCOUNT_BOB,
                    "origin_commit_id": MSG_ID,
                    "fields": ["members"],
                },
            )
        )

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 201)
        group = AuditGroup.objects.get(slug=GROUP_REF)
        delta = StateDelta.objects.get(group=group)
        self.assertEqual(delta.change_kind, "member_removed")
        self.assertEqual(delta.membership_change_source, "convergence")

        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")
        state_response = self.client.get(reverse("api-group-state", kwargs={"slug": group.slug}))
        self.assertEqual(
            state_response.json()["state_deltas"][0]["membership_change_source"],
            "convergence",
        )
        state_tab_response = self.client.get(
            reverse("group-tab", kwargs={"slug": group.slug, "tab": "state"})
        )
        self.assertContains(state_tab_response, "convergence")

    def test_publish_failure_projects_scalar_relay_url(self):
        raw_token, _token = UploadToken.issue("v2 relay scalar")
        body = jsonl(
            audit_event_v2(
                0,
                kind={
                    "type": "publish_failure",
                    "msg_id": MSG_ID,
                    "artifact_kind": "application_message",
                    "target_kind": "event",
                    "stage": "publish",
                    "reason": "timeout",
                    "relay_url": "wss://relay.scalar.example",
                },
            )
        )

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 201)
        observation = NetworkObservation.objects.get(phase="publish_failure")
        self.assertEqual(observation.relay_url, "wss://relay.scalar.example")

    def test_api_message_detail_returns_matches_across_groups(self):
        raw_token, _token = UploadToken.issue("message lookup client")

        def upload_message_event(seq, group_ref, engine_id, account_ref):
            response = self.client.post(
                reverse("api-audit-log-upload"),
                data=jsonl(
                    audit_event_v2(
                        seq,
                        group_ref=group_ref,
                        engine_id=engine_id,
                        account_ref=account_ref,
                        kind={
                            "type": "transport_received",
                            "msg_id": MSG_ID,
                            "transport": {
                                "transport": "nostr",
                                "delivery_plane": "relay",
                                "relay_url": "wss://relay.example",
                                "nostr_event_id": DIGEST_A,
                                "nostr_kind": 445,
                            },
                            "payload_len": 42,
                            "payload_digest": DIGEST_A,
                        },
                    )
                ),
                content_type="application/x-ndjson",
                HTTP_AUTHORIZATION=f"Bearer {raw_token}",
            )
            self.assertEqual(response.status_code, 201)

        upload_message_event(0, GROUP_REF, ENGINE_ALICE, ACCOUNT_ALICE)
        upload_message_event(0, OTHER_GROUP_REF, ENGINE_BOB, ACCOUNT_BOB)
        related_response = self.client.post(
            reverse("api-audit-log-upload"),
            data=jsonl(
                audit_event_v2(
                    1,
                    group_ref=GROUP_REF,
                    engine_id=ENGINE_ALICE,
                    account_ref=ACCOUNT_ALICE,
                    context={"convergence": {"run_id": "msg-run", "phase": "selected"}},
                    kind={
                        "type": "convergence_decision",
                        "current_tip_epoch": 8,
                        "max_rewind_commits": 5,
                        "selected_branch_id": "branch-msg",
                        "selected_tip_epoch": 9,
                        "candidates": [
                            {
                                "branch_id": "branch-msg",
                                "tip_epoch": 9,
                                "eligible": True,
                                "commit_ids": [MSG_ID],
                            }
                        ],
                    },
                ),
                audit_event_v2(
                    2,
                    group_ref=GROUP_REF,
                    engine_id=ENGINE_ALICE,
                    account_ref=ACCOUNT_ALICE,
                    kind={
                        "type": "group_state_changed",
                        "epoch": 9,
                        "change_kind": "member_added",
                        "origin_commit_id": MSG_ID,
                    },
                ),
                audit_event_v2(
                    3,
                    group_ref=GROUP_REF,
                    engine_id=ENGINE_ALICE,
                    account_ref=ACCOUNT_ALICE,
                    context={"operation_id": "op-message-trace"},
                    kind={
                        "type": "human_action",
                        "action": "send_message",
                        "origin": "local_user",
                        "phase": "requested",
                        "message_ids": [MSG_ID],
                    },
                ),
            ),
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )
        self.assertEqual(related_response.status_code, 201)
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

        response = self.client.get(reverse("api-message-detail", kwargs={"message_id": MSG_ID}))

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["schema_version"], "goggles-message/v1")
        self.assertEqual(payload["message_id"], MSG_ID)
        self.assertEqual(payload["filters"]["message_id"], MSG_ID)
        self.assertEqual(payload["pagination"]["returned"], 2)
        self.assertEqual(
            {match["group"]["slug"] for match in payload["matches"]},
            {GROUP_REF, OTHER_GROUP_REF},
        )
        for match in payload["matches"]:
            artifact = match["delivery_artifact"]
            self.assertEqual(artifact["artifact_id"], MSG_ID)
            self.assertTrue(artifact["evidence_refs"])
            self.assertTrue(artifact["engine_observations"][0]["states"][0]["evidence_ref"])
            self.assertIn("related", match)

        matches_by_group = {match["group"]["slug"]: match for match in payload["matches"]}
        group_related = matches_by_group[GROUP_REF]["related"]
        self.assertEqual(
            group_related["network_observations"][0]["phase"],
            "transport_received",
        )
        self.assertEqual(group_related["convergence_runs"][0]["run_id"], "msg-run")
        self.assertEqual(
            group_related["state_deltas"][0]["origin_commit_id"],
            MSG_ID,
        )
        self.assertEqual(
            group_related["action_attribution"]["user_actions"][0]["action"],
            "send_message",
        )
        self.assertEqual(
            group_related["pagination"]["convergence_runs"]["returned"],
            1,
        )
        other_related = matches_by_group[OTHER_GROUP_REF]["related"]
        self.assertEqual(other_related["network_observations"][0]["phase"], "transport_received")
        self.assertEqual(other_related["convergence_runs"], [])
        self.assertEqual(other_related["state_deltas"], [])
        self.assertEqual(other_related["action_attribution"]["user_actions"], [])

        filtered_response = self.client.get(
            reverse("api-message-detail", kwargs={"message_id": MSG_ID}),
            {"engine_id": ENGINE_BOB},
        )

        self.assertEqual(filtered_response.status_code, 200)
        filtered_payload = filtered_response.json()
        self.assertEqual(filtered_payload["pagination"]["returned"], 1)
        self.assertEqual(filtered_payload["matches"][0]["group"]["slug"], OTHER_GROUP_REF)
        self.assertEqual(
            filtered_payload["matches"][0]["delivery_artifact"]["engine_observations"][0][
                "engine_id"
            ],
            ENGINE_BOB,
        )

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

    @override_settings(GOGGLES_MAX_DUMP_RECORDS=1)
    def test_record_limit_quarantines_raw_upload_before_object_expansion(self):
        raw_token, _token = UploadToken.issue("bounded parser")
        body = representative_audit_log()

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("record count exceeds maximum of 1", response.json()["error"])
        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.raw_text, body)
        self.assertEqual(audit_file.events.count(), 1)
        self.assertEqual(audit_file.events.get().raw_line, body)

    def test_line_byte_limit_quarantines_raw_upload_before_json_loads(self):
        raw_token, _token = UploadToken.issue("bounded parser")
        body = jsonl(audit_event_v2(0, kind={"type": "recorder_started", "recorder": "mdk"}))
        byte_limit = len(body.rstrip("\n").encode("utf-8")) - 1

        with self.settings(GOGGLES_MAX_JSONL_LINE_BYTES=byte_limit):
            response = self.client.post(
                reverse("api-audit-log-upload"),
                data=body,
                content_type="application/x-ndjson",
                HTTP_AUTHORIZATION=f"Bearer {raw_token}",
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn(f"exceeds maximum of {byte_limit} UTF-8 bytes", response.json()["error"])
        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.raw_text, body)
        self.assertEqual(audit_file.events.count(), 1)

    @override_settings(GOGGLES_MAX_JSONL_LINE_BYTES=32)
    def test_whitespace_only_line_still_obeys_line_byte_limit(self):
        raw_token, _token = UploadToken.issue("bounded parser")
        body = (" " * 33) + "\n"

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("line 1 exceeds maximum of 32 UTF-8 bytes", response.json()["error"])
        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.raw_text, body)
        self.assertEqual(audit_file.events.get().raw_line, body)

    def test_invalid_utf8_group_upload_links_file_to_fallback_group(self):
        raw_token, _token = UploadToken.issue("ios test client")
        dump_bytes = b"\xff\xfeinvalid marmot audit bytes"

        response = self.client.post(
            reverse("api-group-audit-log-upload", kwargs={"group_slug": "mobile-qa"}),
            data=dump_bytes,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["validation_status"], AuditFile.STATUS_INVALID)
        self.assertEqual(response.json()["group"], "mobile-qa")
        self.assertEqual(response.json()["groups"], ["mobile-qa"])

        audit_file = AuditFile.objects.get()
        fallback_group = AuditGroup.objects.get(slug="mobile-qa")
        self.assertEqual(audit_file.validation_status, AuditFile.STATUS_INVALID)
        self.assertEqual(audit_file.events.get().group, fallback_group)
        self.assertEqual(groups_for_audit_file(audit_file), [fallback_group])
        self.assertEqual(list(audit_files_for_group(fallback_group)), [audit_file])

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

    def test_non_string_account_ref_returns_400_and_is_quarantined(self):
        # A present-but-non-string account_ref (here a JSON number) must be
        # treated as a schema violation -- like engine_id -- not silently coerced
        # to "" (which would drop attribution and mark the event valid). The file
        # is quarantined and the raw evidence (original numeric value) preserved.
        # Regression for marmot-protocol/goggles#53.
        raw_token, _token = UploadToken.issue("ios test client")
        bad_event = audit_event(0)
        bad_event["account_ref"] = 123456
        body = jsonl(bad_event)

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["validation_status"], "invalid")
        self.assertIn("account_ref", response.json()["error"])

        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.validation_status, AuditFile.STATUS_INVALID)
        # Raw upload text is preserved intact for forensic evidence.
        self.assertEqual(audit_file.raw_text, body)

        event = audit_file.events.get()
        self.assertEqual(event.parse_status, AuditEvent.STATUS_INVALID)
        self.assertIn("account_ref", event.validation_error)
        # The non-string value is not stored in the indexed column...
        self.assertEqual(event.account_ref, "")
        # ...but the verbatim raw event preserves the original value.
        self.assertEqual(event.raw_event["account_ref"], 123456)

    def test_non_string_group_ref_returns_400_and_is_quarantined(self):
        # A present-but-non-string group_ref (here a JSON list) must be flagged
        # as a schema violation and quarantined. Previously it was coerced to ""
        # so group_key_for_parsed_line() silently re-filed the event under the
        # fallback "incoming" group with no validation error -- losing the
        # explicit group attribution. Regression for marmot-protocol/goggles#53.
        raw_token, _token = UploadToken.issue("ios test client")
        bad_event = audit_event(0)
        bad_event["group_ref"] = ["not", "a", "string"]
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
        self.assertEqual(audit_file.raw_text, body)
        # The event is NOT silently re-bucketed under the fallback group: the
        # whole file is quarantined, so no AuditGroup is created at all.
        self.assertFalse(AuditGroup.objects.exists())

        event = audit_file.events.get()
        self.assertEqual(event.parse_status, AuditEvent.STATUS_INVALID)
        self.assertIn("group_ref", event.validation_error)
        self.assertEqual(event.group_ref, "")
        self.assertEqual(event.raw_event["group_ref"], ["not", "a", "string"])

    def test_numeric_group_ref_returns_400_and_is_quarantined(self):
        # Same as above but with a JSON number rather than a list, covering the
        # other common non-string shape. Regression for marmot-protocol/goggles#53.
        raw_token, _token = UploadToken.issue("ios test client")
        bad_event = audit_event(0)
        bad_event["group_ref"] = 42
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
        self.assertFalse(AuditGroup.objects.exists())

        event = audit_file.events.get()
        self.assertEqual(event.parse_status, AuditEvent.STATUS_INVALID)
        self.assertIn("group_ref", event.validation_error)
        self.assertEqual(event.group_ref, "")
        self.assertEqual(event.raw_event["group_ref"], 42)

    def test_non_string_group_ref_with_fallback_group_is_not_rebucketed(self):
        # The issue's second failure mode: a line that *declared* a group_ref
        # but with a non-string value must not be silently re-filed under the
        # upload's fallback group. Previously normalize_event() cleared the bad
        # group_ref to "", so group_key_for_parsed_line() fell through to the
        # fallback slug and attached the explicitly-(mis)grouped event to the
        # catch-all group with no indication. The whole file is quarantined, so
        # NO group -- including the fallback "mobile-qa" -- may be created or
        # associated. Regression for marmot-protocol/goggles#53.
        raw_token, _token = UploadToken.issue("ios test client")
        bad_event = audit_event(0)
        bad_event["group_ref"] = ["not", "a", "string"]
        body = jsonl(bad_event)

        response = self.client.post(
            reverse("api-group-audit-log-upload", kwargs={"group_slug": "mobile-qa"}),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["validation_status"], "invalid")
        self.assertIn("group_ref", response.json()["error"])

        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.validation_status, AuditFile.STATUS_INVALID)
        self.assertEqual(audit_file.raw_text, body)
        # No fallback re-bucketing: the malformed-group_ref event is NOT filed
        # under "mobile-qa" (nor any other group).
        self.assertFalse(AuditGroup.objects.exists())

        event = audit_file.events.get()
        self.assertEqual(event.parse_status, AuditEvent.STATUS_INVALID)
        self.assertIsNone(event.group)
        self.assertIn("group_ref", event.validation_error)
        self.assertEqual(event.group_ref, "")
        self.assertEqual(event.raw_event["group_ref"], ["not", "a", "string"])

    def test_malformed_string_group_ref_with_fallback_group_is_not_rebucketed(self):
        # Same suppression must apply to a present-but-malformed *string*
        # group_ref (odd-length / non-hex): it declared a group, so quarantining
        # it must not silently re-file the event under the fallback group.
        # Regression for marmot-protocol/goggles#53.
        raw_token, _token = UploadToken.issue("ios test client")
        bad_event = audit_event(0)
        bad_event["group_ref"] = "nothex"
        body = jsonl(bad_event)

        response = self.client.post(
            reverse("api-group-audit-log-upload", kwargs={"group_slug": "mobile-qa"}),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["validation_status"], "invalid")
        self.assertIn("group_ref", response.json()["error"])

        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.validation_status, AuditFile.STATUS_INVALID)
        self.assertFalse(AuditGroup.objects.exists())

        event = audit_file.events.get()
        self.assertEqual(event.parse_status, AuditEvent.STATUS_INVALID)
        self.assertIsNone(event.group)
        self.assertIn("group_ref", event.validation_error)
        self.assertEqual(event.group_ref, "")
        self.assertEqual(event.raw_event["group_ref"], "nothex")

    def test_absent_group_ref_with_fallback_group_still_uses_fallback(self):
        # Counterpart to the suppression tests: a *genuinely absent* group_ref
        # (key omitted from the line) must STILL fall back to the upload's
        # fallback group. The fix only suppresses fallback grouping for
        # present-but-invalid group_ref, not for absent ones. Guards against
        # over-correction. Regression for marmot-protocol/goggles#53.
        raw_token, _token = UploadToken.issue("ios test client")
        good_event = audit_event(0)
        del good_event["group_ref"]
        body = jsonl(good_event)

        response = self.client.post(
            reverse("api-group-audit-log-upload", kwargs={"group_slug": "mobile-qa"}),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["groups"], ["mobile-qa"])

        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.validation_status, AuditFile.STATUS_VALID)

        fallback_group = AuditGroup.objects.get(slug="mobile-qa")
        event = audit_file.events.get()
        self.assertEqual(event.parse_status, AuditEvent.STATUS_VALID)
        self.assertEqual(event.group, fallback_group)

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

    def test_timeline_uses_valid_lines_from_partially_invalid_file(self):
        raw_token, _token = UploadToken.issue("partial client")
        bad_action = audit_event(
            1,
            kind={
                "type": "human_action",
                "action": "update_group_profile",
                "origin": "local_user",
                "phase": "succeeded",
                "message_ids": [f"not-hex-{MSG_ID}"],
            },
        )
        body = jsonl(audit_event(0), bad_action)

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 400)
        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.validation_status, AuditFile.STATUS_INVALID)
        self.assertEqual(audit_file.valid_event_count, 1)
        self.assertEqual(audit_file.invalid_event_count, 1)

        group = AuditGroup.objects.get(slug=GROUP_REF)
        events = list(valid_events_for_group(group))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].seq, 0)
        payload = timeline_payload_for_group(group, events, [])
        self.assertEqual(len(payload["engines"]), 1)
        self.assertEqual(len(payload["items"]), 1)

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

    def test_duplicate_heavy_reupload_keeps_group_link_with_zero_stored_events(self):
        # A second upload whose events for one group are ALL duplicates of an
        # earlier file stores zero AuditEvent rows for that group, yet the
        # file -> group link must survive: it is recorded on the explicit
        # AuditFile.groups membership, not inferred from stored events
        # (marmot-protocol/goggles#37).
        raw_token, _token = UploadToken.issue("ios test client")
        first_body = jsonl(
            audit_event(0, group_ref=GROUP_REF),
            audit_event(1, group_ref=OTHER_GROUP_REF),
        )
        # The re-upload repeats GROUP_REF's line verbatim (a duplicate that is
        # deduplicated away) while adding a fresh OTHER_GROUP_REF line.
        second_body = jsonl(
            audit_event(0, group_ref=GROUP_REF),
            audit_event(
                2,
                group_ref=OTHER_GROUP_REF,
                kind={
                    "type": "message_state_changed",
                    "msg_id": OTHER_MSG_ID,
                    "new_state": "processed",
                    "reason": "state_update",
                },
            ),
        )

        first_response = self.client.post(
            reverse("api-audit-log-upload"),
            data=first_body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )
        second_response = self.client.post(
            reverse("api-audit-log-upload"),
            data=second_body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(first_response.status_code, 201)
        self.assertEqual(second_response.status_code, 201)
        second_file = AuditFile.objects.order_by("created_at").last()
        group = AuditGroup.objects.get(slug=GROUP_REF)
        other_group = AuditGroup.objects.get(slug=OTHER_GROUP_REF)

        # GROUP_REF's single line was deduplicated away: zero stored events for
        # it in the second file, so the OLD stored-event-derived link is gone.
        self.assertEqual(
            second_file.events.filter(group__slug=GROUP_REF).count(),
            0,
        )

        # The explicit relation keeps BOTH groups linked to the second file.
        linked_groups = groups_for_audit_file(second_file)
        self.assertIn(group, linked_groups)
        self.assertIn(other_group, linked_groups)

        # The upload API response surfaces both groups for the duplicate-heavy
        # upload (group is None when more than one group is linked).
        body = second_response.json()
        self.assertCountEqual(body["groups"], [GROUP_REF, OTHER_GROUP_REF])
        self.assertIsNone(body["group"])

        # The upload_log_list "N linked" badge counts both groups, not just the
        # one with a stored event in the second file.
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")
        list_response = self.client.get(reverse("upload-log-list"))
        listed = {row.id: row for row in list_response.context["audit_files"]}
        self.assertEqual(listed[second_file.id].group_count, 2)

        # Group detail (audit_files_for_group) lists the duplicate-only file for
        # GROUP_REF even though it stored zero events for that group. Before the
        # explicit-M2M fix, filtering on events__group dropped it entirely.
        # Its per-file group_event_count is correctly 0 (no stored events).
        detail_files = {f.id: f for f in audit_files_for_group(group)}
        self.assertIn(second_file.id, detail_files)
        self.assertEqual(detail_files[second_file.id].group_event_count, 0)

        # Group-list audit_file_count counts the duplicate-only file toward
        # GROUP_REF's linked-file total. Both the first and second files are
        # linked to GROUP_REF.
        rows = {row.slug: row for row in group_list_rows()}
        self.assertEqual(rows[GROUP_REF].audit_file_count, 2)

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

    def test_upload_refreshes_all_touched_groups_with_one_update(self):
        group_refs = [f"{index:064x}" for index in range(1, 4)]
        groups = [
            AuditGroup.objects.create(
                name=f"Group {index}",
                slug=f"group-{index}",
                group_ref=group_ref,
            )
            for index, group_ref in enumerate(group_refs, start=1)
        ]

        def message_event(seq, group_ref, engine_id, account_ref, msg_id, wall_time_ms):
            return audit_event(
                seq,
                engine_id=engine_id,
                account_ref=account_ref,
                group_ref=group_ref,
                wall_time_ms=wall_time_ms,
                kind={
                    "type": "ingest_entry",
                    "msg_id": msg_id,
                    "envelope_kind": "group_message",
                    "payload_len": 512,
                    "payload_digest": DIGEST_A,
                },
            )

        def presence(seq, group_ref, engine_id, account_ref, wall_time_ms):
            # An epoch confirmation carries no message; it only extends the
            # engine's active window so a later message it never logged counts
            # as a real (membership-aware) break rather than a late-joiner gap.
            return audit_event(
                seq,
                engine_id=engine_id,
                account_ref=account_ref,
                group_ref=group_ref,
                wall_time_ms=wall_time_ms,
                kind={
                    "type": "epoch_confirmed",
                    "from_epoch": 4,
                    "to_epoch": 5,
                    "pending_kind": "commit",
                },
            )

        # Alice sees the shared message in each group and stays active until
        # T0+1000, so the Bob-only messages she never logged fall inside her
        # window. The captured Bob upload touches all three groups in one ingest
        # and should refresh their persisted rollups in one batched UPDATE with
        # per-group divergent counts of 0, 1, and 2 respectively.
        alice_body = jsonl(
            message_event(1, group_refs[0], ENGINE_ALICE, ACCOUNT_ALICE, "10" * 32, T0 + 10),
            message_event(2, group_refs[1], ENGINE_ALICE, ACCOUNT_ALICE, "20" * 32, T0 + 10),
            message_event(3, group_refs[2], ENGINE_ALICE, ACCOUNT_ALICE, "30" * 32, T0 + 10),
            presence(4, group_refs[1], ENGINE_ALICE, ACCOUNT_ALICE, T0 + 1000),
            presence(5, group_refs[2], ENGINE_ALICE, ACCOUNT_ALICE, T0 + 1000),
        )
        bob_body = jsonl(
            message_event(6, group_refs[0], ENGINE_BOB, ACCOUNT_BOB, "10" * 32, T0 + 20),
            message_event(7, group_refs[1], ENGINE_BOB, ACCOUNT_BOB, "20" * 32, T0 + 20),
            message_event(8, group_refs[1], ENGINE_BOB, ACCOUNT_BOB, "21" * 32, T0 + 30),
            message_event(9, group_refs[2], ENGINE_BOB, ACCOUNT_BOB, "30" * 32, T0 + 20),
            message_event(10, group_refs[2], ENGINE_BOB, ACCOUNT_BOB, "31" * 32, T0 + 30),
            message_event(11, group_refs[2], ENGINE_BOB, ACCOUNT_BOB, "32" * 32, T0 + 40),
        )
        expected_divergent_counts = {
            groups[0].id: 0,
            groups[1].id: 1,
            groups[2].id: 2,
        }
        seed_result = ingest_audit_log_bytes(dump_bytes=alice_body.encode("utf-8"))
        bumped_at = timezone.now()

        with mock.patch.object(ingest_module.timezone, "now", return_value=bumped_at):
            with CaptureQueriesContext(connection) as queries:
                result = ingest_audit_log_bytes(dump_bytes=bob_body.encode("utf-8"))

        self.assertTrue(seed_result.created)
        self.assertTrue(result.created)
        group_update_queries = [
            query["sql"]
            for query in queries
            if 'UPDATE "forensics_auditgroup"' in query["sql"] and '"updated_at"' in query["sql"]
        ]
        self.assertEqual(len(group_update_queries), 1, group_update_queries)
        self.assertIn("CASE", group_update_queries[0])
        for group in groups:
            group.refresh_from_db()
            self.assertEqual(group.updated_at, bumped_at)
            self.assertEqual(
                group.divergent_message_count,
                expected_divergent_counts[group.id],
                group.group_ref,
            )

    def test_audit_event_batch_size_stays_under_postgres_bind_limit(self):
        # AuditEvent.objects.bulk_create() must pass an explicit batch_size so a
        # single INSERT never exceeds Postgres' 65535 bind-parameter cap (the
        # parameter count is encoded as an int16 on the wire). With ~71 columns
        # per unsaved row the cap is ~922 events per statement; assert the
        # derived batch size keeps the per-statement parameter count comfortably
        # below the hard limit. Regression for marmot-protocol/goggles#51.
        fields_per_row = len(
            [field for field in AuditEvent._meta.local_concrete_fields if not field.auto_created]
        )
        batch_size = audit_event_batch_size()
        self.assertGreaterEqual(batch_size, 1)
        self.assertLess(batch_size * fields_per_row, 65535)

    def test_upload_well_over_postgres_bind_limit_ingests_not_500(self):
        # A valid JSONL upload whose line count far exceeds the ~922-event
        # single-statement ceiling must still ingest with a 201, not 500. Without
        # an explicit batch_size, Django's Postgres backend issues one
        # INSERT ... VALUES (...),(...),... carrying len(objs) * ~71 bind
        # parameters; past ~922 events that exceeds the 65535 int16 cap and
        # psycopg raises a non-IntegrityError that escapes the
        # ``except IntegrityError`` handler, rolling back the upload and 500ing
        # with no AuditFile persisted -- losing the raw evidence. SQLite (the dev
        # DB) overrides bulk_batch_size and auto-batches, so this only ever 500s
        # on Postgres in CI; the explicit batch_size makes it correct on both.
        # Regression for marmot-protocol/goggles#51.
        event_count = 1500
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
                for seq in range(event_count)
            ]
        )
        raw_token, _token = UploadToken.issue("ios test client")

        response = self.client.post(
            reverse("api-audit-log-upload"),
            data=body,
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["validation_status"], "valid")
        self.assertEqual(response.json()["event_count"], event_count)
        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.validation_status, AuditFile.STATUS_VALID)
        self.assertEqual(audit_file.events.count(), event_count)
        self.assertEqual(audit_file.raw_text, body)

    def test_unexpected_ingest_error_quarantines_upload_not_500(self):
        # Defense-in-depth: if event creation raises something OTHER than an
        # IntegrityError (e.g. a psycopg DataError from a bind-parameter or
        # btree-index overflow), the upload must still be saved as a quarantined
        # AuditFile that preserves the raw text, not lost to a 500. Simulate the
        # uncaught-error path by making create_events() raise a non-IntegrityError
        # and assert the raw evidence survives. Regression for
        # marmot-protocol/goggles#51.
        from django.db import DataError

        raw_token, _token = UploadToken.issue("ios test client")
        body = representative_audit_log()

        with mock.patch.object(
            ingest_module, "create_events", side_effect=DataError("simulated bind overflow")
        ):
            response = self.client.post(
                reverse("api-audit-log-upload"),
                data=body,
                content_type="application/x-ndjson",
                HTTP_AUTHORIZATION=f"Bearer {raw_token}",
            )

        # Quarantined (invalid) rather than a 500 with no record.
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["validation_status"], "invalid")
        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.validation_status, AuditFile.STATUS_INVALID)
        # The raw upload text is preserved intact as evidence, not dropped.
        self.assertEqual(audit_file.raw_text, body)

    def test_unexpected_ingest_error_group_upload_links_file_to_fallback_group(self):
        from django.db import DataError

        raw_token, _token = UploadToken.issue("ios test client")
        body = representative_audit_log()

        with mock.patch.object(
            ingest_module, "create_events", side_effect=DataError("simulated bind overflow")
        ):
            response = self.client.post(
                reverse("api-group-audit-log-upload", kwargs={"group_slug": "mobile-qa"}),
                data=body,
                content_type="application/x-ndjson",
                HTTP_AUTHORIZATION=f"Bearer {raw_token}",
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["validation_status"], AuditFile.STATUS_INVALID)
        self.assertEqual(response.json()["group"], "mobile-qa")
        self.assertEqual(response.json()["groups"], ["mobile-qa"])

        audit_file = AuditFile.objects.get()
        fallback_group = AuditGroup.objects.get(slug="mobile-qa")
        self.assertEqual(audit_file.validation_status, AuditFile.STATUS_INVALID)
        self.assertEqual(audit_file.raw_text, body)
        self.assertEqual(audit_file.events.get().group, fallback_group)
        self.assertEqual(groups_for_audit_file(audit_file), [fallback_group])
        self.assertEqual(list(audit_files_for_group(fallback_group)), [audit_file])

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


class RebuildAuditProjectionsCommandTests(TestCase):
    def test_rebuild_without_selectors_includes_v3_evidence(self):
        result = ingest_audit_log_bytes(
            dump_bytes=jsonl(
                audit_event_v3(
                    0,
                    kind={
                        "type": "transport_received",
                        "msg_id": MSG_ID,
                        "transport": {
                            "transport": "nostr",
                            "relay_url": "wss://relay.example",
                        },
                        "payload_len": 42,
                        "payload_digest": DIGEST_A,
                    },
                )
            ).encode("utf-8"),
            source_name="v3-command-test.jsonl",
        )

        self.assertEqual(result.audit_file.schema_versions, [SCHEMA_VERSION_V3])
        DeliveryArtifact.objects.all().delete()
        NetworkObservation.objects.all().delete()

        output = StringIO()
        call_command("rebuild_audit_projections", stdout=output)

        self.assertEqual(DeliveryArtifact.objects.get().artifact_id, MSG_ID)
        self.assertEqual(NetworkObservation.objects.get().relay_url, "wss://relay.example")
        self.assertIn("Rebuilt audit projections for 1 group(s)", output.getvalue())

    def test_rebuild_restores_v2_projection_tables_from_raw_evidence(self):
        result = ingest_audit_log_bytes(
            dump_bytes=jsonl(
                audit_event_v2(
                    0,
                    kind={
                        "type": "transport_received",
                        "msg_id": MSG_ID,
                        "transport": {
                            "transport": "nostr",
                            "delivery_plane": "relay",
                            "relay_url": "wss://relay.example",
                            "nostr_event_id": DIGEST_A,
                            "nostr_kind": 445,
                        },
                    },
                ),
                audit_event_v2(
                    1,
                    audit_data_mode="full_data",
                    kind={
                        "type": "message_content_decoded",
                        "msg_id": MSG_ID,
                        "artifact_kind": "application_message",
                        "author": {
                            "member_ref": ACCOUNT_ALICE,
                            "account_pubkey_hex": "aa" * 32,
                        },
                        "decoded_payload": {"content_type": "text/plain", "text": "hello"},
                    },
                ),
                audit_event_v2(
                    2,
                    kind={
                        "type": "recipient_expectation",
                        "msg_id": MSG_ID,
                        "expectation": {
                            "artifact_kind": "application_message",
                            "recipient_scope": "all_other_current_group_members",
                            "expected_member_refs": [ACCOUNT_BOB],
                            "expected_count": 1,
                        },
                    },
                ),
                audit_event_v2(
                    3,
                    context={"convergence": {"run_id": "run-1", "phase": "selected"}},
                    kind={
                        "type": "convergence_decision",
                        "current_tip_epoch": 7,
                        "max_rewind_commits": 5,
                        "selected_branch_id": "branch-a",
                        "candidates": [
                            {
                                "branch_id": "branch-a",
                                "eligible": True,
                                "score": {"app_witness_score": 1},
                            }
                        ],
                        "rule_trace": [
                            {
                                "rule_name": "highest_weight",
                                "result": {"winner": "branch-a"},
                                "decisive": True,
                            }
                        ],
                    },
                ),
                audit_event_v2(
                    4,
                    context={"convergence": {"run_id": "run-1", "phase": "selected"}},
                    kind={
                        "type": "convergence_decision",
                        "current_tip_epoch": 7,
                        "max_rewind_commits": 5,
                        "selected_branch_id": "branch-a",
                        "candidates": [
                            {
                                "branch_id": "branch-a",
                                "eligible": True,
                                "score": {"app_witness_score": 3},
                            }
                        ],
                        "rule_trace": [
                            {
                                "rule_name": "highest_weight",
                                "result": {"winner": "branch-a"},
                                "decisive": True,
                            }
                        ],
                    },
                ),
                audit_event_v2(
                    5,
                    kind={
                        "type": "group_state_changed",
                        "epoch": 8,
                        "change_kind": "member_added",
                        "origin_commit_id": MSG_ID,
                    },
                ),
                audit_event_v2(
                    6,
                    kind={
                        "type": "epoch_state_changed",
                        "previous_state": "pending",
                        "new_state": "committed",
                        "epoch": 8,
                        "reason": "winning_commit_applied",
                    },
                ),
            ).encode("utf-8"),
            source_name="v2-command-test.jsonl",
        )

        self.assertEqual(result.audit_file.schema_versions, [SCHEMA_VERSION_V2])
        self.assertEqual(DeliveryArtifact.objects.count(), 1)
        self.assertEqual(NetworkObservation.objects.count(), 1)
        self.assertEqual(ConvergenceRun.objects.count(), 1)
        self.assertEqual(StateDelta.objects.count(), 1)
        self.assertEqual(EpochStateTransition.objects.count(), 1)

        DeliveryArtifact.objects.all().delete()
        NetworkObservation.objects.all().delete()
        ConvergenceRun.objects.all().delete()
        StateDelta.objects.all().delete()
        EpochStateTransition.objects.all().delete()

        output = StringIO()
        call_command(
            "rebuild_audit_projections",
            "--audit-file-id",
            str(result.audit_file.id),
            stdout=output,
        )

        artifact = DeliveryArtifact.objects.get()
        self.assertEqual(artifact.artifact_id, MSG_ID)
        self.assertEqual(artifact.decoded_payload["text"], "hello")
        self.assertEqual(artifact.recipient_expectations.count(), 1)
        self.assertEqual(NetworkObservation.objects.get().relay_url, "wss://relay.example")
        self.assertEqual(ConvergenceRun.objects.get().selected_branch_id, "branch-a")
        self.assertEqual(ConvergenceCandidate.objects.get().score["app_witness_score"], 3)
        self.assertEqual(
            ConvergenceRuleEvaluation.objects.filter(rule_name="highest_weight").count(),
            2,
        )
        self.assertEqual(StateDelta.objects.get().change_kind, "member_added")
        self.assertEqual(EpochStateTransition.objects.get().new_state, "committed")
        self.assertIn("Rebuilt audit projections for 1 group(s)", output.getvalue())
        self.assertNotIn(GROUP_REF, output.getvalue())
        self.assertNotIn(ENGINE_ALICE, output.getvalue())

    def test_rebuild_skips_structurally_quarantined_v2_files(self):
        result = ingest_audit_log_bytes(
            dump_bytes=jsonl(
                audit_event_v2(
                    0,
                    engine_id=ENGINE_ALICE,
                    account_ref=ACCOUNT_ALICE,
                    kind={
                        "type": "transport_received",
                        "msg_id": MSG_ID,
                        "transport": {
                            "transport": "nostr",
                            "delivery_plane": "relay",
                            "relay_url": "wss://relay.example",
                        },
                    },
                ),
                audit_event_v2(
                    1,
                    engine_id=ENGINE_BOB,
                    account_ref=ACCOUNT_BOB,
                    context={"convergence": {"run_id": "run-quarantined", "phase": "selected"}},
                    kind={
                        "type": "convergence_decision",
                        "current_tip_epoch": 7,
                        "max_rewind_commits": 5,
                        "selected_branch_id": "branch-a",
                        "candidates": [{"branch_id": "branch-a", "eligible": True}],
                        "rule_trace": [{"rule_name": "highest_weight", "decisive": True}],
                    },
                ),
                audit_event_v2(
                    2,
                    engine_id=ENGINE_BOB,
                    account_ref=ACCOUNT_BOB,
                    kind={
                        "type": "group_state_changed",
                        "epoch": 8,
                        "change_kind": "member_added",
                        "origin_commit_id": MSG_ID,
                    },
                ),
                audit_event_v2(
                    3,
                    engine_id=ENGINE_BOB,
                    account_ref=ACCOUNT_BOB,
                    kind={
                        "type": "epoch_state_changed",
                        "previous_state": "pending",
                        "new_state": "committed",
                        "epoch": 8,
                        "reason": "winning_commit_applied",
                    },
                ),
            ).encode("utf-8"),
            source_name="v2-structural-quarantine.jsonl",
        )

        audit_file = result.audit_file
        self.assertEqual(audit_file.validation_status, AuditFile.STATUS_INVALID)
        self.assertIn("audit log contains multiple engine_ids", audit_file.validation_error)
        self.assertIn("audit log contains multiple account_refs", audit_file.validation_error)
        group = AuditGroup.objects.get(slug=GROUP_REF)
        self.assertEqual(
            AuditEvent.objects.filter(
                audit_file=audit_file,
                group=group,
                parse_status=AuditEvent.STATUS_VALID,
            ).count(),
            4,
        )
        self.assertEqual(valid_group_event_queryset(group).count(), 0)

        self.assertEqual(DeliveryArtifact.objects.filter(group=group).count(), 0)
        self.assertEqual(DeliveryObservation.objects.filter(artifact__group=group).count(), 0)
        self.assertEqual(RecipientExpectation.objects.filter(artifact__group=group).count(), 0)
        self.assertEqual(NetworkObservation.objects.filter(group=group).count(), 0)
        self.assertEqual(ConvergenceRun.objects.filter(group=group).count(), 0)
        self.assertEqual(ConvergenceCandidate.objects.filter(run__group=group).count(), 0)
        self.assertEqual(ConvergenceRuleEvaluation.objects.filter(run__group=group).count(), 0)
        self.assertEqual(StateDelta.objects.filter(group=group).count(), 0)
        self.assertEqual(EpochStateTransition.objects.filter(group=group).count(), 0)

        summary = group_summary_context(group)
        self.assertEqual(summary["summary"]["event_count"], 0)
        self.assertEqual(summary["tab_counts"]["overview"], 0)
        self.assertEqual(summary["tab_counts"]["delivery"], 0)
        self.assertEqual(summary["tab_counts"]["network"], 0)
        self.assertEqual(summary["tab_counts"]["convergence"], 0)
        self.assertEqual(summary["tab_counts"]["state"], 0)

    def test_rebuild_preserves_clean_file_projections_with_structural_quarantine(self):
        quarantined_result = ingest_audit_log_bytes(
            dump_bytes=jsonl(
                audit_event_v2(
                    0,
                    engine_id=ENGINE_ALICE,
                    account_ref=ACCOUNT_ALICE,
                    kind={
                        "type": "transport_received",
                        "msg_id": MSG_ID,
                        "transport": {
                            "transport": "nostr",
                            "delivery_plane": "relay",
                            "relay_url": "wss://quarantined.example",
                        },
                    },
                ),
                audit_event_v2(
                    1,
                    engine_id=ENGINE_BOB,
                    account_ref=ACCOUNT_BOB,
                    context={"convergence": {"run_id": "run-quarantined", "phase": "selected"}},
                    kind={
                        "type": "convergence_decision",
                        "current_tip_epoch": 7,
                        "max_rewind_commits": 5,
                        "selected_branch_id": "branch-quarantined",
                        "candidates": [{"branch_id": "branch-quarantined", "eligible": True}],
                        "rule_trace": [{"rule_name": "highest_weight", "decisive": True}],
                    },
                ),
                audit_event_v2(
                    2,
                    engine_id=ENGINE_BOB,
                    account_ref=ACCOUNT_BOB,
                    kind={
                        "type": "group_state_changed",
                        "epoch": 8,
                        "change_kind": "member_added",
                        "origin_commit_id": MSG_ID,
                    },
                ),
                audit_event_v2(
                    3,
                    engine_id=ENGINE_BOB,
                    account_ref=ACCOUNT_BOB,
                    kind={
                        "type": "epoch_state_changed",
                        "previous_state": "pending",
                        "new_state": "committed",
                        "epoch": 8,
                        "reason": "winning_commit_applied",
                    },
                ),
            ).encode("utf-8"),
            source_name="v2-structural-quarantine-mixed.jsonl",
        )
        clean_result = ingest_audit_log_bytes(
            dump_bytes=jsonl(
                audit_event_v2(
                    0,
                    kind={
                        "type": "transport_received",
                        "msg_id": OTHER_MSG_ID,
                        "transport": {
                            "transport": "nostr",
                            "delivery_plane": "relay",
                            "relay_url": "wss://clean.example",
                        },
                    },
                ),
                audit_event_v2(
                    1,
                    kind={
                        "type": "recipient_expectation",
                        "msg_id": OTHER_MSG_ID,
                        "expectation": {
                            "artifact_kind": "application_message",
                            "recipient_scope": "all_other_current_group_members",
                            "expected_member_refs": [ACCOUNT_BOB],
                            "expected_count": 1,
                        },
                    },
                ),
                audit_event_v2(
                    2,
                    context={"convergence": {"run_id": "run-clean", "phase": "selected"}},
                    kind={
                        "type": "convergence_decision",
                        "current_tip_epoch": 9,
                        "max_rewind_commits": 5,
                        "selected_branch_id": "branch-clean",
                        "candidates": [{"branch_id": "branch-clean", "eligible": True}],
                        "rule_trace": [{"rule_name": "highest_weight", "decisive": True}],
                    },
                ),
                audit_event_v2(
                    3,
                    kind={
                        "type": "group_state_changed",
                        "epoch": 10,
                        "change_kind": "member_added",
                        "origin_commit_id": OTHER_MSG_ID,
                    },
                ),
                audit_event_v2(
                    4,
                    kind={
                        "type": "epoch_state_changed",
                        "previous_state": "pending",
                        "new_state": "committed",
                        "epoch": 10,
                        "reason": "winning_commit_applied",
                    },
                ),
            ).encode("utf-8"),
            source_name="v2-clean-mixed.jsonl",
        )

        self.assertEqual(quarantined_result.audit_file.validation_status, AuditFile.STATUS_INVALID)
        self.assertEqual(clean_result.audit_file.validation_status, AuditFile.STATUS_VALID)
        group = AuditGroup.objects.get(slug=GROUP_REF)
        self.assertEqual(valid_group_event_queryset(group).count(), 5)

        artifact = DeliveryArtifact.objects.get(group=group)
        self.assertEqual(artifact.artifact_id, OTHER_MSG_ID)
        self.assertEqual(
            set(artifact.evidence_events.values_list("audit_file_id", flat=True)),
            {clean_result.audit_file.id},
        )
        self.assertEqual(DeliveryObservation.objects.filter(artifact=artifact).count(), 1)
        self.assertEqual(RecipientExpectation.objects.filter(artifact=artifact).count(), 1)
        self.assertEqual(
            NetworkObservation.objects.get(group=group).relay_url, "wss://clean.example"
        )
        self.assertEqual(ConvergenceRun.objects.get(group=group).selected_branch_id, "branch-clean")
        self.assertEqual(ConvergenceCandidate.objects.filter(run__group=group).count(), 1)
        self.assertEqual(ConvergenceRuleEvaluation.objects.filter(run__group=group).count(), 1)
        self.assertEqual(StateDelta.objects.get(group=group).change_kind, "member_added")
        self.assertEqual(EpochStateTransition.objects.get(group=group).new_state, "committed")

        summary = group_summary_context(group)
        self.assertEqual(summary["summary"]["event_count"], 5)
        self.assertEqual(summary["summary"]["engine_count"], 1)
        self.assertEqual(summary["tab_counts"]["overview"], 5)
        self.assertEqual(summary["tab_counts"]["delivery"], 1)
        self.assertEqual(summary["tab_counts"]["network"], 1)
        self.assertEqual(summary["tab_counts"]["convergence"], 1)
        self.assertEqual(summary["tab_counts"]["state"], 2)

    def test_rebuild_default_ignores_v1_only_groups(self):
        result = ingest_audit_log_bytes(
            dump_bytes=representative_audit_log().encode("utf-8"),
            source_name="v1-command-test.jsonl",
        )

        self.assertEqual(result.audit_file.schema_versions, [SCHEMA_VERSION])
        output = StringIO()
        call_command("rebuild_audit_projections", stdout=output)

        self.assertEqual(DeliveryArtifact.objects.count(), 0)
        self.assertEqual(NetworkObservation.objects.count(), 0)
        self.assertEqual(ConvergenceRun.objects.count(), 0)
        self.assertIn("Rebuilt audit projections for 0 group(s)", output.getvalue())

    def test_convergence_rows_without_stable_run_id_are_grouped_as_inferred_runs(self):
        result = ingest_audit_log_bytes(
            dump_bytes=jsonl(
                audit_event_v2(
                    0,
                    wall_time_ms=T0,
                    kind={
                        "type": "convergence_run_state",
                        "phase": "evaluating",
                        "current_tip_epoch": 7,
                    },
                ),
                audit_event_v2(
                    1,
                    wall_time_ms=T0 + 1,
                    kind={
                        "type": "convergence_decision",
                        "current_tip_epoch": 7,
                        "max_rewind_commits": 5,
                        "selected_branch_id": "branch-a",
                        "selected_tip_epoch": 8,
                        "candidates": [{"branch_id": "branch-a", "eligible": True}],
                        "rule_trace": [
                            {
                                "rule_name": "highest_weight",
                                "decisive": True,
                                "selected_branch_id": "branch-a",
                            }
                        ],
                    },
                ),
                audit_event_v2(
                    2,
                    wall_time_ms=T0 + 2,
                    kind={
                        "type": "epoch_state_changed",
                        "previous_state": "pending",
                        "new_state": "committed",
                        "epoch": 8,
                        "reason": "winning_commit_applied",
                    },
                ),
                audit_event_v2(
                    3,
                    wall_time_ms=T0 + 3,
                    kind={
                        "type": "convergence_run_state",
                        "phase": "evaluating",
                        "current_tip_epoch": 8,
                    },
                ),
                audit_event_v2(
                    4,
                    wall_time_ms=T0 + 4,
                    kind={
                        "type": "convergence_decision",
                        "current_tip_epoch": 8,
                        "max_rewind_commits": 5,
                        "selected_branch_id": "branch-b",
                        "selected_tip_epoch": 9,
                        "candidates": [{"branch_id": "branch-b", "eligible": True}],
                    },
                ),
            ).encode("utf-8"),
            source_name="v2-inferred-convergence.jsonl",
        )

        self.assertEqual(result.audit_file.schema_versions, [SCHEMA_VERSION_V2])
        group = AuditGroup.objects.get(slug=GROUP_REF)
        runs = list(ConvergenceRun.objects.filter(group=group).order_by("started_at_ms"))

        self.assertEqual(len(runs), 2)
        self.assertTrue(all(run.inferred for run in runs))
        first_event = AuditEvent.objects.get(group=group, seq=0)
        self.assertEqual(runs[0].run_id, f"inferred-{ENGINE_ALICE}-{first_event.id}")
        self.assertEqual(runs[0].phase, "committed")
        self.assertEqual(runs[0].selected_branch_id, "branch-a")
        self.assertEqual(runs[0].started_at_ms, T0)
        self.assertEqual(runs[0].ended_at_ms, T0 + 2)
        self.assertEqual(runs[0].evidence_events.count(), 3)
        self.assertEqual(runs[0].candidates.get().branch_id, "branch-a")
        self.assertEqual(runs[0].rule_evaluations.get().rule_name, "highest_weight")
        self.assertEqual(runs[1].phase, "selected")
        self.assertEqual(runs[1].selected_branch_id, "branch-b")
        self.assertEqual(runs[1].evidence_events.count(), 2)
        self.assertEqual(EpochStateTransition.objects.filter(group=group).count(), 1)


class IncrementalProjectionIngestTests(TestCase):
    """A small append must project only the uploaded file, not rebuild the group.

    Each test fails against the old clear-and-fully-reproject behavior
    (marmot-protocol/goggles#127), not merely on final row equality:
    the broad delete + per-event re-insert is detected directly.
    """

    INCREMENTAL_T0 = 1_700_000_000_000

    def _upload_message_event(self, seq, msg_id):
        return ingest_audit_log_bytes(
            dump_bytes=jsonl(
                audit_event_v2(
                    seq,
                    wall_time_ms=self.INCREMENTAL_T0 + seq,
                    kind={
                        "type": "transport_received",
                        "msg_id": msg_id,
                        "transport": {
                            "transport": "nostr",
                            "delivery_plane": "relay",
                            "relay_url": "wss://relay.example",
                            "nostr_event_id": DIGEST_A,
                            "nostr_kind": 445,
                        },
                        "payload_len": 10,
                        "payload_digest": DIGEST_A,
                    },
                )
            ).encode("utf-8"),
            source_name=f"append-{seq}.jsonl",
        )

    def test_projection_queries_never_select_verbatim_evidence_columns(self):
        with CaptureQueriesContext(connection) as captured:
            result = self._upload_message_event(0, MSG_ID)

        self.assertTrue(result.created)
        self.assertEqual(
            heavy_bulk_selects(
                captured.captured_queries,
                allowed_columns=(
                    HEAVY_EVENT_SELECT_COLUMNS["raw_kind"],
                    HEAVY_EVENT_SELECT_COLUMNS["context_transport"],
                    HEAVY_EVENT_SELECT_COLUMNS["context_convergence"],
                ),
            ),
            [],
            "projection ingestion must not hydrate raw upload or raw event bodies",
        )

    def test_small_append_does_not_clear_and_reproject_whole_group(self):
        # Seed a group with several prior messages -> several projection rows.
        prior_msg_ids = [f"{byte:02x}" * 32 for byte in range(0xA0, 0xA5)]
        for seq, msg_id in enumerate(prior_msg_ids):
            self._upload_message_event(seq, msg_id)

        group = AuditGroup.objects.get(slug=GROUP_REF)
        prior_artifact_pks = set(
            DeliveryArtifact.objects.filter(group=group).values_list("id", flat=True)
        )
        prior_observation_pks = set(
            DeliveryObservation.objects.filter(artifact__group=group).values_list("id", flat=True)
        )
        prior_network_pks = set(
            NetworkObservation.objects.filter(group=group).values_list("id", flat=True)
        )
        self.assertEqual(len(prior_artifact_pks), len(prior_msg_ids))
        self.assertEqual(len(prior_network_pks), len(prior_msg_ids))

        new_msg_id = "ff" * 32
        with mock.patch.object(
            projections_module,
            "project_event",
            wraps=projections_module.project_event,
        ) as project_event_spy:
            self._upload_message_event(len(prior_msg_ids), new_msg_id)

        # Only the single newly stored event is projected: the prior group
        # events are never re-handed to project_event. The old behavior would
        # call project_event once per valid event in the entire group.
        projected_events = [call.args[0] for call in project_event_spy.call_args_list]
        self.assertEqual(len(projected_events), 1)
        self.assertEqual(projected_events[0].msg_id, new_msg_id)

        # The prior projection rows are extended in place, not deleted and
        # re-inserted, so their primary keys survive the append. Under the old
        # clear-and-rebuild this set would be entirely fresh PKs.
        surviving_artifact_pks = set(
            DeliveryArtifact.objects.filter(group=group, id__in=prior_artifact_pks).values_list(
                "id", flat=True
            )
        )
        self.assertEqual(surviving_artifact_pks, prior_artifact_pks)
        surviving_observation_pks = set(
            DeliveryObservation.objects.filter(id__in=prior_observation_pks).values_list(
                "id", flat=True
            )
        )
        self.assertEqual(surviving_observation_pks, prior_observation_pks)
        surviving_network_pks = set(
            NetworkObservation.objects.filter(id__in=prior_network_pks).values_list("id", flat=True)
        )
        self.assertEqual(surviving_network_pks, prior_network_pks)

        # The append still lands its own projection rows alongside the prior ones.
        self.assertEqual(
            DeliveryArtifact.objects.filter(group=group).count(), len(prior_msg_ids) + 1
        )
        self.assertTrue(
            DeliveryArtifact.objects.filter(group=group, artifact_id=new_msg_id).exists()
        )
        self.assertEqual(
            NetworkObservation.objects.filter(group=group).count(), len(prior_msg_ids) + 1
        )
        # The appended upload also gets its own fresh DeliveryObservation, not
        # just surviving prior rows: a new observation PK appears alongside them.
        appended_observation_pks = set(
            DeliveryObservation.objects.filter(
                artifact__group=group, artifact__artifact_id=new_msg_id
            ).values_list("id", flat=True)
        )
        self.assertEqual(len(appended_observation_pks), 1)
        self.assertTrue(appended_observation_pks.isdisjoint(prior_observation_pks))
        self.assertEqual(
            DeliveryObservation.objects.filter(artifact__group=group).count(),
            len(prior_observation_pks) + 1,
        )

    def test_append_does_not_duplicate_prior_leaf_projection_rows(self):
        # Leaf projection rows (NetworkObservation / RecipientExpectation) are
        # created, not upserted; re-projecting a prior event would duplicate
        # them. Prove the prior event's rows stay singular after an append.
        self._upload_message_event(0, MSG_ID)
        ingest_audit_log_bytes(
            dump_bytes=jsonl(
                audit_event_v2(
                    1,
                    wall_time_ms=self.INCREMENTAL_T0 + 1,
                    kind={
                        "type": "recipient_expectation",
                        "msg_id": MSG_ID,
                        "expectation": {
                            "artifact_kind": "application_message",
                            "recipient_scope": "all_other_current_group_members",
                            "expected_count": 1,
                        },
                    },
                )
            ).encode("utf-8"),
            source_name="expectation.jsonl",
        )

        group = AuditGroup.objects.get(slug=GROUP_REF)
        prior_network_count = NetworkObservation.objects.filter(group=group).count()
        self.assertEqual(prior_network_count, 1)

        # A later, unrelated append must not re-create the first message's
        # NetworkObservation or RecipientExpectation rows.
        self._upload_message_event(2, "ee" * 32)

        self.assertEqual(
            NetworkObservation.objects.filter(group=group, message_id=MSG_ID).count(), 1
        )
        artifact = DeliveryArtifact.objects.get(group=group, artifact_id=MSG_ID)
        self.assertEqual(RecipientExpectation.objects.filter(artifact=artifact).count(), 1)

    def test_inferred_convergence_run_continues_across_uploads(self):
        # An inferred run opened in one upload must be extended (not duplicated)
        # by terminal convergence evidence in a later upload. The incremental
        # state is reconstructed from the persisted run.
        ingest_audit_log_bytes(
            dump_bytes=jsonl(
                audit_event_v2(
                    0,
                    wall_time_ms=self.INCREMENTAL_T0,
                    kind={
                        "type": "convergence_run_state",
                        "phase": "evaluating",
                        "current_tip_epoch": 7,
                    },
                )
            ).encode("utf-8"),
            source_name="conv-open.jsonl",
        )

        group = AuditGroup.objects.get(slug=GROUP_REF)
        self.assertEqual(ConvergenceRun.objects.filter(group=group).count(), 1)
        opened_run = ConvergenceRun.objects.get(group=group)
        self.assertTrue(opened_run.inferred)
        self.assertEqual(opened_run.phase, "evaluating")

        ingest_audit_log_bytes(
            dump_bytes=jsonl(
                audit_event_v2(
                    1,
                    wall_time_ms=self.INCREMENTAL_T0 + 1,
                    kind={
                        "type": "epoch_state_changed",
                        "previous_state": "pending",
                        "new_state": "committed",
                        "epoch": 8,
                        "reason": "winning_commit_applied",
                    },
                )
            ).encode("utf-8"),
            source_name="conv-close.jsonl",
        )

        # Still a single inferred run, now closed onto the committed epoch with
        # both uploads' events as evidence -- not a second stray run.
        self.assertEqual(ConvergenceRun.objects.filter(group=group).count(), 1)
        run = ConvergenceRun.objects.get(group=group)
        self.assertEqual(run.id, opened_run.id)
        self.assertEqual(run.phase, "committed")
        self.assertEqual(run.evidence_events.count(), 2)

    def test_terminated_inferred_run_does_not_capture_later_uploads(self):
        # A run already closed by a terminal event in an earlier upload must NOT
        # be reopened: a later inferred convergence event starts a fresh run.
        ingest_audit_log_bytes(
            dump_bytes=jsonl(
                audit_event_v2(
                    0,
                    wall_time_ms=self.INCREMENTAL_T0,
                    kind={
                        "type": "convergence_run_state",
                        "phase": "evaluating",
                        "current_tip_epoch": 7,
                    },
                ),
                audit_event_v2(
                    1,
                    wall_time_ms=self.INCREMENTAL_T0 + 1,
                    kind={
                        "type": "epoch_state_changed",
                        "previous_state": "pending",
                        "new_state": "committed",
                        "epoch": 8,
                        "reason": "winning_commit_applied",
                    },
                ),
            ).encode("utf-8"),
            source_name="conv-run-closed.jsonl",
        )

        group = AuditGroup.objects.get(slug=GROUP_REF)
        self.assertEqual(ConvergenceRun.objects.filter(group=group).count(), 1)

        ingest_audit_log_bytes(
            dump_bytes=jsonl(
                audit_event_v2(
                    2,
                    wall_time_ms=self.INCREMENTAL_T0 + 2,
                    kind={
                        "type": "convergence_run_state",
                        "phase": "evaluating",
                        "current_tip_epoch": 8,
                    },
                )
            ).encode("utf-8"),
            source_name="conv-run-new.jsonl",
        )

        runs = list(ConvergenceRun.objects.filter(group=group).order_by("started_at_ms", "id"))
        self.assertEqual(len(runs), 2)
        self.assertEqual(runs[0].phase, "committed")
        self.assertEqual(runs[1].phase, "evaluating")
        self.assertEqual(runs[1].current_tip_epoch, 8)
        # The later evaluating event belongs only to the new run, never to the
        # already-closed earlier one.
        self.assertEqual(runs[0].evidence_events.count(), 2)
        self.assertEqual(runs[1].evidence_events.count(), 1)
        self.assertEqual(runs[1].evidence_events.get().current_tip_epoch, 8)

    def test_out_of_order_convergence_backfill_closes_inferred_run(self):
        # An upload that backfills an *older* convergence opener after a newer
        # terminal epoch event was already stored cannot be appended in place:
        # the incremental path would leave the inferred run open (`evaluating`).
        # The ordering guard must fall back to a full group rebuild so the
        # terminal epoch event still closes the run onto `committed`
        # (marmot-protocol/goggles#127).
        ingest_audit_log_bytes(
            dump_bytes=jsonl(
                audit_event_v2(
                    10,
                    wall_time_ms=self.INCREMENTAL_T0 + 10,
                    kind={
                        "type": "epoch_state_changed",
                        "previous_state": "pending",
                        "new_state": "committed",
                        "epoch": 8,
                        "reason": "winning_commit_applied",
                    },
                )
            ).encode("utf-8"),
            source_name="conv-terminal-newer.jsonl",
        )

        group = AuditGroup.objects.get(slug=GROUP_REF)
        # The terminal epoch event alone does not open an inferred run.
        self.assertEqual(ConvergenceRun.objects.filter(group=group).count(), 0)

        ingest_audit_log_bytes(
            dump_bytes=jsonl(
                audit_event_v2(
                    0,
                    wall_time_ms=self.INCREMENTAL_T0,
                    kind={
                        "type": "convergence_run_state",
                        "phase": "evaluating",
                        "current_tip_epoch": 7,
                    },
                )
            ).encode("utf-8"),
            source_name="conv-opener-older.jsonl",
        )

        # One inferred run, closed onto the committed epoch, citing both the
        # backfilled opener and the previously-stored terminal epoch event.
        runs = list(ConvergenceRun.objects.filter(group=group))
        self.assertEqual(len(runs), 1)
        run = runs[0]
        self.assertTrue(run.inferred)
        self.assertEqual(run.phase, "committed")
        self.assertEqual(run.evidence_events.count(), 2)


class ConvergenceRunApiTests(TestCase):
    def setUp(self):
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")
        self.group = AuditGroup.objects.create(
            name="Shared convergence run",
            slug=GROUP_REF,
            group_ref=GROUP_REF,
        )

    def test_convergence_run_detail_requires_engine_when_run_id_is_ambiguous(self):
        ConvergenceRun.objects.create(
            group=self.group,
            run_id="shared-run",
            engine_id=ENGINE_ALICE,
            account_ref=ACCOUNT_ALICE,
            phase="selected",
            started_at_ms=T0,
        )
        ConvergenceRun.objects.create(
            group=self.group,
            run_id="shared-run",
            engine_id=ENGINE_BOB,
            account_ref=ACCOUNT_BOB,
            phase="selected",
            started_at_ms=T0 + 1,
        )

        ambiguous_response = self.client.get(
            reverse(
                "api-group-convergence-run",
                kwargs={"slug": self.group.slug, "run_id": "shared-run"},
            )
        )

        self.assertEqual(ambiguous_response.status_code, 409)
        ambiguous_payload = ambiguous_response.json()
        self.assertEqual(
            ambiguous_payload["schema_version"],
            "goggles-convergence-run-ambiguous/v1",
        )
        self.assertEqual(ambiguous_payload["error"], "multiple_convergence_runs")
        self.assertEqual(len(ambiguous_payload["matches"]), 2)
        self.assertEqual(
            [match["engine_id"] for match in ambiguous_payload["matches"]],
            [ENGINE_ALICE, ENGINE_BOB],
        )

        disambiguated_response = self.client.get(
            reverse(
                "api-group-convergence-run",
                kwargs={"slug": self.group.slug, "run_id": "shared-run"},
            ),
            {"engine_id": ENGINE_BOB},
        )

        self.assertEqual(disambiguated_response.status_code, 200)
        self.assertEqual(
            disambiguated_response.json()["convergence_run"]["engine_id"],
            ENGINE_BOB,
        )
        self.assertEqual(disambiguated_response.json()["filters"]["engine_id"], ENGINE_BOB)


class ValidateAuditSchemaCommandTests(TestCase):
    def test_validate_audit_schema_accepts_v2_fixture(self):
        output = StringIO()

        call_command(
            "validate_audit_schema",
            "fixtures/sample-audit-log-acme-dana.jsonl",
            stdout=output,
        )

        self.assertIn("Schema validation passed for 14 event(s)", output.getvalue())

    def test_validate_audit_schema_dispatches_mixed_v2_and_v3_rows(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "mixed.jsonl"
            path.write_text(
                jsonl(
                    audit_event_v2(0),
                    audit_event_v3(
                        1,
                        kind={
                            "type": "group_state_changed",
                            "epoch": 8,
                            "change_kind": "group_disbanded",
                            "value": {"digest": DIGEST_A, "len": 9},
                        },
                    ),
                ),
                encoding="utf-8",
            )
            output = StringIO()

            call_command("validate_audit_schema", str(path), stdout=output)

        self.assertIn("Schema validation passed for 2 event(s)", output.getvalue())

    def test_validate_audit_schema_reports_non_string_schema_version(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bad-version.jsonl"
            path.write_text(
                json.dumps({"schema_version": [SCHEMA_VERSION_V3]}, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            stderr = StringIO()

            with self.assertRaisesMessage(CommandError, "Schema validation failed"):
                call_command("validate_audit_schema", str(path), stderr=stderr)

        self.assertIn("bad-version.jsonl:1:schema_version", stderr.getvalue())
        self.assertIn("unsupported schema_version", stderr.getvalue())

    def test_validate_audit_schema_reports_line_without_raw_body(self):
        with TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bad.jsonl"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": SCHEMA_VERSION_V2,
                        "seq": 1,
                        "wall_time_ms": 1,
                        "audit_data_mode": "full_data",
                        "engine_id": ENGINE_ALICE,
                        "kind": {"type": "epoch_state_changed", "new_state": "committed"},
                    },
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
            stderr = StringIO()

            with self.assertRaisesMessage(CommandError, "Schema validation failed"):
                call_command("validate_audit_schema", str(path), stderr=stderr)

        self.assertIn("bad.jsonl:1:kind", stderr.getvalue())
        self.assertIn("missing required property", stderr.getvalue())
        self.assertIn("epoch", stderr.getvalue())
        self.assertNotIn("committed", stderr.getvalue())


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

    @override_settings(GOGGLES_MAX_ACTION_EVENTS_PER_REQUEST=1)
    def test_action_api_reports_when_history_scan_is_safely_truncated(self):
        ingest_body(
            jsonl(
                audit_event(0, wall_time_ms=T0, context={"human_action": self._human_action()}),
                audit_event(
                    1,
                    wall_time_ms=T0 + 1000,
                    context={"human_action": self._human_action("rename_group")},
                ),
            )
        )
        group = AuditGroup.objects.get(slug=GROUP_REF)
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

        with CaptureQueriesContext(connection) as captured:
            response = self.client.get(reverse("api-group-actions", kwargs={"slug": group.slug}))

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["pagination"]["scan_truncated"])
        self.assertEqual(response.json()["pagination"]["scan_limit"], 1)
        self.assertEqual(heavy_bulk_selects(captured.captured_queries), [])


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

    def test_create_upload_token_command_rejects_over_max_expiry_cleanly(self):
        # Shares the bounded expiry helper with the export tokens: an overflow-scale
        # day count is a clean CommandError, not an uncaught OverflowError (PR #199).
        with self.assertRaises(CommandError):
            call_command(
                "create_upload_token", "ios qa", "--expires-in-days", str(MAX_TOKEN_EXPIRY_DAYS + 1)
            )
        self.assertFalse(UploadToken.objects.filter(name="ios qa").exists())

    @override_settings(GOGGLES_UPLOADS_ENABLED=False)
    def test_global_upload_pause_rejects_authenticated_upload_without_ingesting(self):
        raw_token, token = UploadToken.issue("ios qa")

        response = self._upload(raw_token)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["error"], "audit log uploads are temporarily disabled")
        self.assertEqual(AuditFile.objects.count(), 0)
        token.refresh_from_db()
        self.assertIsNone(token.last_used_at)


class PersonalAccessTokenTests(TestCase):
    """The user-owned, read-only credential the streaming export accepts.

    Distinct from UploadToken: self-service, read-only, and only as live as its
    owner. See authenticated-group-export.md. The shared hashing/rekey/expiry
    mechanics live in token_crypto and are exercised via UploadToken elsewhere;
    these tests cover the PersonalAccessToken-specific contract.
    """

    def setUp(self):
        self.user = User.objects.create_user(
            username="reader",
            password="correct horse battery staple",
        )

    def test_issue_returns_gpat_prefixed_token_and_stores_only_the_hash(self):
        raw_token, token = PersonalAccessToken.issue("cgka laptop", user=self.user)

        self.assertTrue(raw_token.startswith("gpat_"))
        self.assertEqual(token.user, self.user)
        # The raw secret is shown once and never persisted; only its hash is stored.
        secret = raw_token.split("_", 2)[2]
        self.assertNotIn(secret, token.token_hash)
        self.assertEqual(token.token_hash, PersonalAccessToken.objects.get(pk=token.pk).token_hash)

    def test_issued_lookup_prefix_fills_the_field_without_exceeding_it(self):
        # PR #199: the lookup prefix is 16 hex chars (64 bits), filling
        # token_prefix's max_length=16 — wide enough that an accidental
        # unique-collision on issuance (which does not retry) is negligible.
        _raw_token, token = PersonalAccessToken.issue("prefix width", user=self.user)
        field_max = PersonalAccessToken._meta.get_field("token_prefix").max_length
        self.assertEqual(len(token.token_prefix), 16)
        self.assertLessEqual(len(token.token_prefix), field_max)

    def test_authenticate_round_trips_a_freshly_issued_token(self):
        raw_token, token = PersonalAccessToken.issue("cgka laptop", user=self.user)
        self.assertEqual(PersonalAccessToken.authenticate(raw_token).pk, token.pk)

    def test_inactive_token_is_rejected(self):
        raw_token, token = PersonalAccessToken.issue("revoked", user=self.user)
        token.is_active = False
        token.save(update_fields=["is_active"])
        self.assertIsNone(PersonalAccessToken.authenticate(raw_token))

    def test_expired_token_is_rejected(self):
        raw_token, _token = PersonalAccessToken.issue(
            "stale", user=self.user, expires_at=timezone.now() - timedelta(seconds=1)
        )
        self.assertIsNone(PersonalAccessToken.authenticate(raw_token))

    def test_token_of_deactivated_user_is_rejected(self):
        # A token is only as live as its owner — unique to PersonalAccessToken.
        raw_token, _token = PersonalAccessToken.issue("cgka laptop", user=self.user)
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        self.assertIsNone(PersonalAccessToken.authenticate(raw_token))

    def test_upload_and_personal_tokens_never_cross_authenticate(self):
        # Distinct type prefixes (goggles_ vs gpat_) make the two families
        # structurally un-confusable at authenticate().
        upload_raw, _token = UploadToken.issue("device")
        pat_raw, _pat = PersonalAccessToken.issue("laptop", user=self.user)

        self.assertIsNone(PersonalAccessToken.authenticate(upload_raw))
        self.assertIsNone(UploadToken.authenticate(pat_raw))

    def test_mark_used_records_last_used_at_without_revoking(self):
        _raw_token, token = PersonalAccessToken.issue("cgka laptop", user=self.user)
        self.assertIsNone(token.last_used_at)

        token.mark_used()

        token.refresh_from_db()
        self.assertIsNotNone(token.last_used_at)
        self.assertTrue(token.is_active)


class StreamNdjsonTests(SimpleTestCase):
    """The domain-blind NDJSON serializer: manifest-first, typed rows, and a
    fail-closed eof/error terminator. See forensics/streaming.py."""

    @staticmethod
    def _rows(items, *, raise_at=None):
        """A minimal QuerySet stand-in exposing just ``.iterator(chunk_size=)``."""

        class _FakeRows:
            def iterator(self, chunk_size):
                # The serializer must always pass a chunk_size — prefetch_related
                # querysets require it under .iterator().
                assert chunk_size, "stream_ndjson must forward a chunk_size"
                for index, item in enumerate(items):
                    if raise_at is not None and index == raise_at:
                        raise RuntimeError("db cursor died mid-stream")
                    yield item

        return _FakeRows()

    def _records(self, manifest, sections):
        return [json.loads(line) for line in stream_ndjson(manifest, sections)]

    def test_manifest_first_then_typed_rows_then_eof_with_counts(self):
        sections = [
            ExportSection("event", self._rows([{"id": 1}, {"id": 2}]), lambda row: row),
            ExportSection("source", self._rows([{"id": 9}]), lambda row: row),
        ]

        records = self._records({"schema_version": "goggles-group-export/v1"}, sections)

        self.assertEqual(records[0]["t"], "manifest")
        self.assertEqual(records[0]["schema_version"], "goggles-group-export/v1")
        self.assertEqual([r["t"] for r in records[1:4]], ["event", "event", "source"])
        self.assertEqual(
            records[-1],
            {"t": "eof", "complete": True, "counts": {"event": 2, "source": 1}},
        )

    def test_empty_section_still_reports_complete_with_zero_count(self):
        records = self._records({}, [ExportSection("event", self._rows([]), lambda row: row)])
        self.assertEqual(records[-1], {"t": "eof", "complete": True, "counts": {"event": 0}})

    def test_mid_stream_error_yields_error_line_and_no_eof(self):
        sections = [
            ExportSection("event", self._rows([{"id": 1}, {"id": 2}], raise_at=1), lambda row: row),
        ]

        with self.assertLogs("forensics.streaming", level="ERROR"):
            records = self._records({}, sections)

        self.assertEqual(records[1], {"t": "event", "id": 1})  # the row before the failure streamed
        self.assertEqual(records[-1], {"t": "error", "complete": False})
        self.assertNotIn("eof", [record["t"] for record in records])

    def test_t_discriminator_leads_every_line(self):
        # No sort_keys: a consumer may route by the line's leading key.
        lines = list(
            stream_ndjson(
                {"schema_version": "goggles-group-export/v1"},
                [ExportSection("event", self._rows([{"z": 1}]), lambda row: row)],
            )
        )
        for line in lines:
            self.assertTrue(line.startswith('{"t":'), line)


class TokenExpiryFromDaysTests(SimpleTestCase):
    """The shared bounded expiry helper (PR #199): a positive, sane day count →
    future datetime; non-positive, over-ceiling, or overflow-scale → ValueError
    raised *before* any timedelta arithmetic, so it never leaks an OverflowError."""

    def test_positive_days_within_bound_returns_future_datetime(self):
        before = timezone.now()
        self.assertGreaterEqual(expiry_from_days(7), before + timedelta(days=7))

    def test_ceiling_is_allowed(self):
        self.assertIsNotNone(expiry_from_days(MAX_TOKEN_EXPIRY_DAYS))

    def test_rejects_non_positive(self):
        for days in (0, -1):
            with self.subTest(days=days), self.assertRaises(ValueError):
                expiry_from_days(days)

    def test_rejects_over_ceiling_and_overflow_scale_as_valueerror(self):
        # 99_999_999_999 would raise OverflowError at timedelta(); the bound check
        # must catch it as a ValueError first.
        for days in (MAX_TOKEN_EXPIRY_DAYS + 1, 99_999_999_999):
            with self.subTest(days=days), self.assertRaises(ValueError):
                expiry_from_days(days)


class DeliveryIdentityIndexTests(TestCase):
    """delivery_identity_index collects distinct identities via bounded SQL, not a
    Python scan of every event (B1 in authenticated-group-export.md). Output must
    match the previous implementation exactly — it is shared with the delivery tab.
    """

    def _valid_event(self, group, audit_file, seq, **fields):
        return AuditEvent.objects.create(
            audit_file=audit_file,
            group=group,
            line_number=seq,
            line_hash=f"{seq:064d}",
            raw_line="{}",
            parse_status=AuditEvent.STATUS_VALID,
            event_type="transport_received",
            group_ref=GROUP_REF,
            seq=seq,
            wall_time_ms=1_700_000_000_000 + seq,
            **fields,
        )

    def test_collects_distinct_identities_from_events_files_and_context(self):
        group = AuditGroup.objects.create(name="G", slug="g", group_ref=GROUP_REF)
        file_with_pubkey = AuditFile.objects.create(
            file_sha256="a" * 64,
            byte_size=1,
            raw_text="{}",
            validation_status=AuditFile.STATUS_VALID,
            source_account_pubkey_hex="ff" * 32,
        )
        file_with_pubkey.groups.add(group)
        plain_file = AuditFile.objects.create(
            file_sha256="b" * 64,
            byte_size=1,
            raw_text="{}",
            validation_status=AuditFile.STATUS_VALID,
        )
        plain_file.groups.add(group)

        # Duplicates across events collapse; the account pubkey is drawn from both
        # the backing file and the event's context_source JSON.
        self._valid_event(
            group, file_with_pubkey, 1, account_ref=ACCOUNT_ALICE, engine_id=ENGINE_ALICE
        )
        self._valid_event(
            group, file_with_pubkey, 2, account_ref=ACCOUNT_ALICE, engine_id=ENGINE_ALICE
        )
        self._valid_event(
            group,
            plain_file,
            3,
            account_ref=ACCOUNT_BOB,
            engine_id=ENGINE_BOB,
            context_source={"account_pubkey_hex": "cc" * 32},
        )
        # An event with blank identity fields contributes nothing.
        self._valid_event(group, plain_file, 4)

        index = delivery_identity_index(group)

        self.assertEqual(index["account_refs"], {ACCOUNT_ALICE, ACCOUNT_BOB})
        self.assertEqual(index["engine_ids"], {ENGINE_ALICE, ENGINE_BOB})
        self.assertEqual(index["pubkeys_hex"], {"ff" * 32, "cc" * 32})

    def test_ignores_invalid_events(self):
        group = AuditGroup.objects.create(name="G", slug="g", group_ref=GROUP_REF)
        audit_file = AuditFile.objects.create(
            file_sha256="a" * 64,
            byte_size=1,
            raw_text="{}",
            validation_status=AuditFile.STATUS_VALID,
            source_account_pubkey_hex="ff" * 32,
        )
        audit_file.groups.add(group)
        AuditEvent.objects.create(
            audit_file=audit_file,
            group=group,
            line_number=1,
            line_hash="1".ljust(64, "0"),
            raw_line="{}",
            parse_status=AuditEvent.STATUS_INVALID,
            event_type="transport_received",
            account_ref=ACCOUNT_ALICE,
            engine_id=ENGINE_ALICE,
            group_ref=GROUP_REF,
            seq=1,
            wall_time_ms=1,
        )

        self.assertEqual(
            delivery_identity_index(group),
            {"account_refs": set(), "engine_ids": set(), "pubkeys_hex": set()},
        )

    def test_distinct_queries_do_not_leak_auditevent_ordering(self):
        # AuditEvent has Meta.ordering; if it leaks into SELECT DISTINCT the query
        # dedupes per row (id is unique) and scans every event, defeating the
        # bounded-by-cardinality guarantee. order_by() must keep it out.
        group = AuditGroup.objects.create(name="G", slug="g", group_ref=GROUP_REF)
        audit_file = AuditFile.objects.create(
            file_sha256="a" * 64,
            byte_size=1,
            raw_text="{}",
            validation_status=AuditFile.STATUS_VALID,
            source_account_pubkey_hex="ff" * 32,
        )
        audit_file.groups.add(group)
        for seq in range(5):  # many events, a single identity
            self._valid_event(
                group, audit_file, seq, account_ref=ACCOUNT_ALICE, engine_id=ENGINE_ALICE
            )

        with CaptureQueriesContext(connection) as queries:
            index = delivery_identity_index(group)

        self.assertEqual(index["account_refs"], {ACCOUNT_ALICE})
        self.assertTrue(queries.captured_queries)
        for query in queries.captured_queries:
            self.assertNotIn("ORDER BY", query["sql"].upper())


class GroupExportStreamTests(TestCase):
    """The authenticated NDJSON streaming export. See authenticated-group-export.md."""

    def setUp(self):
        ingest_audit_log_bytes(dump_bytes=representative_audit_log().encode("utf-8"))
        self.group = AuditGroup.objects.get(slug=GROUP_REF)
        self.user = User.objects.create_user(
            username="reader", password="correct horse battery staple"
        )
        self.url = reverse("api-group-export-stream", kwargs={"slug": self.group.slug})

    @staticmethod
    def _records(response):
        body = b"".join(response.streaming_content).decode("utf-8")
        return [json.loads(line) for line in body.splitlines() if line]

    def test_requires_authentication(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 401)

    def test_rejects_invalid_bearer_token(self):
        response = self.client.get(self.url, HTTP_AUTHORIZATION="Bearer gpat_deadbeef_nope")
        self.assertEqual(response.status_code, 401)

    def test_rejects_expired_personal_access_token(self):
        raw_token, _token = PersonalAccessToken.issue(
            "stale", user=self.user, expires_at=timezone.now() - timedelta(seconds=1)
        )
        response = self.client.get(self.url, HTTP_AUTHORIZATION=f"Bearer {raw_token}")
        self.assertEqual(response.status_code, 401)

    def test_upload_token_cannot_read_the_export(self):
        # Least privilege: an upload credential can never read forensic data.
        raw_token, _token = UploadToken.issue("device")
        response = self.client.get(self.url, HTTP_AUTHORIZATION=f"Bearer {raw_token}")
        self.assertEqual(response.status_code, 401)

    def test_streams_with_personal_access_token_and_records_last_used(self):
        raw_token, token = PersonalAccessToken.issue("cgka", user=self.user)

        response = self.client.get(self.url, HTTP_AUTHORIZATION=f"Bearer {raw_token}")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/x-ndjson")
        self.assertIn("attachment", response["Content-Disposition"])
        self.assertEqual(response["Cache-Control"], "no-store")
        records = self._records(response)
        self.assertEqual(records[0]["t"], "manifest")
        self.assertEqual(records[-1]["t"], "eof")
        self.assertTrue(records[-1]["complete"])
        token.refresh_from_db()
        self.assertIsNotNone(token.last_used_at)

    def test_streams_with_logged_in_session(self):
        self.client.login(username="reader", password="correct horse battery staple")

        records = self._records(self.client.get(self.url))

        self.assertEqual(records[0]["t"], "manifest")
        self.assertEqual(records[-1]["t"], "eof")

    def test_manifest_advertises_sections_and_eof_counts_are_accurate(self):
        self.client.login(username="reader", password="correct horse battery staple")

        records = self._records(self.client.get(self.url))

        manifest, eof = records[0], records[-1]
        self.assertEqual(manifest["schema_version"], GROUP_EXPORT_SCHEMA_VERSION)
        self.assertEqual(manifest["sensitivity"], EXPORT_SENSITIVITY)
        # The export is unconditionally complete: it advertises no filter contract.
        self.assertNotIn("filters", manifest)

        # Advertised sections are exactly the record types the stream can emit,
        # and eof.counts match the rows actually streamed.
        body_records = records[1:-1]
        for record_type, count in eof["counts"].items():
            self.assertIn(record_type, manifest["sections"])
            self.assertEqual(sum(1 for record in body_records if record["t"] == record_type), count)
        # The representative log yields at least its source file and its events.
        self.assertGreaterEqual(eof["counts"]["source"], 1)
        self.assertGreaterEqual(eof["counts"]["event"], 1)

    def test_streams_every_row_past_the_projection_page_cap(self):
        # The paginated projections API caps a section at GROUP_PROJECTION_API_DEFAULT_LIMIT
        # (100). The export must stream every row — this is its reason to exist.
        over_cap = GROUP_PROJECTION_API_DEFAULT_LIMIT + 1
        evidence_event = AuditEvent.objects.filter(
            group=self.group, parse_status=AuditEvent.STATUS_VALID
        ).first()
        StateDelta.objects.bulk_create(
            [
                StateDelta(
                    group=self.group,
                    audit_event=evidence_event,
                    epoch=i,
                    change_kind=f"state-marker-{i:04d}",
                    wall_time_ms=1_700_000_300_000 + i,
                )
                for i in range(over_cap)
            ]
        )
        self.client.login(username="reader", password="correct horse battery staple")

        records = self._records(self.client.get(self.url))

        self.assertGreaterEqual(records[-1]["counts"]["state_delta"], over_cap)

    def test_query_filters_are_ignored_export_is_always_complete(self):
        # Regression (PR #199): the manifest advertised filters that only some
        # sections honored — projections were filtered while events/sources were not,
        # and severity/convergence message_id were dropped entirely. The export now
        # ignores query filters: the same complete group whether or not they are sent.
        alice_event = AuditEvent.objects.filter(
            group=self.group, parse_status=AuditEvent.STATUS_VALID, engine_id=ENGINE_ALICE
        ).first()
        StateDelta.objects.create(
            group=self.group,
            audit_event=alice_event,
            epoch=0,
            change_kind="group_renamed",
            wall_time_ms=1_700_000_300_000,
        )
        self.client.login(username="reader", password="correct horse battery staple")

        unfiltered = self._records(self.client.get(self.url))
        # A real engine filter that only projections honored would drop the state_delta
        # above (its event is ENGINE_ALICE), leaving events untouched — the old split.
        filtered = self._records(
            self.client.get(self.url, {"engine_id": "ff" * 16, "severity": "error"})
        )

        self.assertNotIn("filters", unfiltered[0])
        self.assertEqual(unfiltered[-1]["counts"], filtered[-1]["counts"])
        self.assertGreaterEqual(unfiltered[-1]["counts"]["state_delta"], 1)

    @override_settings(GOGGLES_EXPORTS_ENABLED=False)
    def test_disabled_export_returns_503(self):
        raw_token, _token = PersonalAccessToken.issue("cgka", user=self.user)
        response = self.client.get(self.url, HTTP_AUTHORIZATION=f"Bearer {raw_token}")
        self.assertEqual(response.status_code, 503)

    def test_unknown_group_slug_returns_404(self):
        raw_token, _token = PersonalAccessToken.issue("cgka", user=self.user)
        response = self.client.get(
            reverse("api-group-export-stream", kwargs={"slug": "not-a-real-slug"}),
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
        )
        self.assertEqual(response.status_code, 404)

    def _seed_prefetch_heavy_rows(self, count, evidence_event):
        """Add `count` delivery artifacts and convergence runs, each with the related
        rows their payloads iterate (expectations/observations, candidates/rules)."""
        start = DeliveryArtifact.objects.filter(group=self.group).count()
        for i in range(start, start + count):
            artifact = DeliveryArtifact.objects.create(
                group=self.group,
                artifact_id=f"{i:064x}",
                artifact_kind="application_message",
                first_seen_ms=1_700_000_000_000 + i,
            )
            RecipientExpectation.objects.create(
                artifact=artifact, recipient_scope="group", evidence_event=evidence_event
            )
            DeliveryObservation.objects.create(
                artifact=artifact, engine_id=ENGINE_ALICE, latest_state="transport_received"
            )
            run = ConvergenceRun.objects.create(
                group=self.group,
                run_id=f"run-{i:04x}",
                engine_id=ENGINE_ALICE,
                started_at_ms=1_700_000_200_000 + i,
            )
            ConvergenceCandidate.objects.create(
                run=run, branch_id=f"branch-{i}", fork_epoch=i, tip_epoch=i + 1
            )
            ConvergenceRuleEvaluation.objects.create(run=run, rule_name="highest_weight")

    def _export_query_count(self):
        self.client.login(username="reader", password="correct horse battery staple")
        with CaptureQueriesContext(connection) as queries:
            response = self.client.get(self.url)
            list(response.streaming_content)  # force the generator to run
        return len(queries.captured_queries)

    def test_export_query_count_is_flat_in_row_count(self):
        # Adversarial finding #1 claimed iterator() drops prefetch_related → N+1. That
        # is false on Django 6 when chunk_size is passed (it is): prefetch is honored,
        # so multiplying the prefetch-heavy rows must not add queries. If a future edit
        # drops chunk_size, this turns linear and fails.
        event = AuditEvent.objects.filter(
            group=self.group, parse_status=AuditEvent.STATUS_VALID
        ).first()
        self._seed_prefetch_heavy_rows(3, event)
        few = self._export_query_count()
        self._seed_prefetch_heavy_rows(9, event)  # 12 total — 4× the artifacts and runs
        many = self._export_query_count()
        self.assertEqual(few, many)

    def test_mid_stream_error_yields_error_line_and_no_eof_within_a_200(self):
        # Once the manifest is sent the status is committed at 200, so a later
        # failure can only be signalled in-band: an error line and no eof (M4).
        self.client.login(username="reader", password="correct horse battery staple")

        with mock.patch(
            "forensics.views.agent_event_row",
            side_effect=RuntimeError("db cursor died mid-stream"),
        ):
            with self.assertLogs("forensics.streaming", level="ERROR"):
                response = self.client.get(self.url)
                records = self._records(response)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(records[0]["t"], "manifest")
        # Rows emitted before the failure still streamed (sources precede events).
        self.assertTrue(any(record["t"] == "source" for record in records))
        self.assertEqual(records[-1], {"t": "error", "complete": False})
        self.assertNotIn("eof", {record["t"] for record in records})


class GroupListApiAuthTests(TestCase):
    """Group discovery over the JSON API. Same reader contract as the streaming
    export: a logged-in session or a personal access token, never an upload token."""

    def setUp(self):
        # Three groups, not one: with a single row the slug-list and byte-identity
        # assertions below cannot catch an ordering, duplication, or row-leak
        # regression. AuditGroup.Meta.ordering is ["-updated_at", "-created_at"],
        # so the index is the reverse of ingestion order.
        ingest_audit_log_bytes(dump_bytes=representative_audit_log().encode("utf-8"))
        for group_ref in (OTHER_GROUP_REF, THIRD_GROUP_REF):
            ingest_audit_log_bytes(
                dump_bytes=jsonl(
                    audit_event(
                        0,
                        engine_id=ENGINE_BOB,
                        group_ref=group_ref,
                        account_ref=ACCOUNT_BOB,
                    )
                ).encode("utf-8")
            )
        self.group = AuditGroup.objects.get(slug=GROUP_REF)
        self.expected_slugs = [THIRD_GROUP_REF, OTHER_GROUP_REF, GROUP_REF]
        self.user = User.objects.create_user(
            username="reader", password="correct horse battery staple"
        )
        self.url = reverse("api-group-list")

    def test_requires_authentication(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"error": "authentication required"})

    def test_rejects_invalid_bearer_token(self):
        response = self.client.get(self.url, HTTP_AUTHORIZATION="Bearer gpat_deadbeef_nope")
        self.assertEqual(response.status_code, 401)

    def test_rejects_malformed_authorization_header(self):
        response = self.client.get(self.url, HTTP_AUTHORIZATION="Token gpat_deadbeef_nope")
        self.assertEqual(response.status_code, 401)

    def test_rejects_revoked_personal_access_token(self):
        raw_token, token = PersonalAccessToken.issue("revoked", user=self.user)
        token.is_active = False
        token.save(update_fields=["is_active"])

        response = self.client.get(self.url, HTTP_AUTHORIZATION=f"Bearer {raw_token}")
        self.assertEqual(response.status_code, 401)

    def test_rejects_expired_personal_access_token(self):
        raw_token, _token = PersonalAccessToken.issue(
            "stale", user=self.user, expires_at=timezone.now() - timedelta(seconds=1)
        )
        response = self.client.get(self.url, HTTP_AUTHORIZATION=f"Bearer {raw_token}")
        self.assertEqual(response.status_code, 401)

    def test_rejects_token_of_deactivated_user(self):
        raw_token, _token = PersonalAccessToken.issue("cgka", user=self.user)
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        response = self.client.get(self.url, HTTP_AUTHORIZATION=f"Bearer {raw_token}")
        self.assertEqual(response.status_code, 401)

    def test_upload_token_cannot_list_groups(self):
        # Pins the view-level contract: authenticate_reader() accepts only the
        # personal-access-token family, so widening it to upload tokens turns this
        # 401 into a 200. The crypto-layer prefix guard that keeps the two token
        # families structurally un-confusable is covered separately, by
        # PersonalAccessTokenTests.test_upload_and_personal_tokens_never_cross_authenticate.
        raw_token, _token = UploadToken.issue("device")
        response = self.client.get(self.url, HTTP_AUTHORIZATION=f"Bearer {raw_token}")
        self.assertEqual(response.status_code, 401)

    def test_personal_access_token_is_refused_by_session_only_group_endpoints(self):
        """A personal access token authorizes exactly two endpoints — this index and
        the streaming group export. Every other read endpoint stays session-only.

        docs/api-v1.md and AGENTS.md both state that "exactly two" claim, and nothing
        else in the suite defends it: swapping @login_required for authenticate_reader
        on one of these views would otherwise leave the suite green and both documents
        silently false. Widening an endpoint on purpose means updating those docs too.
        """
        raw_token, _token = PersonalAccessToken.issue("cgka", user=self.user)

        for name, kwargs in (
            ("api-group-detail", {"slug": self.group.slug}),
            ("api-account-groups", {"account_ref": ACCOUNT_ALICE}),
            ("api-engine-groups", {"engine_id": ENGINE_ALICE}),
        ):
            with self.subTest(endpoint=name):
                response = self.client.get(
                    reverse(name, kwargs=kwargs), HTTP_AUTHORIZATION=f"Bearer {raw_token}"
                )
                # @login_required sees an anonymous request and redirects to the
                # login page; the token buys no access here.
                self.assertEqual(response.status_code, 302)
                self.assertTrue(response["Location"].startswith("/accounts/login/"))

    def test_lists_groups_with_logged_in_session(self):
        self.client.login(username="reader", password="correct horse battery staple")

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["schema_version"], "goggles-groups/v1")
        self.assertEqual([group["slug"] for group in payload["groups"]], self.expected_slugs)

    def test_lists_groups_with_personal_access_token_and_records_last_used(self):
        raw_token, token = PersonalAccessToken.issue("cgka", user=self.user)

        response = self.client.get(self.url, HTTP_AUTHORIZATION=f"Bearer {raw_token}")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["schema_version"], "goggles-groups/v1")
        self.assertEqual([group["slug"] for group in payload["groups"]], self.expected_slugs)
        token.refresh_from_db()
        self.assertIsNotNone(token.last_used_at)

    def test_personal_access_token_and_session_return_identical_bytes(self):
        # The discovery payload is the same evidence however the reader
        # authenticated, so the two paths must agree byte for byte.
        raw_token, _token = PersonalAccessToken.issue("cgka", user=self.user)

        token_response = self.client.get(self.url, HTTP_AUTHORIZATION=f"Bearer {raw_token}")

        self.client.login(username="reader", password="correct horse battery staple")
        self.assertEqual(token_response.content, self.client.get(self.url).content)

    def test_response_is_uncacheable_and_varies_on_both_credential_sources(self):
        # A shared cache must not key the token-authenticated index — which carries
        # no Cookie — under the anonymous key and replay it to the next caller.
        raw_token, _token = PersonalAccessToken.issue("cgka", user=self.user)

        response = self.client.get(self.url, HTTP_AUTHORIZATION=f"Bearer {raw_token}")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Cache-Control"], "no-store")
        vary = {value.strip().lower() for value in response["Vary"].split(",")}
        self.assertEqual(vary, {"cookie", "authorization"})


class ProfileAccessTokenTests(TestCase):
    """Self-service personal access tokens on the profile page — strictly
    owner-scoped: a user can only see, mint, and revoke their own."""

    def setUp(self):
        self.user = User.objects.create_user(
            username="reader", password="correct horse battery staple"
        )
        self.other = User.objects.create_user(
            username="other", password="correct horse battery staple"
        )
        self.client.login(username="reader", password="correct horse battery staple")

    def test_profile_lists_only_the_callers_tokens(self):
        _raw, mine = PersonalAccessToken.issue("mine-laptop", user=self.user)
        PersonalAccessToken.issue("their-laptop", user=self.other)

        response = self.client.get(reverse("profile"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "mine-laptop")
        self.assertNotContains(response, "their-laptop")
        self.assertEqual(list(response.context["access_tokens"]), [mine])

    def test_create_token_shows_secret_once_and_owns_it(self):
        response = self.client.post(reverse("create-access-token"), {"name": "cgka pipeline"})

        self.assertEqual(response.status_code, 200)
        # The page shows the raw secret once, so it must not be cached anywhere.
        self.assertEqual(response["Cache-Control"], "no-store")
        token = PersonalAccessToken.objects.get(user=self.user, name="cgka pipeline")
        raw_token = response.context["new_token"]
        self.assertTrue(raw_token.startswith("gpat_"))
        self.assertContains(response, raw_token)  # shown exactly once, in the page
        self.assertEqual(PersonalAccessToken.authenticate(raw_token).pk, token.pk)

    def test_create_token_honors_optional_expiry(self):
        before = timezone.now()
        self.client.post(reverse("create-access-token"), {"name": "temp", "expires_in_days": "7"})
        token = PersonalAccessToken.objects.get(user=self.user, name="temp")
        self.assertIsNotNone(token.expires_at)
        self.assertGreaterEqual(token.expires_at, before + timedelta(days=7))

    def test_create_token_defaults_to_no_expiry(self):
        self.client.post(reverse("create-access-token"), {"name": "forever"})
        token = PersonalAccessToken.objects.get(user=self.user, name="forever")
        self.assertIsNone(token.expires_at)

    def test_create_token_rejects_invalid_expiry_and_mints_nothing(self):
        # Regression (PR #199): a crafted POST bypasses the input's min=1, so a
        # non-positive, unparseable, or absurdly large expiry must be rejected — never
        # silently minting a permanent read credential, and never crashing on the
        # OverflowError a huge day count would otherwise raise. Blank still means "never
        # expires" (tested above).
        for bad_value in ("0", "-5", "abc", "99999999999"):
            with self.subTest(expires_in_days=bad_value):
                response = self.client.post(
                    reverse("create-access-token"),
                    {"name": "sneaky", "expires_in_days": bad_value},
                )
                self.assertEqual(response.status_code, 200)
                self.assertFalse(
                    PersonalAccessToken.objects.filter(user=self.user, name="sneaky").exists()
                )

    def test_revoke_deactivates_own_token(self):
        _raw, token = PersonalAccessToken.issue("mine", user=self.user)

        response = self.client.post(reverse("revoke-access-token", kwargs={"pk": token.pk}))

        self.assertRedirects(response, reverse("profile"))
        token.refresh_from_db()
        self.assertFalse(token.is_active)

    def test_cannot_revoke_another_users_token(self):
        _raw, victim = PersonalAccessToken.issue("theirs", user=self.other)

        response = self.client.post(reverse("revoke-access-token", kwargs={"pk": victim.pk}))

        self.assertEqual(response.status_code, 404)
        victim.refresh_from_db()
        self.assertTrue(victim.is_active)

    def test_token_endpoints_require_login(self):
        self.client.logout()

        response = self.client.post(reverse("create-access-token"), {"name": "x"})

        self.assertEqual(response.status_code, 302)  # redirect to login
        self.assertEqual(PersonalAccessToken.objects.count(), 0)

    def test_password_change_still_works_after_refactor(self):
        response = self.client.post(
            reverse("profile"),
            {
                "old_password": "correct horse battery staple",
                "new_password1": "a-fresh-passphrase-9271",
                "new_password2": "a-fresh-passphrase-9271",
            },
        )

        self.assertRedirects(response, reverse("profile"))
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("a-fresh-passphrase-9271"))


class CreateAccessTokenCommandTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="svc-cgka", password="correct horse battery staple"
        )

    def test_creates_read_token_owned_by_named_user(self):
        out = StringIO()
        call_command("create_access_token", "cgka pipeline", "--user", "svc-cgka", stdout=out)

        token = PersonalAccessToken.objects.get(name="cgka pipeline")
        self.assertEqual(token.user, self.user)
        self.assertIsNone(token.expires_at)
        raw_token = out.getvalue().strip().splitlines()[-1]
        self.assertTrue(raw_token.startswith("gpat_"))
        self.assertEqual(PersonalAccessToken.authenticate(raw_token).pk, token.pk)

    def test_expiry_flag_sets_expires_at(self):
        out = StringIO()
        before = timezone.now()
        call_command(
            "create_access_token",
            "temp",
            "--user",
            "svc-cgka",
            "--expires-in-days",
            "7",
            stdout=out,
        )
        token = PersonalAccessToken.objects.get(name="temp")
        self.assertGreaterEqual(token.expires_at, before + timedelta(days=7))

    def test_unknown_user_errors(self):
        with self.assertRaises(CommandError):
            call_command("create_access_token", "x", "--user", "nobody")

    def test_non_positive_expiry_errors(self):
        with self.assertRaises(CommandError):
            call_command("create_access_token", "x", "--user", "svc-cgka", "--expires-in-days", "0")

    def test_over_max_expiry_errors_cleanly(self):
        # A day count that would overflow timedelta/datetime is rejected as a clean
        # CommandError, not an uncaught OverflowError (PR #199).
        with self.assertRaises(CommandError):
            call_command(
                "create_access_token",
                "x",
                "--user",
                "svc-cgka",
                "--expires-in-days",
                str(MAX_TOKEN_EXPIRY_DAYS + 1),
            )
        self.assertFalse(PersonalAccessToken.objects.filter(name="x").exists())


class PurgeAuditDataCommandTests(TestCase):
    def seed_audit_data(self):
        user = User.objects.create_user(
            username="analyst",
            password="correct horse battery staple",
        )
        _raw_token, token = UploadToken.issue("ios qa")
        audit_file = ingest_audit_log_bytes(
            dump_bytes=representative_audit_log().encode("utf-8"),
            upload_token=token,
        ).audit_file
        group = AuditGroup.objects.get(slug=GROUP_REF)
        artifact = DeliveryArtifact.objects.create(
            group=group,
            artifact_id=MSG_ID,
            artifact_kind="application_message",
        )
        DeliveryObservation.objects.create(
            artifact=artifact,
            engine_id=ENGINE_ALICE,
            account_ref=ACCOUNT_ALICE,
            latest_state="transport_received",
        )
        AnalysisRun.objects.create(
            group=group,
            created_by=user,
            title="pre-cutover report",
            report_json={"schema_version": "test-report/v1"},
        )
        return user, token, audit_file, group

    def test_refuses_without_confirmation(self):
        _user, _token, audit_file, _group = self.seed_audit_data()

        with self.assertRaises(CommandError):
            call_command("purge_audit_data", stdout=StringIO())

        self.assertEqual(AuditFile.objects.count(), 1)
        self.assertEqual(AuditEvent.objects.count(), audit_file.valid_event_count)
        self.assertEqual(AuditGroup.objects.count(), 1)
        self.assertEqual(AnalysisRun.objects.count(), 1)

    def test_dry_run_does_not_delete_audit_data(self):
        _user, _token, audit_file, _group = self.seed_audit_data()
        out = StringIO()

        call_command("purge_audit_data", "--dry-run", stdout=out)

        self.assertIn("Dry run only", out.getvalue())
        self.assertEqual(AuditFile.objects.count(), 1)
        self.assertEqual(AuditEvent.objects.count(), audit_file.valid_event_count)
        self.assertEqual(AuditGroup.objects.count(), 1)
        self.assertEqual(DeliveryArtifact.objects.count(), 1)
        self.assertEqual(AnalysisRun.objects.count(), 1)

    def test_confirmed_purge_deletes_audit_data_but_preserves_users_and_tokens(self):
        user, token, _audit_file, _group = self.seed_audit_data()
        out = StringIO()

        call_command("purge_audit_data", "--confirm-delete-audit-data", stdout=out)

        self.assertIn("Audit data purge complete", out.getvalue())
        self.assertEqual(AuditFile.objects.count(), 0)
        self.assertEqual(AuditEvent.objects.count(), 0)
        self.assertEqual(AuditGroup.objects.count(), 0)
        self.assertEqual(DeliveryArtifact.objects.count(), 0)
        self.assertEqual(DeliveryObservation.objects.count(), 0)
        self.assertEqual(AnalysisRun.objects.count(), 0)
        self.assertTrue(User.objects.filter(pk=user.pk).exists())
        self.assertTrue(UploadToken.objects.filter(pk=token.pk).exists())


class PruneAuditDataCommandTests(TransactionTestCase):
    def ingest_paired_evidence(self):
        """One group holding a 20-day-old upload and a fresh upload."""
        _raw_token, token = UploadToken.issue("ios qa")
        old_file = ingest_audit_log_bytes(
            dump_bytes=representative_audit_log(engine_id=ENGINE_ALICE).encode("utf-8"),
            upload_token=token,
        ).audit_file
        recent_file = ingest_audit_log_bytes(
            dump_bytes=representative_audit_log(engine_id=ENGINE_BOB).encode("utf-8"),
            upload_token=token,
        ).audit_file
        AuditFile.objects.filter(pk=old_file.pk).update(
            created_at=timezone.now() - timedelta(days=20)
        )
        group = AuditGroup.objects.get(slug=GROUP_REF)
        return old_file, recent_file, group

    def test_prunes_stale_evidence_rebuilds_and_keeps_fresh_group(self):
        old_file, recent_file, group = self.ingest_paired_evidence()
        out = StringIO()

        call_command("prune_audit_data", stdout=out)

        self.assertIn("rebuilt projections for", out.getvalue())
        self.assertFalse(AuditFile.objects.filter(pk=old_file.pk).exists())
        self.assertTrue(AuditFile.objects.filter(pk=recent_file.pk).exists())
        self.assertQuerySetEqual(
            AuditEvent.objects.all(),
            AuditEvent.objects.filter(audit_file=recent_file),
            ordered=False,
        )
        # The group survives and its projections re-derive from retained evidence.
        self.assertTrue(AuditGroup.objects.filter(pk=group.pk).exists())
        self.assertTrue(NetworkObservation.objects.filter(group=group).exists())

    def test_dry_run_reports_and_deletes_nothing(self):
        old_file, _recent_file, _group = self.ingest_paired_evidence()

        call_command("prune_audit_data", "--dry-run", stdout=StringIO())

        self.assertTrue(AuditFile.objects.filter(pk=old_file.pk).exists())

    def test_retention_days_override_spans_both_files(self):
        old_file, recent_file, _group = self.ingest_paired_evidence()

        call_command("prune_audit_data", "--retention-days", "21", stdout=StringIO())

        self.assertTrue(AuditFile.objects.filter(pk=old_file.pk).exists())
        self.assertTrue(AuditFile.objects.filter(pk=recent_file.pk).exists())

    def test_retention_days_zero_is_rejected(self):
        with self.assertRaises(CommandError):
            call_command("prune_audit_data", "--retention-days", "0", stdout=StringIO())

    def test_retention_default_uses_setting(self):
        with override_settings(GOGGLES_AUDIT_RETENTION_DAYS=21):
            old_file, _recent_file, _group = self.ingest_paired_evidence()

            call_command("prune_audit_data", stdout=StringIO())

            self.assertTrue(AuditFile.objects.filter(pk=old_file.pk).exists())

    def test_nothing_to_prune_reports_cleanly(self):
        _raw_token, token = UploadToken.issue("ios qa")
        ingest_audit_log_bytes(
            dump_bytes=representative_audit_log().encode("utf-8"),
            upload_token=token,
        )

        call_command("prune_audit_data", stdout=StringIO())

        self.assertEqual(AuditFile.objects.count(), 1)

    def test_vacuum_runs_only_on_postgres(self):
        stale_connection = mock.MagicMock()
        stale_connection.vendor = "postgresql"
        cursor = stale_connection.cursor.return_value.__enter__.return_value

        with mock.patch(
            "forensics.management.commands.prune_audit_data.connection", stale_connection
        ):
            vacuum_audit_data()
            stale_connection.cursor.return_value.__enter__.assert_called()
            cursor.execute.assert_has_calls(
                [mock.call(f"VACUUM ANALYZE {table}") for table in VACUUM_TABLES]
            )

        sqlite_connection = mock.MagicMock()
        sqlite_connection.vendor = "sqlite"

        with mock.patch(
            "forensics.management.commands.prune_audit_data.connection", sqlite_connection
        ):
            vacuum_audit_data()
            sqlite_connection.cursor.assert_not_called()


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
            data=representative_audit_log(source={"account_label": "Alice"}),
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
            HTTP_X_GOGGLES_DEVICE_LABEL="MacBook",
            HTTP_X_GOGGLES_PLATFORM="macOS",
            HTTP_X_GOGGLES_APP_VERSION="1.2.3",
            HTTP_USER_AGENT="MDK/1.2.3",
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

    def test_upload_log_list_does_not_select_raw_text(self):
        # Regression for #39: the recent-uploads list renders only metadata, so
        # the queryset must never transfer or instantiate the heavy
        # AuditFile.raw_text column (nor reload it via a deferred-field query).
        raw_token, _token = UploadToken.issue("ios test client")
        user = User.objects.create_user(
            username="analyst",
            password="correct horse battery staple",
        )
        upload_response = self.client.post(
            reverse("api-audit-log-upload"),
            data=representative_audit_log(source={"account_label": "Alice"}),
            content_type="application/x-ndjson",
            HTTP_AUTHORIZATION=f"Bearer {raw_token}",
            HTTP_USER_AGENT="MDK/1.2.3",
            REMOTE_ADDR="203.0.113.10",
        )
        self.assertEqual(upload_response.status_code, 201)
        self.assertTrue(AuditFile.objects.filter(raw_text__gt="").exists())

        self.client.force_login(user)
        with CaptureQueriesContext(connection) as captured:
            response = self.client.get(reverse("upload-log-list"))

        self.assertEqual(response.status_code, 200)
        raw_text_queries = [
            query["sql"] for query in captured.captured_queries if "raw_text" in query["sql"]
        ]
        self.assertEqual(
            raw_text_queries,
            [],
            msg=(
                "upload_log_list must not select AuditFile.raw_text; "
                f"offending SQL: {raw_text_queries}"
            ),
        )

    def test_group_detail_is_login_required_and_shows_audit_workflows(self):
        group = AuditGroup.objects.create(
            name="QA fork group",
            slug=GROUP_REF,
            group_ref=GROUP_REF,
        )
        raw_token, _token = UploadToken.issue("qa clients")
        body = jsonl(
            audit_event_v2(
                0,
                kind={
                    "type": "transport_received",
                    "msg_id": MSG_ID,
                    "transport": {
                        "transport": "nostr",
                        "relay_url": "wss://relay.example",
                        "nostr_event_id": DIGEST_A,
                    },
                    "payload_len": 512,
                    "payload_digest": DIGEST_A,
                },
            ),
            audit_event_v2(
                1,
                audit_data_mode="full_data",
                kind={
                    "type": "message_content_decoded",
                    "msg_id": MSG_ID,
                    "artifact_kind": "application_message",
                    "author": {"member_ref": ACCOUNT_ALICE},
                    "decoded_payload": {
                        "content_type": "text/plain",
                        "text": "hello from Alice",
                    },
                },
            ),
            audit_event_v2(
                2,
                context={"convergence": {"run_id": "run-1", "phase": "selected"}},
                kind={
                    "type": "convergence_decision",
                    "current_tip_epoch": 6,
                    "max_rewind_commits": 5,
                    "selected_branch_id": "branch-a",
                    "selected_fork_epoch": 6,
                    "selected_tip_epoch": 7,
                    "candidates": [
                        {"branch_id": "branch-a", "fork_epoch": 6, "tip_epoch": 7, "eligible": True}
                    ],
                    "rule_trace": [
                        {
                            "rule_name": "highest_weight",
                            "result": {"winner": "branch-a"},
                            "decisive": True,
                            "selected_branch_id": "branch-a",
                        }
                    ],
                },
            ),
            audit_event_v2(
                3,
                audit_data_mode="full_data",
                kind={
                    "type": "group_state_changed",
                    "epoch": 7,
                    "change_kind": "group_renamed",
                    "fields": ["name"],
                    "value": {"digest": DIGEST_B, "text": "Launch room"},
                },
            ),
            audit_event_v2(
                4,
                kind={
                    "type": "epoch_state_changed",
                    "previous_state": "pending",
                    "new_state": "committed",
                    "epoch": 7,
                    "reason": "winning_commit_applied",
                },
            ),
        )

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
        for label in (
            "Overview",
            "Delivery",
            "Network",
            "Convergence",
            "State",
            "Evidence",
            "Exports",
        ):
            self.assertContains(response, label)
        self.assertNotContains(response, "Timeline")
        self.assertNotContains(response, 'id="timeline-data"')
        self.assertNotContains(response, MSG_ID)

        with CaptureQueriesContext(connection) as tab_queries:
            delivery_response = self.client.get(
                reverse("group-tab", kwargs={"slug": group.slug, "tab": "delivery"})
            )
            network_response = self.client.get(
                reverse("group-tab", kwargs={"slug": group.slug, "tab": "network"})
            )
            convergence_response = self.client.get(
                reverse("group-tab", kwargs={"slug": group.slug, "tab": "convergence"})
            )
            state_response = self.client.get(
                reverse("group-tab", kwargs={"slug": group.slug, "tab": "state"})
            )
        self.assertContains(delivery_response, "Message artifacts")
        self.assertContains(delivery_response, MSG_ID[:16])
        self.assertContains(delivery_response, "hello from Alice")

        self.assertContains(network_response, "Transport observations")
        self.assertContains(network_response, "wss://relay.example")

        self.assertContains(convergence_response, "Convergence runs")
        self.assertContains(convergence_response, "branch-a")
        self.assertContains(convergence_response, "highest_weight")

        self.assertContains(state_response, "Group state deltas")
        self.assertContains(state_response, "text value")
        self.assertNotContains(state_response, "Launch room")
        self.assertContains(state_response, "Epoch state transitions")
        self.assertEqual(
            heavy_bulk_selects(
                tab_queries.captured_queries,
                allowed_columns=(HEAVY_EVENT_SELECT_COLUMNS["context_source"],),
            ),
            [],
        )

        evidence_response = self.client.get(
            reverse("group-tab", kwargs={"slug": group.slug, "tab": "evidence"})
        )
        self.assertContains(evidence_response, "Audit files")
        self.assertContains(evidence_response, "Recent evidence rows")

        with CaptureQueriesContext(connection) as evidence_api_queries:
            evidence_api_response = self.client.get(
                reverse("api-group-evidence", kwargs={"slug": group.slug})
            )
        self.assertEqual(evidence_api_response.status_code, 200)
        self.assertTrue(evidence_api_response.json()["evidence"])
        self.assertEqual(heavy_bulk_selects(evidence_api_queries.captured_queries), [])

        event_id = evidence_api_response.json()["evidence"][0]["evidence_ref"]["event_id"]
        with CaptureQueriesContext(connection) as event_api_queries:
            event_api_response = self.client.get(
                reverse("api-event-evidence", kwargs={"event_id": event_id})
            )
        self.assertEqual(event_api_response.status_code, 200)
        self.assertIn("raw_line", event_api_response.json()["event"])
        self.assertFalse(
            any(
                '"forensics_auditfile"."raw_text"' in query["sql"]
                for query in event_api_queries.captured_queries
            )
        )

    def test_group_detail_tabs_cap_large_group_rows(self):
        tab_limit = GROUP_DETAIL_TAB_EVENT_LIMIT
        row_count = tab_limit + 5
        group = AuditGroup.objects.create(
            name="Large tab group",
            slug="large-tab-group",
            group_ref=GROUP_REF,
        )
        audit_file = AuditFile.objects.create(
            file_sha256="e" * 64,
            byte_size=5_000_000,
            raw_text="x" * 5_000_000,
            validation_status=AuditFile.STATUS_VALID,
            source_name="large-tabs.jsonl",
            total_line_count=row_count * 4,
            valid_event_count=row_count * 4,
        )
        audit_file.groups.add(group)
        evidence_event = AuditEvent.objects.create(
            audit_file=audit_file,
            group=group,
            line_number=1,
            line_hash="evidence".ljust(64, "0"),
            raw_line="{}",
            parse_status=AuditEvent.STATUS_VALID,
            event_type="transport_received",
            engine_id=ENGINE_ALICE,
            account_ref=ACCOUNT_ALICE,
            group_ref=GROUP_REF,
            seq=1,
            wall_time_ms=1_700_000_000_000,
            msg_id=MSG_ID,
        )
        for i in range(row_count):
            artifact = DeliveryArtifact.objects.create(
                group=group,
                artifact_id=f"{i:064x}",
                artifact_kind="application_message",
                first_seen_ms=1_700_000_000_000 + i,
            )
            artifact.evidence_events.add(evidence_event)
            observation = DeliveryObservation.objects.create(
                artifact=artifact,
                engine_id=ENGINE_ALICE,
                latest_state=f"delivery-marker-{i:03d}",
                first_seen_ms=1_700_000_000_000 + i,
            )
            observation.evidence_events.add(evidence_event)
            NetworkObservation.objects.create(
                group=group,
                artifact=artifact,
                audit_event=evidence_event,
                direction="inbound",
                phase=f"network-marker-{i:03d}",
                message_id=artifact.artifact_id,
                engine_id=ENGINE_ALICE,
                wall_time_ms=1_700_000_100_000 + i,
            )
            run = ConvergenceRun.objects.create(
                group=group,
                run_id=f"run-{i:03d}",
                engine_id=ENGINE_ALICE,
                phase=f"convergence-marker-{i:03d}",
                started_at_ms=1_700_000_200_000 + i,
            )
            ConvergenceCandidate.objects.create(
                run=run,
                branch_id=f"branch-{i:03d}",
                fork_epoch=i,
                tip_epoch=i + 1,
            )
            StateDelta.objects.create(
                group=group,
                audit_event=evidence_event,
                epoch=i,
                change_kind=f"state-marker-{i:03d}",
                wall_time_ms=1_700_000_300_000 + i,
            )
            EpochStateTransition.objects.create(
                group=group,
                audit_event=evidence_event,
                engine_id=ENGINE_ALICE,
                new_state=f"epoch-marker-{i:03d}",
                epoch=i,
                wall_time_ms=1_700_000_400_000 + i,
            )
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

        with CaptureQueriesContext(connection) as delivery_queries:
            delivery_response = self.client.get(
                reverse("group-tab", kwargs={"slug": group.slug, "tab": "delivery"})
            )
        network_response = self.client.get(
            reverse("group-tab", kwargs={"slug": group.slug, "tab": "network"})
        )
        convergence_response = self.client.get(
            reverse("group-tab", kwargs={"slug": group.slug, "tab": "convergence"})
        )
        state_response = self.client.get(
            reverse("group-tab", kwargs={"slug": group.slug, "tab": "state"})
        )

        self.assertEqual(delivery_response.status_code, 200)
        self.assertEqual(
            heavy_bulk_selects(
                delivery_queries.captured_queries,
                allowed_columns=(HEAVY_EVENT_SELECT_COLUMNS["context_source"],),
            ),
            [],
        )
        self.assertEqual(len(delivery_response.context["artifacts"]), tab_limit)
        self.assertContains(delivery_response, f"Showing first {tab_limit} message artifacts")
        self.assertContains(delivery_response, "delivery-marker-000")
        self.assertNotContains(delivery_response, f"delivery-marker-{row_count - 1:03d}")

        self.assertEqual(network_response.status_code, 200)
        self.assertEqual(len(network_response.context["observations"]), tab_limit)
        self.assertContains(network_response, f"Showing first {tab_limit} network observations")
        self.assertContains(network_response, "network-marker-000")
        self.assertNotContains(network_response, f"network-marker-{row_count - 1:03d}")

        self.assertEqual(convergence_response.status_code, 200)
        self.assertEqual(len(convergence_response.context["runs"]), tab_limit)
        self.assertContains(convergence_response, f"Showing first {tab_limit} convergence runs")
        self.assertContains(convergence_response, "convergence-marker-000")
        self.assertNotContains(convergence_response, f"convergence-marker-{row_count - 1:03d}")

        self.assertEqual(state_response.status_code, 200)
        self.assertEqual(len(state_response.context["state_deltas"]), tab_limit)
        self.assertEqual(len(state_response.context["epoch_transitions"]), tab_limit)
        self.assertContains(state_response, f"Showing first {tab_limit} state deltas")
        self.assertContains(state_response, f"Showing first {tab_limit} epoch transitions")
        self.assertContains(state_response, "state-marker-000")
        self.assertNotContains(state_response, f"state-marker-{row_count - 1:03d}")

    def test_group_delivery_tab_caps_artifact_expansion_consistently(self):
        tab_limit = GROUP_DETAIL_TAB_EVENT_LIMIT
        visible_msg_ids = [f"{i:064x}" for i in range(tab_limit)]
        hidden_msg_id = "f" * 64
        group = AuditGroup.objects.create(
            name="Expanded artifact group",
            slug="expanded-artifact-group",
            group_ref=GROUP_REF,
        )
        for msg_id in [*visible_msg_ids, hidden_msg_id]:
            artifact = DeliveryArtifact.objects.create(
                group=group,
                artifact_id=msg_id,
                artifact_kind="application_message",
                first_seen_ms=1_700_000_000_001,
            )
            DeliveryObservation.objects.create(
                artifact=artifact,
                engine_id=ENGINE_ALICE,
                latest_state="decoded",
                first_seen_ms=1_700_000_000_001,
            )
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

        response = self.client.get(
            reverse("group-tab", kwargs={"slug": group.slug, "tab": "delivery"})
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["artifacts_limited"])
        self.assertEqual(len(response.context["artifacts"]), tab_limit)
        self.assertContains(response, f"Showing first {tab_limit} message artifacts")
        self.assertContains(response, visible_msg_ids[0][:16])
        self.assertNotContains(response, hidden_msg_id[:16])

    def test_group_epoch_count_counts_distinct_epochs_in_database(self):
        group = AuditGroup.objects.create(
            name="Epoch union group",
            slug="epoch-union-group",
            group_ref=GROUP_REF,
        )
        audit_file = AuditFile.objects.create(
            file_sha256="c" * 64,
            byte_size=1024,
            raw_text="{}\n",
            validation_status=AuditFile.STATUS_VALID,
            source_name="epochs.jsonl",
            total_line_count=3,
            valid_event_count=3,
        )
        AuditEvent.objects.bulk_create(
            [
                AuditEvent(
                    audit_file=audit_file,
                    group=group,
                    line_number=1,
                    line_hash="epoch-1".ljust(64, "0"),
                    raw_line="{}",
                    parse_status=AuditEvent.STATUS_VALID,
                    event_type="convergence_decision",
                    epoch=1,
                    source_epoch=2,
                    to_epoch=3,
                    current_tip_epoch=4,
                    selected_tip_epoch=5,
                ),
                AuditEvent(
                    audit_file=audit_file,
                    group=group,
                    line_number=2,
                    line_hash="epoch-2".ljust(64, "0"),
                    raw_line="{}",
                    parse_status=AuditEvent.STATUS_VALID,
                    event_type="epoch_rolled_back",
                    epoch=1,
                    source_epoch=6,
                    pending_epoch=5,
                    current_tip_epoch=7,
                    selected_tip_epoch=7,
                ),
                AuditEvent(
                    audit_file=audit_file,
                    group=group,
                    line_number=3,
                    line_hash="epoch-3".ljust(64, "0"),
                    raw_line="{}",
                    parse_status=AuditEvent.STATUS_VALID,
                    event_type="send_entry",
                ),
            ]
        )

        with CaptureQueriesContext(connection) as captured:
            epoch_count = group_epoch_count(valid_group_event_queryset(group))

        self.assertEqual(epoch_count, 7)
        self.assertEqual(len(captured), 1)
        sql = captured[0]["sql"].upper()
        self.assertIn("COUNT", sql)
        self.assertEqual(sql.count("UNION"), len(GROUP_EPOCH_FIELDS) - 1)

    def test_group_detail_shell_size_stays_bounded_for_large_groups(self):
        group = AuditGroup.objects.create(
            name="Large response group",
            slug="large-response-group",
            group_ref=GROUP_REF,
        )
        audit_file = AuditFile.objects.create(
            file_sha256="f" * 64,
            byte_size=5_000_000,
            raw_text="x" * 5_000_000,
            validation_status=AuditFile.STATUS_VALID,
            source_name="huge.jsonl",
            source_account_label="Alice",
            source_device_label="MacBook",
            total_line_count=3_000,
            valid_event_count=3_000,
        )
        AuditEvent.objects.bulk_create(
            AuditEvent(
                audit_file=audit_file,
                group=group,
                line_number=i + 1,
                line_hash=f"{i:064x}",
                raw_line=f"RAW-LINE-MARKER-{i}",
                parse_status=AuditEvent.STATUS_VALID,
                event_type="ingest_entry",
                engine_id=ENGINE_ALICE if i % 2 == 0 else ENGINE_BOB,
                account_ref=ACCOUNT_ALICE,
                group_ref=GROUP_REF,
                seq=i,
                wall_time_ms=1_700_000_000_000 + i,
                msg_id=f"{i:064x}",
            )
            for i in range(3_000)
        )
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

        with CaptureQueriesContext(connection) as shell_queries:
            response = self.client.get(reverse("group-detail", kwargs={"slug": group.slug}))

        self.assertEqual(response.status_code, 200)
        self.assertLess(len(response.content), 250_000)
        self.assertNotContains(response, "RAW-LINE-MARKER-2999")
        self.assertNotContains(response, 'id="timeline-data"')
        self.assertEqual(
            heavy_bulk_selects(
                shell_queries.captured_queries,
                allowed_columns=(
                    HEAVY_EVENT_SELECT_COLUMNS["raw_kind"],
                    HEAVY_EVENT_SELECT_COLUMNS["context_source"],
                ),
            ),
            [],
        )

        with CaptureQueriesContext(connection) as evidence_queries:
            evidence_response = self.client.get(
                reverse("group-tab", kwargs={"slug": group.slug, "tab": "evidence"})
            )

        self.assertEqual(evidence_response.status_code, 200)
        self.assertLess(len(evidence_response.content), 250_000)
        self.assertLessEqual(
            len(evidence_response.context["recent_events"]),
            GROUP_DETAIL_TAB_EVENT_LIMIT,
        )
        self.assertEqual(heavy_bulk_selects(evidence_queries.captured_queries), [])


class AuditFileDetailViewTests(TestCase):
    def setUp(self):
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

    @staticmethod
    def make_audit_file(event_count=0, raw_text="line zero\n", **kwargs):
        digest = hashlib.sha256(f"{event_count}:{raw_text}".encode()).hexdigest()
        audit_file = AuditFile.objects.create(
            file_sha256=digest,
            byte_size=len(raw_text.encode("utf-8")),
            raw_text=raw_text,
            total_line_count=event_count,
            valid_event_count=event_count,
            **kwargs,
        )
        AuditEvent.objects.bulk_create(
            AuditEvent(
                audit_file=audit_file,
                line_number=i + 1,
                line_hash=f"{i:064x}",
                raw_line=f"line {i}",
                parse_status=AuditEvent.STATUS_VALID,
                event_type=f"detail_type_{i:03d}",
                engine_id=ENGINE_ALICE,
                account_ref=ACCOUNT_ALICE,
                group_ref=GROUP_REF,
                seq=i,
            )
            for i in range(event_count)
        )
        return audit_file

    def detail_url(self, audit_file):
        return reverse("audit-file-detail", args=[audit_file.pk])

    def test_detail_requires_login(self):
        self.client.logout()
        audit_file = self.make_audit_file()

        response = self.client.get(self.detail_url(audit_file))

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("login"), response["Location"])

    def test_detail_paginates_event_rows(self):
        total_events = AUDIT_FILE_EVENT_PAGE_SIZE + 5
        audit_file = self.make_audit_file(total_events)

        first_page = self.client.get(self.detail_url(audit_file))

        self.assertEqual(first_page.status_code, 200)
        self.assertEqual(len(first_page.context["event_rows"]), AUDIT_FILE_EVENT_PAGE_SIZE)
        self.assertEqual(first_page.context["event_page"].paginator.count, total_events)
        content = first_page.content.decode()
        self.assertIn("detail_type_000", content)
        self.assertNotIn("detail_type_104", content)
        self.assertContains(first_page, f"Showing 1–{AUDIT_FILE_EVENT_PAGE_SIZE} of {total_events}")

        second_page = self.client.get(self.detail_url(audit_file), {"page": 2})

        self.assertEqual(second_page.status_code, 200)
        self.assertEqual(len(second_page.context["event_rows"]), 5)
        self.assertContains(second_page, "detail_type_104")
        self.assertNotContains(second_page, "detail_type_000")

    def test_detail_truncates_raw_text_preview_and_links_download(self):
        tail_marker = "TAIL-RAW-TEXT-SHOULD-NOT-BE-IN-PREVIEW"
        raw_text = "x" * (RAW_TEXT_PREVIEW_CHARS + 100) + tail_marker
        audit_file = self.make_audit_file(1, raw_text=raw_text, source_name="big-upload.jsonl")

        response = self.client.get(self.detail_url(audit_file))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context["raw_text_preview"]), RAW_TEXT_PREVIEW_CHARS)
        self.assertTrue(response.context["raw_text_is_truncated"])
        content = response.content.decode()
        self.assertIn("Raw JSONL preview", content)
        self.assertIn("Download full JSONL", content)
        self.assertIn(reverse("audit-file-raw-text", args=[audit_file.pk]), content)
        self.assertNotIn(tail_marker, content)
        self.assertContains(
            response,
            f"Showing first {RAW_TEXT_PREVIEW_CHARS} of {len(raw_text)} characters",
        )

    def test_detail_html_size_is_bounded_by_preview_and_page_size(self):
        small = self.make_audit_file(2, raw_text="small\n")
        huge = self.make_audit_file(
            AUDIT_FILE_EVENT_PAGE_SIZE + 150,
            raw_text="x" * 5_000_000,
            source_name="huge",
        )

        with CaptureQueriesContext(connection) as small_queries:
            small_response = self.client.get(self.detail_url(small))
        with CaptureQueriesContext(connection) as huge_queries:
            huge_response = self.client.get(self.detail_url(huge))

        self.assertEqual(small_response.status_code, 200)
        self.assertEqual(huge_response.status_code, 200)
        self.assertEqual(len(huge_response.context["event_rows"]), AUDIT_FILE_EVENT_PAGE_SIZE)
        self.assertEqual(len(small_queries), len(huge_queries))
        self.assertLess(len(huge_response.content) - len(small_response.content), 150_000)
        self.assertLess(len(huge_response.content), 250_000)

    def test_raw_text_download_returns_full_content(self):
        tail_marker = "TAIL-RAW-TEXT-DOWNLOAD"
        raw_text = "x" * (RAW_TEXT_PREVIEW_CHARS + 100) + tail_marker
        audit_file = self.make_audit_file(raw_text=raw_text, source_name="device export.jsonl")

        response = self.client.get(reverse("audit-file-raw-text", args=[audit_file.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/x-ndjson; charset=utf-8")
        self.assertIn("attachment", response["Content-Disposition"])
        self.assertIn("device-export.jsonl", response["Content-Disposition"])
        self.assertEqual(response.content.decode(), raw_text)


class HealthCheckTests(TestCase):
    def test_healthz_returns_minimal_json_without_login(self):
        response = self.client.get(reverse("healthz"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertEqual(response.json(), {"status": "ok"})


class SeedDataScenarioTests(TestCase):
    def test_scenario_is_deterministic(self):
        first = build_dev_scenario()
        second = build_dev_scenario()
        self.assertEqual(
            [(log.source_name, log.jsonl) for log in first],
            [(log.source_name, log.jsonl) for log in second],
        )

    def test_scenario_conforms_to_canonical_json_schema(self):
        import json as _json

        from forensics.management.commands.validate_audit_schema import (
            DEFAULT_SCHEMA_PATH,
            schema_validator,
        )

        validator = schema_validator(DEFAULT_SCHEMA_PATH)
        for log in build_dev_scenario():
            for line_number, line in enumerate(log.jsonl.splitlines(), 1):
                event = _json.loads(line)
                errors = sorted(validator.iter_errors(event), key=lambda error: error.path)
                self.assertEqual(
                    errors,
                    [],
                    msg=f"{log.source_name}:{line_number}: {[e.message for e in errors]}",
                )

    def test_scenario_logs_all_ingest_as_valid_single_engine_files(self):
        logs = build_dev_scenario()
        self.assertEqual(len(logs), sum(count for _name, count in SCENARIO_GROUPS))

        for log in logs:
            result = ingest_audit_log_bytes(
                dump_bytes=log.dump_bytes,
                source_name=log.source_name,
                source_device_label=log.device_label,
                source_platform=log.platform,
                content_type="application/x-ndjson",
            )
            audit_file = result.audit_file
            self.assertEqual(
                audit_file.validation_status,
                AuditFile.STATUS_VALID,
                msg=f"{log.source_name}: {audit_file.validation_error}",
            )
            # One recorder (engine) and one account per participant log.
            self.assertEqual(len(audit_file.engine_ids), 1, msg=log.source_name)
            self.assertLessEqual(len(audit_file.account_refs), 1, msg=log.source_name)
            # Account label/pubkey are backfilled from the body, not headers.
            self.assertEqual(audit_file.source_account_label, log.account_label)
            self.assertEqual(audit_file.source_account_pubkey_hex, log.account_pubkey_hex)


@override_settings(DEBUG=True)
class SeedDevCommandTests(TestCase):
    def test_seed_dev_creates_admin_user_and_sample_audit_log_idempotently(self):
        output = StringIO()

        call_command("seed_dev", stdout=output)
        call_command("seed_dev", stdout=StringIO())

        admin = User.objects.get(username="admin")
        self.assertTrue(admin.check_password("pass123"))
        self.assertTrue(admin.is_staff)
        self.assertTrue(admin.is_superuser)

        # Re-seeding is idempotent (dedup by sha256): 2 + 3 + 4 + 6 participant logs.
        self.assertEqual(AuditFile.objects.count(), 15)
        self.assertTrue(
            all(f.validation_status == AuditFile.STATUS_VALID for f in AuditFile.objects.all())
        )
        for name, participant_count in SCENARIO_GROUPS:
            group = AuditGroup.objects.get(group_ref=group_ref_for(name))
            self.assertEqual(
                AuditFile.objects.filter(events__group=group).distinct().count(),
                participant_count,
                msg=name,
            )

        # The busy family group exercises every projection surface.
        family = AuditGroup.objects.get(group_ref=group_ref_for("Family"))
        self.assertTrue(DeliveryArtifact.objects.filter(group=family).exists())
        self.assertTrue(NetworkObservation.objects.filter(group=family).exists())
        self.assertTrue(StateDelta.objects.filter(group=family).exists())
        # The work group records a fork/convergence decision.
        acme = AuditGroup.objects.get(group_ref=group_ref_for("Acme Standup"))
        self.assertTrue(ConvergenceRun.objects.filter(group=acme).exists())

        self.assertIn("Dev user ready: admin", output.getvalue())
        self.assertNotIn("pass123", output.getvalue())

    @override_settings(DEBUG=False)
    def test_seed_dev_refuses_when_debug_false_without_explicit_allow(self):
        with mock.patch.dict(os.environ, {"GOGGLES_ALLOW_SEED": ""}):
            with self.assertRaisesMessage(
                CommandError,
                "Refusing to run seed_dev when DEBUG=False",
            ):
                call_command("seed_dev", stdout=StringIO())

        self.assertFalse(User.objects.filter(username="admin").exists())
        self.assertEqual(AuditFile.objects.count(), 0)

    def test_seed_dev_refuses_to_promote_existing_user_without_force(self):
        existing = User.objects.create_user(username="admin", password="original")

        with self.assertRaisesMessage(CommandError, "already exists"):
            call_command("seed_dev", stdout=StringIO())

        existing.refresh_from_db()
        self.assertTrue(existing.check_password("original"))
        self.assertFalse(existing.is_staff)
        self.assertFalse(existing.is_superuser)
        self.assertTrue(existing.is_active)
        self.assertEqual(AuditFile.objects.count(), 0)

    def test_seed_dev_force_promotes_existing_user_explicitly(self):
        existing = User.objects.create_user(username="admin", password="original")

        call_command("seed_dev", "--force", stdout=StringIO())

        existing.refresh_from_db()
        self.assertTrue(existing.check_password("pass123"))
        self.assertTrue(existing.is_staff)
        self.assertTrue(existing.is_superuser)

    @override_settings(DEBUG=False)
    def test_seed_dev_allows_explicit_env_override_when_debug_false(self):
        with mock.patch.dict(os.environ, {"GOGGLES_ALLOW_SEED": "1"}):
            call_command("seed_dev", stdout=StringIO())

        admin = User.objects.get(username="admin")
        self.assertTrue(admin.is_staff)
        self.assertTrue(admin.is_superuser)

    @override_settings(DEBUG=False)
    def test_seed_dev_env_override_does_not_promote_existing_user_without_force(self):
        existing = User.objects.create_user(username="admin", password="original")

        with mock.patch.dict(os.environ, {"GOGGLES_ALLOW_SEED": "1"}):
            with self.assertRaisesMessage(CommandError, "already exists"):
                call_command("seed_dev", stdout=StringIO())

        existing.refresh_from_db()
        self.assertTrue(existing.check_password("original"))
        self.assertFalse(existing.is_staff)
        self.assertFalse(existing.is_superuser)

    def test_seed_dev_seeds_realistic_group_activity(self):
        call_command("seed_dev", stdout=StringIO())

        # Identity is backfilled from the body's source_context, so the engine
        # lanes read with account label / device / platform.
        family = AuditGroup.objects.get(group_ref=group_ref_for("Family"))
        files = list(audit_files_for_group(family))
        self.assertEqual(len(files), 6)
        self.assertTrue(all(f.validation_status == AuditFile.STATUS_VALID for f in files))

        events = list(valid_events_for_group(family))
        payload = timeline_payload_for_group(family, events, files)
        labels = {engine["label"] for engine in payload["engines"]}
        self.assertIn("Rosa Family / iPhone 15 / ios", labels)
        self.assertIn("Hank Family / Pixel 9 / android", labels)
        self.assertEqual(payload["excluded"]["count"], 0)

        # The promote-admin human action and a published message are on the timeline.
        self.assertIn("promote_admin", {event.human_action_action for event in events})
        self.assertTrue(any(item["type"] == "human_action" for item in payload["items"]))
        self.assertTrue(any(item["type"] == "publish_outcome" for item in payload["items"]))

        # Decoded message content survives ingestion in full-data mode.
        self.assertTrue(
            DeliveryArtifact.objects.filter(
                group=family,
                decoded_payload__text="Sunday dinner at 5 — who's coming?",
            ).exists()
        )

        # The work group's fork resolves to a selected branch.
        acme = AuditGroup.objects.get(group_ref=group_ref_for("Acme Standup"))
        run = ConvergenceRun.objects.get(group=acme, run_id="run-standup-1")
        self.assertTrue(run.selected_branch_id)
        self.assertEqual(ConvergenceCandidate.objects.filter(run=run).count(), 2)

        # The fork-failure group's convergence blocks with no winner, then the
        # epoch is rolled back -- a real convergence failure, not a clean resolve.
        mesh = AuditGroup.objects.get(group_ref=group_ref_for("Mesh Relay QA"))
        failed_run = ConvergenceRun.objects.get(group=mesh, run_id="conv-mesh-31")
        self.assertEqual(failed_run.phase, "failed")
        self.assertFalse(failed_run.selected_branch_id)
        self.assertEqual(
            ConvergenceCandidate.objects.filter(run=failed_run, eligible=True).count(), 0
        )
        self.assertTrue(
            AuditEvent.objects.filter(group=mesh, event_type="epoch_rolled_back").exists()
        )
        self.assertTrue(
            AuditEvent.objects.filter(group=mesh, event_type="fork_resolution").exists()
        )
        # The epoch range now renders (regression for the epoch-display fix).
        mesh_row = {row.slug: row for row in group_list_rows()}[group_ref_for("Mesh Relay QA")]
        self.assertIsNotNone(mesh_row.epoch_min)
        self.assertIsNotNone(mesh_row.epoch_max)
        self.assertTrue(mesh_row.has_fork_activity)


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


def ingest_entry_event(seq, engine_id, account_ref, msg_id, wall_time_ms):
    return audit_event(
        seq,
        engine_id=engine_id,
        account_ref=account_ref,
        wall_time_ms=wall_time_ms,
        kind={
            "type": "ingest_entry",
            "msg_id": msg_id,
            "envelope_kind": "group_message",
            "payload_len": 512,
            "payload_digest": DIGEST_A,
        },
    )


def bob_presence_event(seq, wall_time_ms, from_epoch=4, to_epoch=5):
    # An epoch confirmation carries no message; it only marks ENGINE_BOB active
    # at ``wall_time_ms`` so divergence can tell a real break from a benign gap.
    return audit_event(
        seq,
        engine_id=ENGINE_BOB,
        account_ref=ACCOUNT_BOB,
        wall_time_ms=wall_time_ms,
        kind={
            "type": "epoch_confirmed",
            "from_epoch": from_epoch,
            "to_epoch": to_epoch,
            "pending_kind": "commit",
        },
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
                # Bob is present from T0 (an early epoch confirmation) yet never
                # logs MSG_ID that Alice ingested at T0 — a real, membership-aware
                # break rather than a late-joiner gap.
                audit_event(
                    0,
                    engine_id=ENGINE_BOB,
                    account_ref=ACCOUNT_BOB,
                    kind={
                        "type": "epoch_confirmed",
                        "from_epoch": 4,
                        "to_epoch": 5,
                        "pending_kind": "commit",
                    },
                    wall_time_ms=T0,
                ),
                audit_event(
                    1,
                    engine_id=ENGINE_BOB,
                    account_ref=ACCOUNT_BOB,
                    kind={"type": "send_entry", "intent_kind": "message"},
                    wall_time_ms=T0 + 300,
                ),
            )
        )

    def seed_clean_group(self):
        ingest_body(jsonl(epoch_confirmed(0, ENGINE_CAROL, 2, 3, T0 + 400)))

    def test_epoch_range_spans_non_epoch_confirmed_events(self):
        # Regression: a group whose epoch activity is expressed only via
        # epoch_state_changed / group_state_changed (the ``epoch`` field) must
        # still report a range instead of "–" on the landing page.
        ingest_body(
            jsonl(
                audit_event(
                    0,
                    kind={
                        "type": "group_state_changed",
                        "epoch": 8,
                        "change_kind": "topic_changed",
                        "fields": ["topic"],
                    },
                    wall_time_ms=T0,
                ),
                audit_event(
                    1,
                    kind={
                        "type": "epoch_state_changed",
                        "previous_state": "pending",
                        "new_state": "committed",
                        "epoch": 9,
                        "reason": "winning_commit_applied",
                    },
                    wall_time_ms=T0 + 100,
                ),
            )
        )

        group = {row.slug: row for row in group_list_rows()}[GROUP_REF]
        self.assertEqual(group.epoch_min, 8)
        self.assertEqual(group.epoch_max, 9)

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
        self.assertEqual(fork_group.event_count, 5)
        self.assertEqual(fork_group.audit_file_count, 2)
        self.assertEqual(fork_group.last_activity_ms, T0 + 300)
        self.assertTrue(fork_group.has_fork_activity)
        # Bob is present from T0 but never logs MSG_ID Alice ingested at T0.
        self.assertEqual(fork_group.divergent_count, 1)
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

    def test_group_list_rows_do_not_rebuild_message_traces(self):
        self.seed_fork_group()

        with mock.patch.object(
            analysis_module,
            "message_traces_from_events",
            side_effect=AssertionError("group list must use persisted divergence counts"),
        ):
            rows = {group.slug: group for group in group_list_rows()}

        self.assertEqual(rows[GROUP_REF].divergent_count, 1)

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

    def test_persisted_divergent_count_matches_live_trace_count(self):
        """The persisted landing-page count and the live trace-based detail
        count must agree for the same group.

        Divergence is defined in two structurally linked analysis paths sharing
        ``is_divergent_message``: the persisted aggregation written by ingest
        (``AuditGroup.divergent_message_count``) and the trace-based
        ``group_integrity_summary``. Both build the membership-aware in-scope
        engine set identically, so a one-sided change to the definition drifts
        the two counts apart and fails this test.

        The fixture exercises the membership-aware predicate end to end. Alice
        and Bob overlap from T0+10 onward; Bob has a pre-window gap that must
        NOT count:
          - SEEN_MSG:  observed by Alice AND Bob              -> convergent
          - EARLY_MSG: Alice only, before Bob's window starts -> benign gap
          - BREAK_MSG: Alice only, inside Bob's active window -> real break
        """
        early_msg_id = "55" * 32
        seen_msg_id = MSG_ID
        break_msg_id = OTHER_MSG_ID

        def message_event(seq, engine_id, account_ref, msg_id, wall_time_ms):
            return audit_event(
                seq,
                engine_id=engine_id,
                account_ref=account_ref,
                wall_time_ms=wall_time_ms,
                kind={
                    "type": "ingest_entry",
                    "msg_id": msg_id,
                    "envelope_kind": "group_message",
                    "payload_len": 512,
                    "payload_digest": DIGEST_A,
                },
            )

        ingest_body(
            jsonl(
                message_event(0, ENGINE_ALICE, ACCOUNT_ALICE, early_msg_id, T0),
                message_event(1, ENGINE_ALICE, ACCOUNT_ALICE, break_msg_id, T0 + 50),
                message_event(2, ENGINE_ALICE, ACCOUNT_ALICE, seen_msg_id, T0 + 90),
            )
        )
        ingest_body(
            jsonl(
                # An epoch confirmation carries no message, but it marks Bob
                # active from T0+10: BREAK_MSG (T0+50) then lands inside his
                # window while EARLY_MSG (T0) stays before it.
                audit_event(
                    0,
                    engine_id=ENGINE_BOB,
                    account_ref=ACCOUNT_BOB,
                    wall_time_ms=T0 + 10,
                    kind={
                        "type": "epoch_confirmed",
                        "from_epoch": 4,
                        "to_epoch": 5,
                        "pending_kind": "commit",
                    },
                ),
                message_event(1, ENGINE_BOB, ACCOUNT_BOB, seen_msg_id, T0 + 95),
            )
        )

        group = AuditGroup.objects.get(slug=GROUP_REF)
        persisted = group.divergent_message_count
        summary = analysis_module.group_integrity_summary(group)

        self.assertEqual(persisted, summary["divergent_message_count"])
        # Only BREAK_MSG is a real break; the pre-window EARLY_MSG gap is benign.
        self.assertEqual(persisted, 1)
        self.assertEqual(summary["divergent_msg_ids"], [break_msg_id])

        traces = {
            trace["msg_id"]: trace for trace in analysis_module.message_traces_for_group(group)
        }
        self.assertFalse(traces[early_msg_id]["is_divergent"])
        self.assertTrue(traces[break_msg_id]["is_divergent"])
        self.assertEqual(traces[break_msg_id]["missed_by"], [ENGINE_BOB])
        self.assertEqual(traces[early_msg_id]["absent_engines"], [ENGINE_BOB])

    def test_partially_invalid_file_counts_agree_across_header_tabs_and_persisted(self):
        """Header summary, every tab badge, and the persisted divergent count
        must agree with the timeline/tab/trace content for a group whose
        divergent evidence lives in a *partially-invalid* file (goggles#103).

        Regression for the filter split introduced by commit ``0ac4442``: the
        content path (``valid_events_for_group``) excludes only *structural*
        quarantine errors, so it includes the valid events of a file marked
        INVALID for a non-structural reason (one malformed JSONL line). The
        summary/badge (``valid_group_event_queryset``), persisted-aggregate
        (``divergent_counts_for_group_ids``) and landing-page
        (``group_list_rows``) paths used to additionally require
        ``validation_status=VALID``, so they dropped that file and understated
        every headline figure relative to what the detail views render.

        Fixture: BREAK_MSG (Alice-only, inside Bob's active window) is a real
        divergent message, and Alice's events live in a partially-invalid file;
        SEEN_MSG is observed by both. Both engines must count, and the one
        break must be reflected in the persisted figure.
        """
        break_msg_id = OTHER_MSG_ID
        seen_msg_id = MSG_ID

        # File 1 — Alice only (single engine), partially invalid via ONE
        # non-structural bad line (human_action.message_ids not hex). The file
        # flips to INVALID but its two ingest_entry events stay parse_status
        # VALID, and the error is NOT a structural multi-engine/account error.
        bad_action = audit_event(
            99,
            engine_id=ENGINE_ALICE,
            account_ref=ACCOUNT_ALICE,
            kind={
                "type": "human_action",
                "action": "update_group_profile",
                "origin": "local_user",
                "phase": "succeeded",
                "message_ids": [f"not-hex-{MSG_ID}"],
            },
        )
        # An epoch-carrying valid event that lives in the *partially-invalid*
        # file. group_epoch_count counts distinct values across the epoch fields
        # (to_epoch among them); its to_epoch=9 appears nowhere else, so under
        # the old valid-files-only predicate this file was dropped and epoch 9
        # vanished from the Timeline badge while the timeline tab body
        # (valid_events_for_group) still rendered it — the exact Timeline-tab gap
        # goggles#103 calls out.
        alice_epoch = audit_event(
            2,
            engine_id=ENGINE_ALICE,
            account_ref=ACCOUNT_ALICE,
            wall_time_ms=T0 + 70,
            kind={
                "type": "epoch_confirmed",
                "from_epoch": 8,
                "to_epoch": 9,
                "pending_kind": "commit",
            },
        )
        alice_result = ingest_body(
            jsonl(
                ingest_entry_event(0, ENGINE_ALICE, ACCOUNT_ALICE, break_msg_id, T0 + 50),
                ingest_entry_event(1, ENGINE_ALICE, ACCOUNT_ALICE, seen_msg_id, T0 + 90),
                alice_epoch,
                bad_action,
            )
        )
        # File 2 — Bob only, fully valid. The epoch confirmation marks Bob
        # active from T0+10, so BREAK_MSG (T0+50) lands inside his window.
        bob_result = ingest_body(
            jsonl(
                audit_event(
                    0,
                    engine_id=ENGINE_BOB,
                    account_ref=ACCOUNT_BOB,
                    wall_time_ms=T0 + 10,
                    kind={
                        "type": "epoch_confirmed",
                        "from_epoch": 4,
                        "to_epoch": 5,
                        "pending_kind": "commit",
                    },
                ),
                ingest_entry_event(1, ENGINE_BOB, ACCOUNT_BOB, seen_msg_id, T0 + 95),
            )
        )

        # The partially-invalid file is INVALID for a non-structural reason.
        self.assertEqual(alice_result.audit_file.validation_status, AuditFile.STATUS_INVALID)
        self.assertNotIn("multiple engine_ids", alice_result.audit_file.validation_error)
        self.assertNotIn("multiple account_refs", alice_result.audit_file.validation_error)
        self.assertEqual(bob_result.audit_file.validation_status, AuditFile.STATUS_VALID)

        group = AuditGroup.objects.get(slug=GROUP_REF)

        # --- Content truth: what the timeline / tabs / trace actually render. ---
        content_events = list(valid_events_for_group(group))
        audit_files = list(audit_files_for_group(group))
        timeline = timeline_payload_for_group(group, content_events, audit_files)
        content_engine_count = len({e.engine_id for e in content_events if e.engine_id})
        content_message_count = len({e.msg_id for e in content_events if e.msg_id})
        # Epoch set the Timeline tab body renders, grounded in the content path
        # (mirrors views.group_epoch_count). Alice's partial-invalid file
        # contributes to_epoch=9; if the badge predicate dropped that file the
        # badge would understate this set.
        content_epochs = set()
        for event in content_events:
            for value in (
                event.epoch,
                event.source_epoch,
                event.to_epoch,
                event.pending_epoch,
                event.current_tip_epoch,
                event.selected_tip_epoch,
            ):
                if value is not None:
                    content_epochs.add(value)
        content_epoch_count = len(content_epochs)
        trace_summary = analysis_module.group_integrity_summary(group, events=content_events)
        trace_divergent = trace_summary["divergent_message_count"]
        break_rows = sum(
            1 for t in analysis_module.message_traces_for_group(group) if t["is_divergent"]
        )

        # Alice's valid events survive the partial-invalidation; both engines
        # are present in the content the detail views render.
        self.assertEqual(content_engine_count, 2)
        self.assertEqual(content_message_count, 2)
        self.assertEqual(len(timeline["engines"]), 2)
        self.assertEqual(trace_divergent, 1)
        self.assertEqual(break_rows, 1)
        # The epoch carried only by Alice's partially-invalid file is part of
        # the timeline content (regression guard: must be non-trivial and must
        # include the partial-invalid file's epoch). group_epoch_count counts
        # distinct epoch values across the epoch fields, so Bob's to_epoch=5 and
        # Alice's to_epoch=9 give 2 distinct epochs.
        self.assertEqual(content_epoch_count, 2)
        self.assertIn(9, content_epochs)

        # --- Header summary + tab badges (views.valid_group_event_queryset). ---
        shell = group_detail_shell_context(group)
        self.assertEqual(shell["summary"]["engine_count"], content_engine_count)
        self.assertEqual(shell["summary"]["message_count"], content_message_count)
        self.assertEqual(
            shell["summary"]["delivery_count"], DeliveryArtifact.objects.filter(group=group).count()
        )
        self.assertEqual(shell["summary"]["event_count"], len(content_events))
        # The header engine-preview column count cannot exceed the headline
        # engine_count (the timeline renders content_engine_count columns).
        self.assertEqual(
            shell["timeline_summary"]["engine_overflow_count"]
            + len(shell["timeline_summary"]["engines"]),
            content_engine_count,
        )
        self.assertEqual(shell["tab_counts"]["overview"], len(content_events))
        self.assertEqual(shell["tab_counts"]["evidence"], len(audit_files))
        self.assertEqual(
            shell["tab_counts"]["delivery"], DeliveryArtifact.objects.filter(group=group).count()
        )
        self.assertEqual(
            shell["tab_counts"]["network"], NetworkObservation.objects.filter(group=group).count()
        )
        self.assertEqual(
            shell["tab_counts"]["convergence"], ConvergenceRun.objects.filter(group=group).count()
        )
        self.assertEqual(
            shell["tab_counts"]["state"],
            StateDelta.objects.filter(group=group).count()
            + EpochStateTransition.objects.filter(group=group).count(),
        )
        # The shell still carries the compact engine/epoch preview; it must match
        # the content path, including the epoch that only the partially-invalid
        # file carries.
        self.assertEqual(shell["timeline_summary"]["epoch_count"], content_epoch_count)

        # --- Persisted divergent count (divergent_counts_for_group_ids). ---
        persisted = group.divergent_message_count
        live_persisted = analysis_module.divergent_counts_for_group_ids([group.pk])[group.pk]
        self.assertEqual(persisted, trace_divergent)
        self.assertEqual(live_persisted, trace_divergent)
        self.assertEqual(persisted, break_rows)

        # --- Landing page per-group rows. ---
        rows = {row.slug: row for row in group_list_rows()}
        landing = rows[group.slug]
        self.assertEqual(landing.engine_count, content_engine_count)
        self.assertEqual(landing.event_count, len(content_events))
        self.assertEqual(landing.divergent_count, trace_divergent)

    def test_migration_0010_backfills_stale_valid_files_only_divergent_count(self):
        """A group uploaded before this fix deployed keeps a stale, valid-files-
        only ``divergent_message_count`` until some later ingest happens to
        touch it; the read paths (landing/header) render that stored value
        directly. Migration 0010's recompute must repair such a group to the
        partial-invalid-aware count without waiting for re-ingest (goggles#103,
        adversarial-review blocking finding).

        The break (BREAK_MSG, Alice-only, inside Bob's window) lives entirely in
        a *partially-invalid* file, so the old valid-files-only predicate scored
        the group at 0. We seed that stale value and assert the migration's
        recompute fixes it to the live trace count of 1.
        """
        from importlib import import_module

        from django.apps import apps as global_apps

        break_msg_id = OTHER_MSG_ID
        seen_msg_id = MSG_ID

        bad_action = audit_event(
            99,
            engine_id=ENGINE_ALICE,
            account_ref=ACCOUNT_ALICE,
            kind={
                "type": "human_action",
                "action": "update_group_profile",
                "origin": "local_user",
                "phase": "succeeded",
                "message_ids": [f"not-hex-{MSG_ID}"],
            },
        )
        alice_result = ingest_body(
            jsonl(
                ingest_entry_event(0, ENGINE_ALICE, ACCOUNT_ALICE, break_msg_id, T0 + 50),
                ingest_entry_event(1, ENGINE_ALICE, ACCOUNT_ALICE, seen_msg_id, T0 + 90),
                bad_action,
            )
        )
        ingest_body(
            jsonl(
                audit_event(
                    0,
                    engine_id=ENGINE_BOB,
                    account_ref=ACCOUNT_BOB,
                    wall_time_ms=T0 + 10,
                    kind={
                        "type": "epoch_confirmed",
                        "from_epoch": 4,
                        "to_epoch": 5,
                        "pending_kind": "commit",
                    },
                ),
                ingest_entry_event(1, ENGINE_BOB, ACCOUNT_BOB, seen_msg_id, T0 + 95),
            )
        )

        self.assertEqual(alice_result.audit_file.validation_status, AuditFile.STATUS_INVALID)
        group = AuditGroup.objects.get(slug=GROUP_REF)

        trace_divergent = analysis_module.group_integrity_summary(group)["divergent_message_count"]
        self.assertEqual(trace_divergent, 1)

        # Simulate a pre-deploy row: the stale valid-files-only value (the break
        # file is INVALID, so the old predicate dropped it and scored 0). Write
        # it directly to bypass the now-correct ingest rollup.
        AuditGroup.objects.filter(pk=group.pk).update(divergent_message_count=0)
        self.assertEqual(AuditGroup.objects.get(pk=group.pk).divergent_message_count, 0)

        # Run the forward data migration's recompute against the real app
        # registry; it must repair the stored value to the trace count.
        migration = import_module(
            "forensics.migrations.0010_recompute_divergent_counts_partial_invalid"
        )
        migration.recompute_divergent_message_counts(global_apps, None)

        self.assertEqual(
            AuditGroup.objects.get(pk=group.pk).divergent_message_count, trace_divergent
        )
        # The self-contained migration computation must equal the runtime one.
        self.assertEqual(
            analysis_module.divergent_counts_for_group_ids([group.pk])[group.pk],
            trace_divergent,
        )


class MessageObservationMatrixTests(TestCase):
    SEEN_MSG = MSG_ID
    EARLY_MSG = OTHER_MSG_ID
    BREAK_MSG = "55" * 32

    def seed_break_group(self):
        # Alice and Bob overlap from T0+10. EARLY_MSG appears before Bob's
        # window (benign late-joiner gap); BREAK_MSG appears inside it (a real
        # present-member break); SEEN_MSG is observed by both (convergent).
        ingest_body(
            jsonl(
                ingest_entry_event(0, ENGINE_ALICE, ACCOUNT_ALICE, self.EARLY_MSG, T0),
                ingest_entry_event(1, ENGINE_ALICE, ACCOUNT_ALICE, self.BREAK_MSG, T0 + 50),
                ingest_entry_event(2, ENGINE_ALICE, ACCOUNT_ALICE, self.SEEN_MSG, T0 + 90),
            )
        )
        ingest_body(
            jsonl(
                bob_presence_event(0, T0 + 10),
                ingest_entry_event(1, ENGINE_BOB, ACCOUNT_BOB, self.SEEN_MSG, T0 + 95),
            )
        )
        return AuditGroup.objects.get(slug=GROUP_REF)

    def test_matrix_marks_present_miss_observed_and_late_joiner_absent(self):
        group = self.seed_break_group()
        matrix = analysis_module.message_observation_matrix(list(valid_events_for_group(group)))
        column = {engine["engine_id"]: engine["idx"] for engine in matrix["engines"]}
        rows = {row["msg_id"]: row for row in matrix["rows"]}

        # A demonstrably-present engine that never logged the message: real break.
        break_row = rows[self.BREAK_MSG]
        self.assertTrue(break_row["is_divergent"])
        self.assertEqual(break_row["cells"][column[ENGINE_ALICE]]["status"], "observed")
        self.assertEqual(break_row["cells"][column[ENGINE_BOB]]["status"], "missed")
        self.assertEqual(break_row["missed_by"], [ENGINE_BOB])

        # Bob had not started logging yet: a benign gap, not a break.
        early_row = rows[self.EARLY_MSG]
        self.assertFalse(early_row["is_divergent"])
        self.assertEqual(early_row["cells"][column[ENGINE_BOB]]["status"], "absent")

        # Observed by both engines: convergent.
        seen_row = rows[self.SEEN_MSG]
        self.assertFalse(seen_row["is_divergent"])
        self.assertEqual(seen_row["cells"][column[ENGINE_BOB]]["status"], "observed")

    def test_legacy_messages_tab_is_not_served(self):
        group = self.seed_break_group()
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

        response = self.client.get(
            reverse("group-tab", kwargs={"slug": group.slug, "tab": "messages"})
        )

        self.assertEqual(response.status_code, 404)


class GroupDetailTimelineViewTests(TestCase):
    def test_group_detail_exposes_lazy_projection_tabs(self):
        ingest_body(representative_audit_log())
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

        response = self.client.get(reverse("group-detail", kwargs={"slug": GROUP_REF}))

        self.assertNotContains(response, 'id="timeline-data"')
        self.assertContains(response, reverse("group-agent-export", kwargs={"slug": GROUP_REF}))
        for tab in ("delivery", "network", "convergence", "state", "evidence", "exports"):
            self.assertContains(
                response,
                reverse("group-tab", kwargs={"slug": GROUP_REF, "tab": tab}),
            )
        self.assertContains(response, "Export JSON")

    def test_group_detail_labels_raw_message_ids_separately_from_delivery_artifacts(self):
        group = AuditGroup.objects.create(
            name="Raw only group",
            slug="raw-only-group",
            group_ref=GROUP_REF,
        )
        audit_file = AuditFile.objects.create(
            file_sha256="d" * 64,
            byte_size=128,
            raw_text="{}\n",
            validation_status=AuditFile.STATUS_VALID,
            source_name="raw-only.jsonl",
            total_line_count=1,
            valid_event_count=1,
        )
        audit_file.groups.add(group)
        AuditEvent.objects.create(
            audit_file=audit_file,
            group=group,
            line_number=1,
            line_hash="d" * 64,
            raw_line="{}",
            parse_status=AuditEvent.STATUS_VALID,
            event_type="ingest_entry",
            msg_id=MSG_ID,
            engine_id=ENGINE_ALICE,
            group_ref=GROUP_REF,
            wall_time_ms=1_700_000_000_001,
        )
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

        response = self.client.get(reverse("group-detail", kwargs={"slug": group.slug}))

        self.assertContains(response, "0 delivery artifacts")
        self.assertContains(response, "1 raw message id")
        self.assertNotContains(response, "1 message artifact")

    def test_convergence_tab_renders_projected_runs(self):
        group = AuditGroup.objects.create(
            name="Projected convergence group",
            slug="projected-convergence-group",
            group_ref=GROUP_REF,
        )
        run = ConvergenceRun.objects.create(
            group=group,
            run_id="run-paged",
            engine_id=ENGINE_ALICE,
            phase="selected",
            selected_branch_id="branch-a",
            started_at_ms=1_700_000_000_001,
        )
        ConvergenceCandidate.objects.create(
            run=run,
            branch_id="branch-a",
            fork_epoch=6,
            tip_epoch=7,
        )
        ConvergenceRuleEvaluation.objects.create(
            run=run,
            rule_name="highest_weight",
            decisive=True,
            selected_branch_id="branch-a",
        )
        non_decisive_run = ConvergenceRun.objects.create(
            group=group,
            run_id="run-no-decisive",
            engine_id=ENGINE_BOB,
            phase="selected",
            selected_branch_id="branch-b",
            started_at_ms=1_700_000_000_002,
        )
        ConvergenceCandidate.objects.create(
            run=non_decisive_run,
            branch_id="branch-b",
            fork_epoch=8,
            tip_epoch=9,
        )
        ConvergenceRuleEvaluation.objects.create(
            run=non_decisive_run,
            rule_name="non_decisive_weight",
            decisive=False,
            selected_branch_id="branch-b",
        )
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

        response = self.client.get(
            reverse("group-tab", kwargs={"slug": group.slug, "tab": "convergence"})
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "run-paged")
        self.assertContains(response, "branch-a")
        self.assertContains(response, "highest_weight")
        self.assertContains(response, "run-no-decisive")
        self.assertContains(response, "non_decisive_weight")
        runs_by_id = {run.run_id: run for run in response.context["runs"]}
        self.assertEqual(runs_by_id["run-no-decisive"].decisive_rules, [])
        self.assertContains(response, '<span class="is-muted">–</span>', html=True)

    def test_group_detail_shows_engine_preview_overflow_count(self):
        group = AuditGroup.objects.create(
            name="Crowded group",
            slug="crowded-group",
            group_ref=GROUP_REF,
        )
        audit_file = AuditFile.objects.create(
            file_sha256="b" * 64,
            byte_size=1_000,
            raw_text="\n".join("{}" for _ in range(14)),
            validation_status=AuditFile.STATUS_VALID,
            source_name="crowded.jsonl",
            total_line_count=14,
            valid_event_count=14,
        )
        AuditEvent.objects.bulk_create(
            AuditEvent(
                audit_file=audit_file,
                group=group,
                line_number=i + 1,
                line_hash=f"{i:064x}",
                raw_line="{}",
                parse_status=AuditEvent.STATUS_VALID,
                event_type="ingest_entry",
                engine_id=f"{i:032x}",
                account_ref=ACCOUNT_ALICE,
                group_ref=GROUP_REF,
                seq=i,
                wall_time_ms=1_700_000_000_000 + i,
            )
            for i in range(14)
        )
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

        response = self.client.get(reverse("group-detail", kwargs={"slug": group.slug}))

        self.assertContains(response, "+2")
        self.assertContains(response, "2 more engines")

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

    @override_settings(GOGGLES_AGENT_EXPORT_MAX_EVENTS=1)
    def test_group_agent_export_rejects_oversized_synchronous_build(self):
        ingest_body(representative_audit_log())
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

        response = self.client.get(reverse("group-agent-export", kwargs={"slug": GROUP_REF}))

        self.assertEqual(response.status_code, 413)
        self.assertEqual(response.json()["event_count"], 2)
        self.assertEqual(response.json()["max_events"], 1)

    def test_group_detail_fetches_events_with_bounded_queries(self):
        ingest_body(representative_audit_log(engine_id=ENGINE_ALICE))
        ingest_body(representative_audit_log(engine_id=ENGINE_BOB))
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(
                reverse("group-tab", kwargs={"slug": GROUP_REF, "tab": "evidence"})
            )

        self.assertEqual(response.status_code, 200)
        self.assertLessEqual(len(ctx.captured_queries), 12)

    def test_group_detail_does_not_compute_message_traces_for_shell(self):
        ingest_body(representative_audit_log(engine_id=ENGINE_ALICE))
        ingest_body(representative_audit_log(engine_id=ENGINE_BOB))
        group = AuditGroup.objects.get(slug=GROUP_REF)
        group.divergent_message_count = 7
        group.save(update_fields=["divergent_message_count"])
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

        with mock.patch.object(
            analysis_module,
            "message_traces_from_events",
            side_effect=AssertionError("group shell must use projection/header counts"),
        ):
            response = self.client.get(reverse("group-detail", kwargs={"slug": GROUP_REF}))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Overview")

    def test_group_detail_query_count_does_not_grow_with_file_count(self):
        # Per-file group_event_count is annotated in SQL by
        # audit_files_for_group (goggles#65), not computed per file. Prove it by
        # showing the query count is identical whether the group has 2 files or
        # 6: a COUNT-per-file N+1 (goggles#18) would add one query per extra
        # file.
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

        files_url = reverse("group-tab", kwargs={"slug": GROUP_REF, "tab": "evidence"})
        with CaptureQueriesContext(connection) as few_ctx:
            response_few = self.client.get(files_url)
        self.assertEqual(response_few.status_code, 200)
        self.assertEqual(AuditFile.objects.count(), 2)

        for engine_id in engines[2:]:
            ingest_body(representative_audit_log(engine_id=engine_id))
        self.assertEqual(AuditFile.objects.count(), len(engines))

        with CaptureQueriesContext(connection) as many_ctx:
            response_many = self.client.get(files_url)
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

    def test_group_detail_does_not_load_events_of_marginally_overlapping_files(self):
        # goggles#65: audit_files_for_group annotates the per-file group-event
        # count in SQL. It must NOT prefetch every AuditEvent of every related
        # file just to count, in Python, the matching subset. Prove it with a
        # file whose events span two groups: rendering group_detail for one
        # files tab must report a count of only that group's events for the file
        # AND must never SELECT the file's events (incl. the other group's)
        # into the worker.
        body = jsonl(
            audit_event(0, group_ref=GROUP_REF),
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
        ingest_body(body)
        User.objects.create_user(username="analyst", password="correct horse battery staple")
        self.client.login(username="analyst", password="correct horse battery staple")

        audit_file = AuditFile.objects.get()
        self.assertEqual(audit_file.events.count(), 2)  # one per group

        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(
                reverse("group-tab", kwargs={"slug": GROUP_REF, "tab": "evidence"})
            )

        self.assertEqual(response.status_code, 200)

        # Only this group's single event is counted, not all 2 events on the file.
        rows = response.context["audit_files"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], audit_file.id)
        self.assertEqual(rows[0]["group_event_count"], 1)

        # The dropped prefetch (`prefetch_related("events__group")`) issued a
        # standalone `SELECT <event columns> FROM "forensics_auditevent" WHERE
        # ..."audit_file_id" IN (...)` that pulled every event of every related
        # file into the worker. With the SQL annotation the per-file count is a
        # `COUNT(...) FILTER` over a JOIN on the AuditFile query, so no query
        # loads events keyed by `audit_file_id IN`. The legitimate event loads
        # this request performs (valid_events_for_group, the invalid-count) are
        # all scoped to `group_id`, never `audit_file_id IN`, so this marker is
        # unique to the prefetch.
        prefetch_shaped = [
            q["sql"] for q in ctx.captured_queries if '"audit_file_id" IN' in q["sql"]
        ]
        self.assertEqual(
            prefetch_shaped,
            [],
            "group detail prefetched the events of every related file just to "
            "count per-file group membership (goggles#65 over-fetch regression)",
        )


class GroupOverviewLazyContextTests(TestCase):
    # Regression guard for goggles#123: the heavy group_overview_context()
    # builder must only run for the detail-page shell, never for the lightweight
    # summary/API contexts that discard it.
    def setUp(self):
        ingest_body(representative_audit_log())
        self.group = AuditGroup.objects.get(group_ref=GROUP_REF)

    def test_group_summary_context_does_not_build_overview(self):
        with mock.patch("forensics.views.group_overview_context") as overview:
            context = group_summary_context(self.group)

        overview.assert_not_called()
        self.assertNotIn("overview", context)
        self.assertIn("summary", context)
        self.assertIn("tab_counts", context)

    def test_group_api_payload_does_not_build_overview(self):
        with mock.patch("forensics.views.group_overview_context") as overview:
            payload = group_api_payload(self.group)

        overview.assert_not_called()
        self.assertEqual(
            set(payload),
            {"slug", "name", "group_ref", "summary", "tab_counts", "updated_at"},
        )

    def test_group_api_payload_does_not_build_engine_preview(self):
        with (
            mock.patch(
                "forensics.views.engine_source_values",
                side_effect=AssertionError(
                    "group_api_payload must not load full engine source metadata"
                ),
            ) as source_values,
            mock.patch("forensics.views.group_engine_rows", wraps=group_engine_rows) as engine_rows,
        ):
            payload = group_api_payload(self.group)

        engine_rows.assert_not_called()
        source_values.assert_not_called()
        self.assertEqual(
            set(payload),
            {"slug", "name", "group_ref", "summary", "tab_counts", "updated_at"},
        )

    def test_group_detail_shell_context_builds_overview_once(self):
        with mock.patch(
            "forensics.views.group_overview_context", wraps=group_overview_context
        ) as overview:
            context = group_detail_shell_context(self.group)

        overview.assert_called_once_with(self.group)
        self.assertIn("overview", context)


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

    def test_admin_changelists_do_not_select_verbatim_evidence_columns(self):
        audit_file = self.make_audit_file(3, source_name="large")
        AuditFile.objects.filter(pk=audit_file.pk).update(raw_text="x" * 5_000_000)

        with CaptureQueriesContext(connection) as captured:
            file_response = self.client.get(reverse("admin:forensics_auditfile_changelist"))
            event_response = self.client.get(reverse("admin:forensics_auditevent_changelist"))

        self.assertEqual(file_response.status_code, 200)
        self.assertEqual(event_response.status_code, 200)
        self.assertEqual(heavy_bulk_selects(captured.captured_queries), [])

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

    def test_audit_file_admin_search_avoids_json_field_scans(self):
        from .admin import AuditFileAdmin

        self.assertEqual(AuditFileAdmin.search_fields, ("file_sha256__exact",))
        self.assertNotIn("account_refs", AuditFileAdmin.search_fields)
        self.assertNotIn("engine_ids", AuditFileAdmin.search_fields)
        self.assertNotIn("group_refs", AuditFileAdmin.search_fields)
        self.assertFalse(AuditFileAdmin.show_full_result_count)

    def test_audit_event_admin_filters_avoid_distinct_and_fk_dropdown_scans(self):
        from .admin import AuditEventAdmin

        self.assertEqual(AuditEventAdmin.list_filter, ("parse_status",))
        self.assertNotIn("event_type", AuditEventAdmin.list_filter)
        self.assertNotIn("outcome", AuditEventAdmin.list_filter)
        self.assertNotIn("outcome_kind", AuditEventAdmin.list_filter)
        self.assertNotIn("new_state", AuditEventAdmin.list_filter)
        self.assertNotIn("audit_file", AuditEventAdmin.list_filter)
        self.assertFalse(AuditEventAdmin.show_full_result_count)

    def test_audit_event_admin_search_avoids_raw_line_scans(self):
        from .admin import AuditEventAdmin

        self.assertEqual(
            AuditEventAdmin.search_fields,
            (
                "account_ref__exact",
                "engine_id__exact",
                "group_ref__exact",
                "msg_id__exact",
                "payload_digest__exact",
                "candidate_digest__exact",
            ),
        )
        self.assertNotIn("raw_line", AuditEventAdmin.search_fields)
        self.assertNotIn("incumbent_digest", AuditEventAdmin.search_fields)

    def test_audit_event_admin_keeps_audit_file_deep_link_without_sidebar_filter(self):
        from .admin import AuditEventAdmin

        self.assertNotIn("audit_file", AuditEventAdmin.list_filter)
        self.assertIn("audit_file", AuditEventAdmin.autocomplete_fields)
        self.assertIn("group", AuditEventAdmin.autocomplete_fields)

    def test_audit_event_change_page_bounds_raw_evidence(self):
        from .admin import AuditEventAdmin

        audit_file = self.make_audit_file(1)
        event = audit_file.events.get()
        trailing_marker = "TRAILING-RAW-LINE-MARKER"
        AuditEvent.objects.filter(pk=event.pk).update(
            raw_line="FIRST-RAW-LINE-MARKER" + ("x" * 2_000_000) + trailing_marker,
            raw_event={"oversized": "y" * 2_000_000},
            raw_kind={"oversized": "z" * 500_000},
            raw_context={"oversized": "q" * 500_000},
        )

        response = self.client.get(reverse("admin:forensics_auditevent_change", args=[event.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertLess(len(response.content), 200_000)
        self.assertContains(response, "Raw line (preview)")
        self.assertContains(response, "FIRST-RAW-LINE-MARKER")
        self.assertNotContains(response, trailing_marker)
        self.assertContains(response, "Open JSON evidence")
        self.assertContains(
            response,
            reverse("api-event-evidence", kwargs={"event_id": event.pk}),
        )
        for field in HEAVY_EVENT_SELECT_COLUMNS:
            self.assertIn(field, AuditEventAdmin.exclude)
            self.assertNotContains(response, f'name="{field}"')

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
    _MANAGED_PREFIXES = ("DJANGO_", "GLITCHTIP_")
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

    def test_missing_glitchtip_dsn_leaves_sdk_disabled(self):
        with self._clean_env(**self._PROD_ENV):
            with mock.patch("sentry_sdk.init") as sentry_init:
                ns = self._load_settings()

        self.assertEqual(ns["GLITCHTIP_DSN"], "")
        sentry_init.assert_not_called()

    def test_glitchtip_dsn_configures_privacy_safe_sdk_defaults(self):
        dsn = "https://public@example.com/1"
        with self._clean_env(**self._PROD_ENV, GLITCHTIP_DSN=dsn):
            with mock.patch("sentry_sdk.init") as sentry_init:
                ns = self._load_settings()

        sentry_init.assert_called_once()
        _args, kwargs = sentry_init.call_args
        self.assertEqual(kwargs["dsn"], dsn)
        self.assertEqual(kwargs["traces_sample_rate"], 0.05)
        self.assertFalse(kwargs["auto_session_tracking"])
        self.assertFalse(kwargs["send_default_pii"])
        self.assertEqual(kwargs["max_request_body_size"], "never")
        self.assertFalse(kwargs["include_local_variables"])
        self.assertEqual(kwargs["environment"], "production")
        self.assertIsNone(kwargs["release"])
        self.assertIs(kwargs["before_send"], ns["scrub_glitchtip_event"])

    def test_glitchtip_trace_sample_rate_is_env_overridable(self):
        with self._clean_env(**self._PROD_ENV, GLITCHTIP_DSN="https://public@example.com/1"):
            with mock.patch.dict(os.environ, {"GLITCHTIP_TRACES_SAMPLE_RATE": "0.2"}):
                with mock.patch("sentry_sdk.init") as sentry_init:
                    self._load_settings()

        _args, kwargs = sentry_init.call_args
        self.assertEqual(kwargs["traces_sample_rate"], 0.2)

    def test_glitchtip_security_endpoint_enables_csp_report_only(self):
        endpoint = "https://glitch.example.com/api/1/security/?glitchtip_key=public"
        with self._clean_env(DJANGO_DEBUG="1", GLITCHTIP_SECURITY_ENDPOINT=endpoint):
            with mock.patch("sentry_sdk.init") as sentry_init:
                ns = self._load_settings()

        sentry_init.assert_not_called()
        self.assertEqual(
            ns["MIDDLEWARE"][1],
            "django.middleware.csp.ContentSecurityPolicyMiddleware",
        )
        policy = ns["SECURE_CSP_REPORT_ONLY"]
        self.assertEqual(policy["report-uri"], [endpoint])
        self.assertEqual(policy["default-src"], [ns["CSP"].SELF])
        self.assertEqual(policy["object-src"], [ns["CSP"].NONE])
        self.assertEqual(policy["frame-ancestors"], [ns["CSP"].NONE])

    def test_glitchtip_scrubber_removes_sensitive_event_material(self):
        with self._clean_env(DJANGO_DEBUG="1"):
            ns = self._load_settings()

        scrubbed = ns["scrub_glitchtip_event"](
            {
                "request": {
                    "headers": {
                        "Authorization": "Bearer raw-token",
                        "User-Agent": "client",
                        "X-Goggles-Device-Label": "iphone",
                        "Accept": "application/json",
                    },
                    "data": "raw upload body",
                    "cookies": {"sessionid": "secret"},
                    "query_string": "token=secret",
                    "env": {"REMOTE_ADDR": "203.0.113.8"},
                },
                "user": {"username": "investigator", "ip_address": "203.0.113.8"},
                "extra": {
                    "raw_text": '{"engine_id":"abc"}',
                    "nested": {
                        "payload_digest": "abc123",
                        "safe_count": 2,
                    },
                    "upload_token": "secret",
                },
            },
            {},
        )

        request = scrubbed["request"]
        self.assertNotIn("data", request)
        self.assertNotIn("cookies", request)
        self.assertNotIn("query_string", request)
        self.assertNotIn("env", request)
        self.assertEqual(request["headers"]["Authorization"], ns["SCRUBBED_VALUE"])
        self.assertEqual(request["headers"]["User-Agent"], ns["SCRUBBED_VALUE"])
        self.assertEqual(request["headers"]["X-Goggles-Device-Label"], ns["SCRUBBED_VALUE"])
        self.assertEqual(request["headers"]["Accept"], "application/json")
        self.assertEqual(scrubbed["user"], {"username": "investigator"})
        self.assertEqual(scrubbed["extra"]["raw_text"], ns["SCRUBBED_VALUE"])
        self.assertEqual(scrubbed["extra"]["nested"]["payload_digest"], ns["SCRUBBED_VALUE"])
        self.assertEqual(scrubbed["extra"]["nested"]["safe_count"], 2)
        self.assertEqual(scrubbed["extra"]["upload_token"], ns["SCRUBBED_VALUE"])


class ClientIpTests(SimpleTestCase):
    """Regression tests for goggles#15.

    ``source_ip`` must come from the trusted rightmost ``X-Forwarded-For`` hop
    appended by our reverse proxy, never from the spoofable leftmost client
    value, and a non-IP must degrade to ``None`` rather than 500 the upload.
    """

    def setUp(self):
        self.factory = RequestFactory()

    def test_uses_rightmost_trusted_proxy_value_not_spoofed_leftmost(self):
        request = self.factory.post(
            "/",
            HTTP_X_FORWARDED_FOR="1.2.3.4, 203.0.113.10",
            REMOTE_ADDR="127.0.0.1",
        )

        self.assertEqual(client_ip(request), "203.0.113.10")

    def test_invalid_forwarded_for_value_returns_none(self):
        request = self.factory.post(
            "/",
            HTTP_X_FORWARDED_FOR="not-an-ip",
            REMOTE_ADDR="127.0.0.1",
        )

        self.assertIsNone(client_ip(request))

    def test_absent_forwarded_for_falls_back_to_remote_addr(self):
        request = self.factory.post("/", REMOTE_ADDR="198.51.100.22")

        self.assertEqual(client_ip(request), "198.51.100.22")

    def test_ipv6_forwarded_for_value_is_preserved(self):
        request = self.factory.post(
            "/",
            HTTP_X_FORWARDED_FOR="1.2.3.4, 2001:db8::1",
            REMOTE_ADDR="127.0.0.1",
        )

        self.assertEqual(client_ip(request), "2001:db8::1")

    def test_invalid_remote_addr_returns_none(self):
        request = self.factory.post("/", REMOTE_ADDR="garbage")

        self.assertIsNone(client_ip(request))
