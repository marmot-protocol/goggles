from __future__ import annotations

from .models import AuditEvent

# AuditEvent columns that are populated by ingestion bookkeeping instead of the
# normalized kind/context copy loop. Everything else on AuditEvent is considered
# a persisted normalized value and is copied when normalize_event() produces the
# matching key.
NON_NORMALIZED_AUDIT_EVENT_FIELDS = frozenset(
    {
        "id",
        "group",
        "audit_file",
        "line_number",
        "line_hash",
        "raw_line",
        "raw_event",
        "raw_kind",
        "raw_context",
        "parse_status",
        "validation_error",
        "schema_version",
        "seq",
        "wall_time_ms",
        "account_ref",
        "engine_id",
        "group_ref",
        "event_type",
        "created_at",
    }
)

# The agent export already includes the verbatim raw context under event["context"].
# Keep the duplicated normalized context snapshots out of event["normalized"], but
# make that divergence visible here instead of hiding it in a second hand-written
# field tuple.
AGENT_EXPORT_NORMALIZED_FIELD_EXCLUDE = frozenset(
    {
        "context_human_action",
        "context_transport",
        "context_engine",
        "context_group",
    }
)
AGENT_EXPORT_NORMALIZED_FIELD_EXTRA = ()

# Snapshot of the exact persisted normalized-field set, pinned in
# AuditEvent model-declaration order.
#
# persisted_normalized_fields() *derives* this set from the AuditEvent model
# (concrete columns minus NON_NORMALIZED_AUDIT_EVENT_FIELDS), which guards the
# silent-drop direction (a normalized key that no column persists). It does NOT
# guard the reverse, more dangerous direction for a forensic tool: a future
# bookkeeping / non-normalized column added to AuditEvent whose author forgets
# to list it in NON_NORMALIZED_AUDIT_EVENT_FIELDS would be auto-included here,
# silently copied from parsed.normalized by event_values(), and surfaced under
# event["normalized"] in the agent-state export -- with no test failing.
#
# Pinning the derived set against this explicit tuple forces any AuditEvent
# column add/remove to come with a conscious edit here, putting a reviewer's
# eyes on whether the new column is a normalized value (extend this tuple) or
# bookkeeping (add it to NON_NORMALIZED_AUDIT_EVENT_FIELDS). See goggles#85.
EXPECTED_PERSISTED_NORMALIZED_FIELDS = (
    "context_operation_id",
    "context_human_action",
    "context_transport",
    "context_engine",
    "context_group",
    "human_action_action",
    "human_action_origin",
    "human_action_phase",
    "human_action_fields",
    "human_action_component_ids",
    "human_action_target_count",
    "human_action_message_ids",
    "msg_id",
    "outbound_msg_id",
    "outbound_welcome_msg_ids",
    "target_kind",
    "relay_urls",
    "accepted_relay_urls",
    "failed_relays",
    "required_acks",
    "met_required_acks",
    "epoch",
    "source_epoch",
    "from_epoch",
    "to_epoch",
    "pending_epoch",
    "restored_epoch",
    "current_tip_epoch",
    "selected_fork_epoch",
    "selected_tip_epoch",
    "payload_len",
    "payload_digest",
    "candidate_digest",
    "incumbent_digest",
    "envelope_kind",
    "outcome",
    "outcome_kind",
    "stale_reason",
    "decision",
    "reason",
    "winner",
    "new_state",
    "pending_kind",
    "intent_kind",
    "result_kind",
    "proposal_kind",
    "snapshot_name",
    "selected_branch_id",
    "detail",
    "fallback_snapshot_used",
    "invalidated_msg_id",
    "max_rewind_commits",
    "candidate_count",
    "eligible_count",
)


def persisted_normalized_fields() -> tuple[str, ...]:
    """AuditEvent fields copied from ParsedLine.normalized during ingest."""
    return tuple(
        field.name
        for field in AuditEvent._meta.local_concrete_fields
        if field.name not in NON_NORMALIZED_AUDIT_EVENT_FIELDS
    )


def agent_export_normalized_fields() -> tuple[str, ...]:
    """Persisted normalized fields included under event["normalized"] in exports."""
    return tuple(
        field
        for field in persisted_normalized_fields()
        if field not in AGENT_EXPORT_NORMALIZED_FIELD_EXCLUDE
    ) + tuple(AGENT_EXPORT_NORMALIZED_FIELD_EXTRA)
