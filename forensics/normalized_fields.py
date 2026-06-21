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


def audit_event_concrete_field_names() -> frozenset[str]:
    return frozenset(field.name for field in AuditEvent._meta.local_concrete_fields)


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
