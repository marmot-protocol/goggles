from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime
from itertools import count

from django.db.models import Count, Max, Min, Q
from django.utils import timezone

from . import normalized_fields as normalized_field_config
from .models import AuditEvent, AuditFile, AuditGroup

FORK_EVENT_TYPES = (
    "fork_resolution",
    "convergence_decision",
    "epoch_confirmed",
    "epoch_rolled_back",
)

# Every ``AuditEvent`` column that carries a group epoch. The group-list epoch
# range spans all of them so that groups whose epoch activity is expressed via
# ``epoch_state_changed`` / ``group_state_changed`` / convergence events (i.e.
# anything other than ``epoch_confirmed``) still report a range instead of "–".
GROUP_EPOCH_RANGE_FIELDS = (
    "epoch",
    "source_epoch",
    "from_epoch",
    "to_epoch",
    "pending_epoch",
    "restored_epoch",
    "current_tip_epoch",
    "selected_fork_epoch",
    "selected_tip_epoch",
)

PEELER_EVENT_TYPES = ("peeler_outcome", "rejection", "message_state_changed")

FAILED_MESSAGE_STATES = {"failed", "epoch_invalidated"}
DEFERRED_MESSAGE_STATES = {"peel_deferred"}
ATTENTION_MESSAGE_STATES = FAILED_MESSAGE_STATES | DEFERRED_MESSAGE_STATES
PEELER_WARNING_OUTCOMES = {"decrypt_failed", "stale_epoch"}

# Event kinds that represent message traffic rather than group-state machinery.
MESSAGE_EVENT_TYPES = {
    "ingest_entry",
    "ingest_outcome",
    "send_entry",
    "send_outcome",
    "publish_attempt",
    "publish_outcome",
    "publish_failure",
    "human_action",
    "peeler_outcome",
    "message_state_changed",
    "rejection",
}

EPOCH_CHANGE_RESULT_KINDS = {"group_created", "group_evolution"}
AGENT_EXPORT_SCHEMA_VERSION = "goggles-agent-group-state/v1"
AGENT_EXPORT_NORMALIZED_FIELDS = normalized_field_config.agent_export_normalized_fields()

# What a forensic export carries versus deliberately omits. Shared verbatim by the
# agent-state export and the streaming group export so the two never disagree about
# the sensitivity contract of the data they emit.
EXPORT_SENSITIVITY = {
    "classification": "sensitive_forensic_export",
    "contains": [
        "engine_ids",
        "account_refs",
        "group_refs",
        "message_ids",
        "payload_digests",
        "relay_urls",
    ],
    "omits": [
        "raw_upload_bodies",
        "bearer_tokens",
        "source_ips",
        "user_agents",
    ],
}

VIZ_PALETTE_SIZE = 8
GROUP_REF_FULL_DISPLAY_MAX = 80
GROUP_REF_EDGE_DISPLAY_CHARS = 32
STRUCTURAL_QUARANTINE_ERRORS = (
    "audit log contains multiple engine_ids",
    "audit log contains multiple account_refs",
)


def structural_quarantine_exclusion(field_prefix: str = "") -> Q:
    """The ``Q`` that excludes events belonging to a *structurally* quarantined
    file (multi-engine / multi-account uploads), the single definition shared by
    every "events that count for a group" path.

    A file marked ``validation_status=INVALID`` for a non-structural reason
    (e.g. one malformed JSONL line) still contributes its ``parse_status=VALID``
    events to the group: those events are real evidence and are rendered in the
    timeline/tabs/export (goggles#80, commit ``0ac4442``). Only the structural
    quarantine errors above mean the *whole* file's engine/account attribution
    is untrustworthy and must be dropped wholesale.

    ``field_prefix`` adapts the predicate to the relation path of the caller:
    ``""`` for a queryset already rooted on ``AuditEvent``
    (``audit_file__validation_error``), or ``"audit_events__"`` for the
    reverse relation used when annotating ``AuditGroup``
    (``audit_events__audit_file__validation_error``).
    """
    predicate = Q()
    for error in STRUCTURAL_QUARANTINE_ERRORS:
        predicate &= ~Q(**{f"{field_prefix}audit_file__validation_error__icontains": error})
    return predicate


def audit_files_for_group(group):
    # File membership comes from the explicit AuditFile.groups M2M (goggles#37),
    # NOT from stored AuditEvent rows. A duplicate-heavy upload whose group
    # events were all deduplicated away has zero stored events for the group but
    # is still genuinely linked to it; filtering on `events__group` (the old
    # behavior) dropped such files from group detail entirely.
    #
    # The per-file group-event count is still annotated in SQL from the stored
    # events (a duplicate-only file correctly shows group_event_count=0). This
    # avoids prefetching every event of every related file just to count them in
    # Python (goggles#65) while staying bounded — no COUNT-per-file N+1
    # (goggles#18). distinct=True guards against row multiplication from joining
    # both the groups (M2M) and events relations.
    return (
        AuditFile.objects.filter(groups=group)
        # ``raw_text`` can be tens of MiB and none of the group metadata views
        # consume it. Loading it here made every overview/evidence/export
        # metadata query retain the full body of every related upload. The raw
        # body remains available through the dedicated detail/download paths.
        .defer("raw_text", "user_agent")
        .annotate(
            group_event_count=Count("events", filter=Q(events__group=group), distinct=True),
        )
        .distinct()
        .order_by("-created_at", "-id")
    )


def valid_events_for_group(group, *, include_export_fields=False):
    fields = [
        "id",
        "audit_file_id",
        "audit_file__source_account_label",
        "audit_file__source_device_label",
        "audit_file__source_platform",
        "line_number",
        "parse_status",
        "validation_error",
        "seq",
        "wall_time_ms",
        "account_ref",
        "engine_id",
        "group_ref",
        "event_type",
        *AGENT_EXPORT_NORMALIZED_FIELDS,
    ]
    if include_export_fields:
        fields.extend(
            [
                "line_hash",
                "schema_version",
                "raw_context",
                "raw_kind",
            ]
        )
    return (
        AuditEvent.objects.filter(
            structural_quarantine_exclusion(),
            group=group,
            parse_status=AuditEvent.STATUS_VALID,
        )
        .select_related("audit_file")
        .only(*fields)
        .order_by(
            "wall_time_ms",
            "engine_id",
            "line_number",
            "id",
        )
    )


def group_summary(group, audit_files, events=None):
    if events is None:
        events = list(valid_events_for_group(group))
    engine_ids = {event.engine_id for event in events if event.engine_id}
    group_refs = {event.group_ref for event in events if event.group_ref}
    msg_ids = message_ids_from_events(events)
    invalid_count = AuditEvent.objects.filter(
        group=group,
        parse_status=AuditEvent.STATUS_INVALID,
    ).count()
    return {
        "file_count": len(audit_files),
        "event_count": len(events),
        "invalid_event_count": invalid_count,
        "engine_count": len(engine_ids),
        "group_count": len(group_refs),
        "message_count": len(msg_ids),
    }


def file_rows_for_group(audit_files, group):
    return [
        {
            "id": audit_file.id,
            "source_name": audit_file.source_name or f"audit-file-{audit_file.id}",
            "source_label": source_label_for_file(audit_file),
            "source_account_label": audit_file.source_account_label,
            "source_device_label": audit_file.source_device_label,
            "source_platform": audit_file.source_platform,
            "validation_status": audit_file.validation_status,
            "total_line_count": audit_file.total_line_count,
            "valid_event_count": audit_file.valid_event_count,
            "invalid_event_count": audit_file.invalid_event_count,
            "duplicate_event_count": audit_file.duplicate_event_count,
            # Per-file group-event count, annotated in SQL by
            # audit_files_for_group (`Count("events", filter=Q(events__group))`).
            # Counting in the database avoids loading every event of every
            # related file into memory (goggles#65) while staying bounded — no
            # COUNT-per-file N+1 (goggles#18).
            "group_event_count": audit_file.group_event_count,
            "account_refs": audit_file.account_refs,
            "engine_ids": audit_file.engine_ids,
            "group_refs": audit_file.group_refs,
            "created_at": audit_file.created_at,
        }
        for audit_file in audit_files
    ]


# ---------------------------------------------------------------------------
# Groups home
# ---------------------------------------------------------------------------


def group_list_rows():
    groups = list(AuditGroup.objects.all())
    group_file_counts = audit_file_counts_for_groups(groups)
    group_event_stats, fork_group_ids = event_stats_for_groups(groups)
    for group in groups:
        stats = group_event_stats.get(group.pk, {})
        search_ref = group.group_ref or group.slug
        group.search_ref = search_ref
        group.display_ref = display_group_ref(search_ref)
        group.audit_file_count = group_file_counts.get(group.pk, 0)
        group.event_count = stats.get("event_count", 0)
        group.engine_count = stats.get("engine_count", 0)
        group.epoch_min = stats.get("epoch_min")
        group.epoch_max = stats.get("epoch_max")
        group.last_activity_ms = stats.get("last_activity_ms")
        group.has_fork_activity = group.pk in fork_group_ids
        group.divergent_count = group.divergent_message_count
        group.last_activity = _last_activity_datetime(group.last_activity_ms)
    return groups


def event_stats_for_groups(groups):
    """Aggregate group-list event stats from ``AuditEvent`` directly.

    Joining ``AuditGroup`` to every event and every related file in one
    annotation makes the landing page sensitive to planner choices once the
    structural-quarantine predicate is included. Group from the event side
    instead; this preserves the canonical predicate while keeping the work
    proportional to stored events, not multiplied group joins.
    """
    group_ids = [group.pk for group in groups if group.pk]
    if not group_ids:
        return {}, set()
    valid_events = AuditEvent.objects.filter(
        structural_quarantine_exclusion(),
        group_id__in=group_ids,
        parse_status=AuditEvent.STATUS_VALID,
    )
    annotations = {
        "event_count": Count("id", distinct=True),
        "engine_count": Count("engine_id", filter=~Q(engine_id=""), distinct=True),
        "last_activity_ms": Max("wall_time_ms"),
    }
    for field in GROUP_EPOCH_RANGE_FIELDS:
        annotations[f"epoch_min_{field}"] = Min(field)
        annotations[f"epoch_max_{field}"] = Max(field)

    stats = {}
    for row in valid_events.values("group_id").annotate(**annotations):
        mins = [row[f"epoch_min_{field}"] for field in GROUP_EPOCH_RANGE_FIELDS]
        maxs = [row[f"epoch_max_{field}"] for field in GROUP_EPOCH_RANGE_FIELDS]
        row["epoch_min"] = min((v for v in mins if v is not None), default=None)
        row["epoch_max"] = max((v for v in maxs if v is not None), default=None)
        stats[row["group_id"]] = row
    fork_group_ids = set(
        valid_events.filter(event_type__in=["fork_resolution", "epoch_rolled_back"])
        .values_list("group_id", flat=True)
        .distinct()
    )
    return stats, fork_group_ids


def audit_file_counts_for_groups(groups):
    """Count explicit group-file memberships without multiplying event rows.

    Combining the ``AuditFile.groups`` M2M join with the event aggregates in a
    single group-list annotation makes Postgres compute DISTINCT counts over the
    event x file-membership product for each group. On production-sized uploads
    that can time out the landing page. Keep the event aggregate query narrow,
    then count the M2M table independently.
    """
    group_ids = [group.pk for group in groups if group.pk]
    if not group_ids:
        return {}
    through = AuditFile.groups.through
    return {
        row["auditgroup_id"]: row["count"]
        for row in (
            through.objects.filter(auditgroup_id__in=group_ids)
            .values("auditgroup_id")
            .annotate(count=Count("auditfile_id", distinct=True))
        )
    }


def _last_activity_datetime(last_activity_ms):
    """Build a ``datetime`` from a ``wall_time_ms`` value, defensively.

    Ingest bounds ``wall_time_ms`` to a sane epoch range, but data already in
    the database (uploaded before that guard, or via a future bug) could carry
    an out-of-range value. ``datetime.fromtimestamp`` raises for those (year
    > 9999), and this runs for the groups landing page (also
    ``LOGIN_REDIRECT_URL``), so one bad event must never 500 the page for
    every analyst. Degrade to ``None`` ("unknown time") instead.
    """
    if last_activity_ms is None:
        return None
    try:
        return datetime.fromtimestamp(last_activity_ms / 1000, tz=UTC)
    except (ValueError, OverflowError, OSError):
        return None


def display_group_ref(value: str) -> str:
    if len(value) <= GROUP_REF_FULL_DISPLAY_MAX:
        return value
    return f"{value[:GROUP_REF_EDGE_DISPLAY_CHARS]}...{value[-GROUP_REF_EDGE_DISPLAY_CHARS:]}"


def divergent_counts_for_groups(groups):
    """Compute persisted divergent-message counts for the given groups.

    This is intentionally kept out of the groups landing page hot path. Ingest
    calls it only for groups touched by a new upload, then stores the result on
    ``AuditGroup.divergent_message_count`` so ``/`` can render without loading
    every valid ``AuditEvent`` into Python.
    """
    return divergent_counts_for_group_ids([group.pk for group in groups if group.pk])


def is_divergent_message(engines, in_scope_engines):
    """A message is divergent when at least one engine observed it AND at least
    one *in-scope* engine did not.

    ``in_scope_engines`` is the membership-aware universe for a single message:
    its observers plus the engines that were demonstrably active when it first
    appeared (see ``engines_present_but_missing``). Scoping to in-scope engines
    keeps a late joiner — or an engine whose log ends earlier — from being
    counted as "missing" traffic it could never have seen, so the headline
    divergent count reflects real breaks rather than benign membership gaps.

    Single source of truth for the divergence predicate, shared by the
    lightweight persisted aggregation (``divergent_counts_for_group_ids``,
    landing-page hot path) and the trace-based detail computation
    (``missing_observations_for_group`` / ``group_integrity_summary``). Both
    callers build the in-scope set identically, so the landing-page count and
    the detail-page count cannot silently drift; the parity regression test
    guards that. Migration 0006 backfilled the original (pre-membership)
    definition and is frozen history; migration 0009 recomputes existing rows
    with this membership-aware definition.
    """
    observed = set(engines)
    in_scope = set(in_scope_engines)
    return bool(observed) and bool(in_scope - observed)


def engine_windows(events):
    """Per-engine ``[first_ms, last_ms]`` wall-clock observation window.

    The window is the span of timestamps an engine actually emitted within the
    event set. Events without a wall time can't be placed, so they don't widen
    it. This bounds where an engine is treated as an active member for
    divergence: a message is only "missed" by an engine if it appeared inside
    that engine's window.
    """
    windows: dict[str, tuple[int, int]] = {}
    for event in events:
        engine_id = event.engine_id
        wall_time_ms = event.wall_time_ms
        if not engine_id or wall_time_ms is None:
            continue
        first, last = windows.get(engine_id, (wall_time_ms, wall_time_ms))
        windows[engine_id] = (min(first, wall_time_ms), max(last, wall_time_ms))
    return windows


def engines_present_but_missing(observers, reference_ms, windows, all_engines):
    """Engines that were demonstrably active when a message first appeared but
    hold no event for it — the membership-aware definition of a real break.

    ``reference_ms`` is the earliest time any engine observed the message. A
    non-observer counts as a present-but-missing break only when that instant
    lies inside its ``engine_windows`` span. A ``None`` reference (the message
    was never observed with a wall time) accuses no one.
    """
    if reference_ms is None:
        return set()
    missing = set()
    for engine_id in all_engines:
        if engine_id in observers:
            continue
        window = windows.get(engine_id)
        if window is not None and window[0] <= reference_ms <= window[1]:
            missing.add(engine_id)
    return missing


def divergent_counts_for_group_ids(group_ids):
    """Return ``{group_id: divergent_message_count}`` for persisted updates."""
    group_ids = list(dict.fromkeys(group_id for group_id in group_ids if group_id))
    counts = dict.fromkeys(group_ids, 0)
    if not group_ids:
        return counts

    engines_by_group = defaultdict(set)
    windows_by_group: dict[int, dict[str, tuple[int, int]]] = defaultdict(dict)
    message_engines_by_group = defaultdict(lambda: defaultdict(set))
    message_reference_by_group: dict[int, dict[str, int]] = defaultdict(dict)
    rows = AuditEvent.objects.filter(
        structural_quarantine_exclusion(),
        group_id__in=group_ids,
        parse_status=AuditEvent.STATUS_VALID,
    ).values_list(
        "group_id",
        "engine_id",
        "wall_time_ms",
        "msg_id",
        "outbound_msg_id",
        "invalidated_msg_id",
        "outbound_welcome_msg_ids",
        "human_action_message_ids",
    )

    for (
        group_id,
        engine_id,
        wall_time_ms,
        msg_id,
        outbound_msg_id,
        invalidated_msg_id,
        outbound_welcome_msg_ids,
        human_action_message_ids,
    ) in rows.iterator(chunk_size=2_000):
        if not engine_id:
            continue
        engines_by_group[group_id].add(engine_id)
        if wall_time_ms is not None:
            windows = windows_by_group[group_id]
            first, last = windows.get(engine_id, (wall_time_ms, wall_time_ms))
            windows[engine_id] = (min(first, wall_time_ms), max(last, wall_time_ms))
        for message_id in event_message_id_values(
            msg_id,
            outbound_msg_id,
            invalidated_msg_id,
            outbound_welcome_msg_ids,
            human_action_message_ids,
        ):
            message_engines_by_group[group_id][message_id].add(engine_id)
            if wall_time_ms is not None:
                references = message_reference_by_group[group_id]
                current = references.get(message_id)
                if current is None or wall_time_ms < current:
                    references[message_id] = wall_time_ms

    for group_id, message_engines in message_engines_by_group.items():
        all_engines = engines_by_group[group_id]
        windows = windows_by_group[group_id]
        references = message_reference_by_group[group_id]
        divergent = 0
        for message_id, observers in message_engines.items():
            missing = engines_present_but_missing(
                observers, references.get(message_id), windows, all_engines
            )
            if is_divergent_message(observers, observers | missing):
                divergent += 1
        counts[group_id] = divergent
    return counts


def event_message_id_values(
    msg_id,
    outbound_msg_id,
    invalidated_msg_id,
    outbound_welcome_msg_ids,
    human_action_message_ids,
):
    ids = []
    for value in (msg_id, outbound_msg_id, invalidated_msg_id):
        if value:
            ids.append(value)
    ids.extend(outbound_welcome_msg_ids or [])
    ids.extend(human_action_message_ids or [])
    return ids


# ---------------------------------------------------------------------------
# Message traces
# ---------------------------------------------------------------------------


def message_traces_for_group(group, events=None):
    if events is None:
        events = list(valid_events_for_group(group))
    all_engines = {event.engine_id for event in events if event.engine_id}
    return message_traces_from_events(events, all_engines)


def message_traces_from_events(events, all_engines):
    all_engines = set(all_engines)
    windows = engine_windows(events)
    by_msg = defaultdict(list)
    for event in events:
        for msg_id in event_message_ids(event):
            by_msg[msg_id].append(event)

    traces = []
    for msg_id, msg_events in sorted(by_msg.items()):
        observers = {event.engine_id for event in msg_events if event.engine_id}
        event_types = sorted({event.event_type for event in msg_events if event.event_type})
        states = sorted(
            {
                value
                for event in msg_events
                for value in (event.new_state, event.outcome, event.outcome_kind, event.reason)
                if value
            }
        )
        wall_times = [event.wall_time_ms for event in msg_events if event.wall_time_ms is not None]
        reference_ms = min(wall_times) if wall_times else None
        missed_by = engines_present_but_missing(observers, reference_ms, windows, all_engines)
        traces.append(
            {
                "msg_id": msg_id,
                "engines": sorted(observers),
                # Engines with no record of the message, split into a real break
                # (``missed_by``: active in-window when it appeared) and a benign
                # gap (``absent_engines``: joined later / their log ended earlier).
                # ``missing_engines`` keeps the old observers-complement union for
                # back-compatible consumers such as the agent-state export.
                "missing_engines": sorted(all_engines - observers),
                "missed_by": sorted(missed_by),
                "absent_engines": sorted(all_engines - observers - missed_by),
                "reference_ms": reference_ms,
                "is_divergent": is_divergent_message(observers, observers | missed_by),
                "event_types": event_types,
                "states": states,
                "first_wall_time_ms": reference_ms,
                "last_wall_time_ms": max(wall_times) if wall_times else None,
                "event_count": len(msg_events),
            }
        )
    return traces


def source_label_for_file(audit_file: AuditFile) -> str:
    parts = [
        audit_file.source_account_label,
        audit_file.source_device_label,
        audit_file.source_platform,
    ]
    return " / ".join(part for part in parts if part)


def missing_observations_for_group(group, traces=None):
    if traces is None:
        traces = message_traces_for_group(group)
    return [trace for trace in traces if trace_is_divergent(trace)]


def trace_is_divergent(trace):
    """Whether a message trace is a real, membership-aware divergence.

    ``message_traces_from_events`` already applies the shared predicate
    (``is_divergent_message`` over each message's in-scope engine set —
    observers plus present-but-missing engines) and stores the result, so the
    detail path and the persisted landing-page aggregation stay in lockstep.
    """
    return trace["is_divergent"]


def message_observation_matrix(events):
    """Per-message × per-engine observation grid for the Messages tab.

    Rows are messages; columns are the group's engines in timeline order. Each
    cell states what that engine did with the message:

      - ``observed``: the engine logged at least one event for it
      - ``missed``:   the engine was active when the message appeared but logged
                      nothing for it (a real break — see ``is_divergent_message``)
      - ``absent``:   the engine was not active in that window (benign — a late
                      joiner or a log that ended earlier)

    This is the "what did each engine see" view the union-merged trace table
    could not express. Divergence here uses the same shared predicate as the
    landing-page count, so the matrix and the badge agree.
    """
    engines, _engine_idx = timeline_engines(events)
    for engine in engines:
        # Compact column header: the human account name (first label segment)
        # falls back to the short engine id. The full label stays available for
        # the column's title tooltip in the template.
        label = engine.get("label") or ""
        engine["display_name"] = label.split(" / ")[0] if label else engine["short"]
    all_engines = {engine["engine_id"] for engine in engines}
    windows = engine_windows(events)

    by_msg = defaultdict(list)
    for event in events:
        for msg_id in event_message_ids(event):
            by_msg[msg_id].append(event)

    rows = []
    for msg_id, msg_events in sorted(by_msg.items()):
        observers = {event.engine_id for event in msg_events if event.engine_id}
        wall_times = [event.wall_time_ms for event in msg_events if event.wall_time_ms is not None]
        reference_ms = min(wall_times) if wall_times else None
        missed_by = engines_present_but_missing(observers, reference_ms, windows, all_engines)

        detail_by_engine = defaultdict(lambda: {"event_types": set(), "states": set()})
        for event in msg_events:
            if not event.engine_id:
                continue
            detail = detail_by_engine[event.engine_id]
            if event.event_type:
                detail["event_types"].add(event.event_type)
            for value in (event.new_state, event.outcome, event.outcome_kind, event.reason):
                if value:
                    detail["states"].add(value)

        cells = []
        for engine in engines:
            engine_id = engine["engine_id"]
            if engine_id in observers:
                detail = detail_by_engine[engine_id]
                cells.append(
                    {
                        "status": "observed",
                        "event_types": sorted(detail["event_types"]),
                        "states": sorted(detail["states"]),
                    }
                )
            elif engine_id in missed_by:
                cells.append({"status": "missed", "event_types": [], "states": []})
            else:
                cells.append({"status": "absent", "event_types": [], "states": []})

        rows.append(
            {
                "msg_id": msg_id,
                "reference_ms": reference_ms,
                "first_wall_time_ms": reference_ms,
                "last_wall_time_ms": max(wall_times) if wall_times else None,
                "event_count": len(msg_events),
                "observers": sorted(observers),
                "missed_by": sorted(missed_by),
                "is_divergent": is_divergent_message(observers, observers | missed_by),
                "cells": cells,
            }
        )
    return {"engines": engines, "rows": rows}


def fork_and_convergence_events(group, events=None):
    if events is None:
        events = valid_events_for_group(group).filter(event_type__in=FORK_EVENT_TYPES)
        return [event_row(event) for event in events]
    return [event_row(event) for event in events if event.event_type in FORK_EVENT_TYPES]


def peeler_and_rejection_events(group, events=None):
    if events is None:
        events = list(valid_events_for_group(group).filter(event_type__in=PEELER_EVENT_TYPES))
    rows = []
    for event in events:
        if event.event_type == "peeler_outcome" and (
            event.outcome != "success" or event.fallback_snapshot_used
        ):
            rows.append(event_row(event))
        elif event.event_type == "rejection":
            rows.append(event_row(event))
        elif (
            event.event_type == "message_state_changed"
            and event.new_state in ATTENTION_MESSAGE_STATES
        ):
            rows.append(event_row(event))
    return rows


def human_action_groups_for_group(events):
    sequence = count()
    groups = {}
    for event in events:
        if not event.human_action_action:
            continue
        # Only merge events that share a real operation_id. Events with no
        # operation_id must NOT collapse onto action type (goggles#30) — that
        # would union every same-type human action across the group's history
        # into one card. Fall back to a per-event unique key so each
        # operation_id-less action becomes its own group.
        #
        # Keep real operation_ids and synthetic per-event keys in DISJOINT
        # namespaces via tuple keys. Ingest accepts arbitrary string operation
        # IDs, so a flat string fallback like f"event:{pk}" can collide with a
        # real operation_id of the literal form "event:<pk>", re-merging
        # unrelated actions. Tuple discriminators ("op", ...) vs ("event", ...)
        # cannot collide regardless of operation_id contents.
        if event.context_operation_id:
            key = ("op", event.context_operation_id)
        else:
            key = ("event", event.pk)
        if key not in groups:
            groups[key] = {
                "order": next(sequence),
                "key": key,
                "operation_id": event.context_operation_id,
                "action": event.human_action_action,
                "action_label": action_label(event.human_action_action),
                "origin": event.human_action_origin,
                "phase": event.human_action_phase,
                "fields": event.human_action_fields or [],
                "component_ids": event.human_action_component_ids or [],
                "target_count": event.human_action_target_count,
                "from_epoch": event.from_epoch,
                "to_epoch": event.to_epoch,
                "message_ids": [],
                "events": [],
                "relay_rows": [],
                "first_wall_time_ms": event.wall_time_ms,
                "last_wall_time_ms": event.wall_time_ms,
            }
        group = groups[key]
        group["origin"] = group["origin"] or event.human_action_origin
        group["phase"] = group["phase"] or event.human_action_phase
        group["fields"] = sorted(set(group["fields"]) | set(event.human_action_fields or []))
        group["component_ids"] = sorted(
            set(group["component_ids"]) | set(event.human_action_component_ids or [])
        )
        # Nullable integer: a real 0 must survive. ``X or Y`` would drop a
        # genuine target_count of 0 (or overwrite it with a later positive
        # value), so preserve the existing group value unless it is None.
        group["target_count"] = first_present(
            group["target_count"], event.human_action_target_count
        )
        group["from_epoch"] = (
            group["from_epoch"] if group["from_epoch"] is not None else event.from_epoch
        )
        group["to_epoch"] = group["to_epoch"] if group["to_epoch"] is not None else event.to_epoch
        group["message_ids"] = sorted(set(group["message_ids"]) | set(event_message_ids(event)))
        if event.wall_time_ms is not None:
            if group["first_wall_time_ms"] is None:
                group["first_wall_time_ms"] = event.wall_time_ms
            group["last_wall_time_ms"] = max(
                group["last_wall_time_ms"] or event.wall_time_ms,
                event.wall_time_ms,
            )
        row = event_row(event)
        group["events"].append(row)
        if row["relay_summary"]:
            group["relay_rows"].append(row)
    return sorted(
        groups.values(),
        key=lambda group: (
            group["first_wall_time_ms"] is None,
            group["first_wall_time_ms"] or 0,
            group["order"],
        ),
    )


def event_row(event: AuditEvent):
    return {
        "id": event.id,
        "line_number": event.line_number,
        "parse_status": event.parse_status,
        "validation_error": event.validation_error,
        "engine_id": event.engine_id,
        "account_ref": event.account_ref,
        "event_type": event.event_type,
        "wall_time_ms": event.wall_time_ms,
        "seq": event.seq,
        "group_ref": event.group_ref,
        "operation_id": event.context_operation_id,
        "human_action": event.human_action_action,
        "human_action_label": action_label(event.human_action_action),
        "human_action_origin": event.human_action_origin,
        "human_action_phase": event.human_action_phase,
        "human_action_fields": event.human_action_fields,
        "human_action_component_ids": event.human_action_component_ids,
        "human_action_target_count": event.human_action_target_count,
        "msg_id": primary_msg_id(event),
        "message_ids": event_message_ids(event),
        "epoch": event_epoch(event),
        "digest": primary_digest(event),
        "target_kind": event.target_kind,
        "relay_summary": relay_summary(event),
        "outcome": primary_outcome(event),
        "reason": primary_reason(event),
        "summary": event_summary(event),
    }


def event_summary(event: AuditEvent) -> str:
    if event.event_type == "human_action":
        label = action_label(event.human_action_action)
        suffix = secondary_action_label(event)
        return f"{label}{f' · {suffix}' if suffix else ''}"
    if event.event_type == "publish_attempt":
        relay_count = len(event.relay_urls or [])
        return f"publish attempt · {relay_count} relay{'' if relay_count == 1 else 's'}"
    if event.event_type == "publish_outcome":
        accepted = len(event.accepted_relay_urls or [])
        failed = len(event.failed_relays or [])
        return f"publish outcome · {accepted} accepted / {failed} failed"
    if event.event_type == "publish_failure":
        return f"publish failure{f' · {event.reason}' if event.reason else ''}"
    if event.human_action_action:
        label = action_label(event.human_action_action)
        return f"{event.event_type} · {label}"
    if event.event_type == "fork_resolution":
        return f"{event.winner} at source epoch {event.source_epoch}"
    if event.event_type == "convergence_decision":
        return f"tip {event.current_tip_epoch} -> {int_or_dash(event.selected_tip_epoch)}"
    if event.event_type == "epoch_confirmed":
        return f"epoch {event.from_epoch} -> {event.to_epoch}"
    if event.event_type == "epoch_rolled_back":
        return f"rollback {event.pending_epoch} -> {event.restored_epoch}"
    if event.event_type == "peeler_outcome":
        fallback = " with snapshot fallback" if event.fallback_snapshot_used else ""
        return f"{event.outcome}{fallback}"
    if event.event_type == "message_state_changed":
        return f"{event.msg_id} -> {event.new_state}"
    if event.event_type == "ingest_outcome":
        return f"{event.outcome_kind} epoch {int_or_dash(event.epoch)}"
    if event.event_type == "send_outcome":
        return f"{event.intent_kind} -> {event.result_kind}"
    return event.event_type


def event_tone(event: AuditEvent) -> str:
    if event.event_type == "human_action":
        return "send" if event.human_action_origin == "local_user" else "receive"
    if event.event_type == "publish_failure":
        return "error"
    if event.event_type == "publish_outcome" and event.failed_relays:
        return "error" if not event.met_required_acks else "send"
    tone = "send" if event.event_type.startswith("send_") else "receive"
    if event.event_type in {"fork_resolution", "convergence_decision"}:
        tone = "fork"
    if event.event_type == "peeler_outcome":
        if event.outcome in PEELER_WARNING_OUTCOMES:
            return "warning"
        if event.outcome and event.outcome != "success":
            return "error"
    if event.event_type == "rejection":
        tone = "error"
    if event.event_type == "message_state_changed":
        if event.new_state in FAILED_MESSAGE_STATES:
            tone = "error"
        elif event.new_state in DEFERRED_MESSAGE_STATES:
            tone = "warning"
    return tone


def first_present(*values):
    """First value that is not ``None``.

    Unlike an ``X or Y`` chain, this preserves falsy-but-real integers such as
    epoch ``0`` or ``seq`` ``0``. Stored integer fields are nullable, so ``None``
    (not falsiness) is the only sentinel for "absent".
    """
    for value in values:
        if value is not None:
            return value
    return None


def int_or_dash(value, dash: str = "-"):
    """Render an integer field, preserving a real ``0``.

    ``value or dash`` would collapse epoch/seq ``0`` to the dash; ``None`` is the
    only "absent" sentinel for these nullable integer columns.
    """
    return dash if value is None else value


def event_epoch(event: AuditEvent):
    return first_present(
        event.epoch,
        event.source_epoch,
        event.to_epoch,
        event.pending_epoch,
        event.current_tip_epoch,
        event.selected_tip_epoch,
    )


def primary_msg_id(event: AuditEvent):
    """First present message id for an event, used as its display/correlation key.

    Falls back through both ``invalidated_msg_id`` (fork resolutions) and the
    first ``human_action_message_ids`` entry (human actions). These two tail
    sources are populated by mutually exclusive event types, so the combined
    chain matches what ``event_row`` (invalidated) and ``timeline_items``
    (human_action) each derived before they were unified.
    """
    return (
        event.msg_id
        or event.outbound_msg_id
        or event.invalidated_msg_id
        or (event.human_action_message_ids or [None])[0]
    )


def primary_digest(event: AuditEvent):
    """First present digest for an event (candidate, then payload, then incumbent)."""
    return event.candidate_digest or event.payload_digest or event.incumbent_digest


def primary_outcome(event: AuditEvent):
    """First present outcome-like field for an event."""
    return event.outcome or event.outcome_kind or event.decision or event.winner or event.new_state


def primary_reason(event: AuditEvent):
    """First present reason-like field for an event."""
    return event.reason or event.stale_reason or event.detail or event.pending_kind


def event_message_ids(event: AuditEvent):
    return event_message_id_values(
        event.msg_id,
        event.outbound_msg_id,
        event.invalidated_msg_id,
        event.outbound_welcome_msg_ids,
        event.human_action_message_ids,
    )


def action_label(value: str) -> str:
    return value.replace("_", " ").strip().title() if value else ""


def secondary_action_label(event: AuditEvent) -> str:
    parts = []
    if event.human_action_origin:
        parts.append(event.human_action_origin)
    if event.human_action_phase:
        parts.append(event.human_action_phase)
    if event.human_action_fields:
        parts.append(", ".join(event.human_action_fields))
    if event.from_epoch is not None or event.to_epoch is not None:
        parts.append(f"epoch {int_or_dash(event.from_epoch)} -> {int_or_dash(event.to_epoch)}")
    return " · ".join(parts)


def relay_summary(event: AuditEvent) -> str:
    if event.event_type == "publish_attempt":
        relay_count = len(event.relay_urls or [])
        if not relay_count:
            return ""
        return f"{relay_count} target relay{'' if relay_count == 1 else 's'}"
    if event.event_type == "publish_outcome":
        accepted = len(event.accepted_relay_urls or [])
        failed = len(event.failed_relays or [])
        required = f" / {event.required_acks} required" if event.required_acks is not None else ""
        return f"{accepted} accepted, {failed} failed{required}"
    if event.event_type == "publish_failure":
        relays = event.relay_urls or []
        if relays:
            return f"failed on {len(relays)} relay{'' if len(relays) == 1 else 's'}"
        return event.reason or event.detail
    return ""


def message_ids_from_events(events):
    ids = set()
    for event in events:
        ids.update(event_message_ids(event))
    return ids


# ---------------------------------------------------------------------------
# Legacy epoch timeline payload
# ---------------------------------------------------------------------------
#
# Server-side semantic payload retained for regression tests and agent exports.
# The group workspace no longer serves the all-events timeline as a primary UI,
# but these helpers still encode useful ordering/integrity semantics:
#   - engines[]: column order, labels, deterministic viz color
#   - epochs[]:  per-epoch confirmations (commit node = first timed confirm,
#                the rest are "applied" ticks), fork/rollback/snapshot detail
#                for the rail, stub entries for referenced-but-unconfirmed
#                epochs (confirmed: false)
#   - items[]:   every placed event, sorted (t, line, id); engine refs are
#                indexes into engines[]; empty fields omitted
# Timestamps are per-device wall clocks (time.basis); the client must not
# assume cross-engine monotonicity. Epoch numbers are real and may be sparse.


def timeline_payload_for_group(group, events, audit_files, traces=None, *, include_integrity=True):
    """Build a timeline payload.

    ``traces`` is only consumed when ``include_integrity`` is true. Callers that
    set ``include_integrity=False`` are opting out of integrity construction and
    any trace work because they will supply integrity separately.
    """
    ordered = sorted_timeline_events(events)
    engines, engine_idx = timeline_engines(ordered)
    epochs, roles = timeline_epochs(ordered, engine_idx, len(engines))
    items, excluded = timeline_items(ordered, engine_idx, roles)
    placed = [item["t"] for item in items]
    payload = {
        "version": 1,
        "group": {"name": group.name, "slug": group.slug, "group_ref": group.group_ref},
        "time": {
            "start_ms": min(placed) if placed else None,
            "end_ms": max(placed) if placed else None,
            "basis": "per_device_wall_clock",
        },
        "engines": engines,
        "epochs": epochs,
        "items": items,
        "excluded": excluded,
    }
    if include_integrity:
        if traces is None:
            traces = message_traces_from_events(
                ordered, {engine["engine_id"] for engine in engines}
            )
        payload["integrity"] = group_integrity_summary(group, events=ordered, traces=traces)
    return payload


def agent_state_export_for_group(group, events, audit_files):
    ordered = sorted_timeline_events(events)
    timeline = timeline_payload_for_group(group, ordered, audit_files)
    engine_ids = {engine["engine_id"] for engine in timeline["engines"]}
    return {
        "schema_version": AGENT_EXPORT_SCHEMA_VERSION,
        "generated_at": timezone.now().isoformat(),
        "sensitivity": EXPORT_SENSITIVITY,
        "group": timeline["group"],
        "summary": group_summary(group, audit_files, events=ordered),
        "sources": [agent_source_row(audit_file) for audit_file in audit_files],
        "timeline": timeline,
        "actions": human_action_groups_for_group(ordered),
        "messages": message_traces_from_events(ordered, engine_ids),
        "events": [agent_event_row(event) for event in ordered],
    }


def agent_source_row(audit_file):
    return {
        "id": audit_file.id,
        "source_name": audit_file.source_name or f"audit-file-{audit_file.id}",
        "source_label": source_label_for_file(audit_file),
        "source_account_label": audit_file.source_account_label,
        "source_device_label": audit_file.source_device_label,
        "source_platform": audit_file.source_platform,
        "source_app_version": audit_file.source_app_version,
        "validation_status": audit_file.validation_status,
        "validation_error": audit_file.validation_error,
        "total_line_count": audit_file.total_line_count,
        "valid_event_count": audit_file.valid_event_count,
        "invalid_event_count": audit_file.invalid_event_count,
        "duplicate_event_count": audit_file.duplicate_event_count,
        # Annotated in SQL by audit_files_for_group (goggles#65); see
        # file_rows_for_group for the rationale.
        "group_event_count": audit_file.group_event_count,
        "first_seq": audit_file.first_seq,
        "last_seq": audit_file.last_seq,
        "first_wall_time_ms": audit_file.first_wall_time_ms,
        "last_wall_time_ms": audit_file.last_wall_time_ms,
        "account_refs": audit_file.account_refs,
        "engine_ids": audit_file.engine_ids,
        "group_refs": audit_file.group_refs,
        "schema_versions": audit_file.schema_versions,
        "created_at": audit_file.created_at.isoformat(),
    }


def agent_event_row(event):
    normalized = {}
    for field in AGENT_EXPORT_NORMALIZED_FIELDS:
        value = getattr(event, field)
        if value in (None, "", [], {}):
            continue
        normalized[field] = value
    return {
        "id": event.id,
        "source": {
            "file_id": event.audit_file_id,
            "line_number": event.line_number,
            "line_hash": event.line_hash,
        },
        "schema_version": event.schema_version,
        "seq": event.seq,
        "wall_time_ms": event.wall_time_ms,
        "account_ref": event.account_ref,
        "engine_id": event.engine_id,
        "group_ref": event.group_ref,
        "event_type": event.event_type,
        "context": event.raw_context or {},
        "kind": event.raw_kind or {},
        "normalized": normalized,
    }


def group_integrity_summary(group, events=None, traces=None):
    if events is None:
        events = list(valid_events_for_group(group))
    if traces is None:
        traces = message_traces_for_group(group, events=events)
    missing = missing_observations_for_group(group, traces=traces)
    fork_count = sum(1 for event in events if event.event_type == "fork_resolution")
    rollback_count = sum(1 for event in events if event.event_type == "epoch_rolled_back")
    return {
        "divergent_message_count": len(missing),
        "divergent_msg_ids": [trace["msg_id"] for trace in missing],
        "fork_resolution_count": fork_count,
        "rollback_count": rollback_count,
        "has_fork_activity": bool(fork_count or rollback_count),
    }


def sorted_timeline_events(events):
    # Python sort, DB-agnostic: SQLite orders NULL wall times first, Postgres
    # last. None-timestamp events sort last and are excluded by timeline_items.
    return sorted(
        events,
        key=lambda event: (
            event.wall_time_ms is None,
            event.wall_time_ms or 0,
            event.line_number,
            event.id,
        ),
    )


def color_index(value: str) -> int:
    # Same 31-multiplier hash as the design system's Avatar palette, applied
    # to the engine id so the color survives label edits and reordering.
    # 1-based to match the --viz-1..8 token names.
    h = 0
    for char in value or "":
        h = (h * 31 + ord(char)) & 0xFFFFFFFF
    return h % VIZ_PALETTE_SIZE + 1


def engine_initials(label: str, engine_id: str) -> str:
    primary = label.split(" / ")[0].strip() if label else ""
    words = primary.split()
    if words:
        return "".join(word[0] for word in words[:2]).upper()
    return (engine_id[:2] or "?").upper()


def timeline_engines(events):
    by_engine: dict[str, dict] = {}
    file_ids: dict[str, set] = defaultdict(set)
    for event in events:
        engine_id = event.engine_id
        if not engine_id:
            continue
        info = by_engine.setdefault(
            engine_id,
            {
                "engine_id": engine_id,
                "account_ref": event.account_ref or "",
                "label": "",
                "color_index": color_index(engine_id),
                "first_event_ms": None,
                "last_event_ms": None,
                "event_count": 0,
            },
        )
        info["event_count"] += 1
        if not info["account_ref"] and event.account_ref:
            info["account_ref"] = event.account_ref
        if event.wall_time_ms is not None:
            if info["first_event_ms"] is None:
                info["first_event_ms"] = event.wall_time_ms
            info["last_event_ms"] = max(
                info["last_event_ms"] or event.wall_time_ms, event.wall_time_ms
            )
        label = source_label_for_file(event.audit_file)
        if label:
            info["label"] = label
        file_ids[engine_id].add(event.audit_file_id)

    engines = sorted(
        by_engine.values(),
        key=lambda info: (
            info["first_event_ms"] is None,
            info["first_event_ms"] or 0,
            info["engine_id"],
        ),
    )
    for idx, info in enumerate(engines):
        info["idx"] = idx
        info["short"] = info["engine_id"][:8]
        info["initials"] = engine_initials(info["label"], info["engine_id"])
        info["file_ids"] = sorted(file_ids[info["engine_id"]])
    engine_idx = {info["engine_id"]: info["idx"] for info in engines}
    return engines, engine_idx


def timeline_epochs(events, engine_idx, engine_count):
    confirmations = defaultdict(list)
    direct_initiators = defaultdict(list)
    message_epochs = defaultdict(set)
    forks = defaultdict(list)
    convergences = defaultdict(list)
    rollbacks = defaultdict(list)
    snapshots = defaultdict(list)
    referenced = set()
    message_counts = Counter()
    roles = {}

    for event in events:
        epoch = event_epoch(event)
        if epoch is not None:
            for msg_id in event_message_ids(event):
                message_epochs[msg_id].add(epoch)

    for event in events:
        engine = engine_idx.get(event.engine_id)
        for epoch, initiator in epoch_initiators_for_event(event, engine, message_epochs):
            direct_initiators[epoch].append(initiator)
        if event.event_type == "epoch_confirmed" and event.to_epoch is not None:
            confirmations[event.to_epoch].append(
                {
                    "engine": engine,
                    "t": event.wall_time_ms,
                    "from_epoch": event.from_epoch,
                    "pending_kind": event.pending_kind or "",
                    "human_action": event.human_action_action or "",
                    "human_action_origin": event.human_action_origin or "",
                    "human_action_phase": event.human_action_phase or "",
                    "item_id": event.id,
                }
            )
        elif event.event_type == "fork_resolution" and event.source_epoch is not None:
            referenced.add(event.source_epoch)
            forks[event.source_epoch].append(
                {
                    "item_id": event.id,
                    "engine": engine,
                    "t": event.wall_time_ms,
                    "winner": event.winner or "",
                    "candidate_digest": event.candidate_digest or "",
                    "incumbent_digest": event.incumbent_digest or "",
                    "invalidated_msg_id": event.invalidated_msg_id or "",
                }
            )
        elif event.event_type == "convergence_decision":
            anchor = event.current_tip_epoch
            for ref in (event.current_tip_epoch, event.selected_tip_epoch):
                if ref is not None:
                    referenced.add(ref)
            if anchor is not None:
                convergences[anchor].append(
                    {
                        "item_id": event.id,
                        "engine": engine,
                        "t": event.wall_time_ms,
                        "current_tip_epoch": event.current_tip_epoch,
                        "selected_tip_epoch": event.selected_tip_epoch,
                        "selected_fork_epoch": event.selected_fork_epoch,
                        "selected_branch_id": event.selected_branch_id or "",
                        "candidate_count": event.candidate_count,
                        "eligible_count": event.eligible_count,
                        "max_rewind_commits": event.max_rewind_commits,
                    }
                )
        elif event.event_type == "epoch_rolled_back":
            roles[event.id] = "rollback"
            entry = {
                "item_id": event.id,
                "engine": engine,
                "t": event.wall_time_ms,
                "pending_epoch": event.pending_epoch,
                "restored_epoch": event.restored_epoch,
                "pending_kind": event.pending_kind or "",
            }
            if event.pending_epoch is not None:
                referenced.add(event.pending_epoch)
                rollbacks[event.pending_epoch].append({**entry, "role": "abandoned"})
            if event.restored_epoch is not None:
                referenced.add(event.restored_epoch)
                rollbacks[event.restored_epoch].append({**entry, "role": "restored_to"})
        elif event.event_type == "snapshot_created" and event.source_epoch is not None:
            referenced.add(event.source_epoch)
            snapshots[event.source_epoch].append(
                {
                    "item_id": event.id,
                    "engine": engine,
                    "t": event.wall_time_ms,
                    "snapshot_name": event.snapshot_name or "",
                    "reason": event.reason or "",
                }
            )
        if event.event_type in MESSAGE_EVENT_TYPES:
            epoch = event_epoch(event)
            if epoch is not None:
                message_counts[epoch] += 1

    epochs = []
    for number in sorted(set(confirmations) | referenced | set(direct_initiators)):
        confs = sorted(
            confirmations.get(number, []),
            key=lambda conf: (conf["t"] is None, conf["t"] or 0, conf["item_id"]),
        )
        initiators = sorted(
            dedupe_epoch_initiators(direct_initiators.get(number, [])),
            key=lambda item: (item["t"] is None, item["t"] or 0, item["item_id"]),
        )
        seen_engines = set()
        for conf in confs:
            conf["repeat"] = conf["engine"] in seen_engines
            if conf["engine"] is not None:
                seen_engines.add(conf["engine"])
        initiator_engines = {
            initiator["engine"] for initiator in initiators if initiator["engine"] is not None
        }
        timed = [conf for conf in confs if conf["t"] is not None]
        first = timed[0] if timed else None
        for conf in confs:
            roles[conf["item_id"]] = (
                "commit" if first and conf["item_id"] == first["item_id"] else "applied"
            )
        suspected = any(
            rollback["role"] == "abandoned" for rollback in rollbacks.get(number, [])
        ) or any((conv["candidate_count"] or 0) > 1 for conv in convergences.get(number, []))
        if forks.get(number):
            fork_status = "resolved"
        elif suspected:
            fork_status = "suspected"
        else:
            fork_status = "none"
        epochs.append(
            {
                "epoch": number,
                "confirmed": bool(confs),
                "first_confirmed_ms": first["t"] if first else None,
                "first_confirmed_engine": first["engine"] if first else None,
                "commit_item_id": first["item_id"] if first else None,
                "initiators": initiators,
                "initiator_engines": sorted(initiator_engines),
                "confirmations": confs,
                "unconfirmed_engines": sorted(
                    set(range(engine_count)) - seen_engines - initiator_engines
                )
                if confs
                else sorted(range(engine_count)),
                "spread_ms": (timed[-1]["t"] - timed[0]["t"]) if len(timed) > 1 else None,
                "fork_status": fork_status,
                "forks": forks.get(number, []),
                "convergences": convergences.get(number, []),
                "rollbacks": rollbacks.get(number, []),
                "snapshots": snapshots.get(number, []),
                "message_event_count": message_counts.get(number, 0),
            }
        )
    return epochs, roles


def epoch_initiators_for_event(event, engine, message_epochs):
    if engine is None or event.human_action_origin != "local_user":
        return []

    initiator = {
        "engine": engine,
        "t": event.wall_time_ms,
        "action": event.human_action_action or "",
        "phase": event.human_action_phase or "",
        "result_kind": event.result_kind or "",
        "pending_kind": event.pending_kind or "",
        "item_id": event.id,
        "source": event.event_type,
    }

    if event.to_epoch is not None:
        return [(event.to_epoch, initiator)]

    if event.event_type == "send_outcome" and event.result_kind in EPOCH_CHANGE_RESULT_KINDS:
        epochs = set()
        for msg_id in event_message_ids(event):
            epochs.update(message_epochs.get(msg_id, set()))
        return [(epoch, initiator) for epoch in sorted(epochs)]

    return []


def dedupe_epoch_initiators(initiators):
    by_key = {}
    for item in initiators:
        key = (item["engine"], item["item_id"], item["source"])
        by_key.setdefault(key, item)
    return list(by_key.values())


def timeline_items(events, engine_idx, roles):
    items = []
    excluded_ids = []
    by_reason = {"no_wall_time": 0, "no_engine": 0}
    peeler_bursts = defaultdict(list)
    for event in events:
        engine = engine_idx.get(event.engine_id)
        if event.wall_time_ms is None:
            by_reason["no_wall_time"] += 1
            excluded_ids.append(event.id)
            continue
        if engine is None:
            by_reason["no_engine"] += 1
            excluded_ids.append(event.id)
            continue
        if is_timeline_peeler_retry_event(event):
            peeler_bursts[(engine, event.wall_time_ms // 1000)].append(event)
            continue
        items.append(timeline_item_for_event(event, engine, roles))
    for (engine, _second), burst_events in peeler_bursts.items():
        if len(burst_events) == 1:
            event = burst_events[0]
            items.append(timeline_item_for_event(event, engine_idx[event.engine_id], roles))
        else:
            items.append(timeline_peeler_retry_burst_item(burst_events, engine))
    items.sort(key=timeline_item_sort_key)
    excluded = {
        "count": len(excluded_ids),
        "by_reason": by_reason,
        "event_ids": excluded_ids,
    }
    return items, excluded


def timeline_item_for_event(event, engine, roles):
    item = {
        "id": event.id,
        "engine": engine,
        "t": event.wall_time_ms,
        "seq": event.seq,
        "type": event.event_type,
        "tone": event_tone(event),
        "role": roles.get(event.id),
        "epoch": event_epoch(event),
        "msg_id": primary_msg_id(event),
        "message_ids": event_message_ids(event),
        "related_key": (
            event.msg_id
            or event.outbound_msg_id
            or (event.human_action_message_ids or [None])[0]
            or event.candidate_digest
            or event.payload_digest
        ),
        "operation_id": event.context_operation_id,
        "human_action": event.human_action_action,
        "human_action_label": action_label(event.human_action_action),
        "human_action_origin": event.human_action_origin,
        "human_action_phase": event.human_action_phase,
        "human_action_fields": event.human_action_fields,
        "target_kind": event.target_kind,
        "relay_summary": relay_summary(event),
        "envelope_kind": event.envelope_kind,
        "intent_kind": event.intent_kind,
        "result_kind": event.result_kind,
        "proposal_kind": event.proposal_kind,
        "snapshot_name": event.snapshot_name,
        "payload_len": event.payload_len,
        "digest": primary_digest(event),
        "outcome": primary_outcome(event),
        "reason": primary_reason(event),
        "summary": event_summary(event),
        "line": event.line_number,
        "file_id": event.audit_file_id,
    }
    return compact_item(item)


def is_timeline_peeler_retry_event(event: AuditEvent) -> bool:
    return (event.event_type == "peeler_outcome" and event.outcome in PEELER_WARNING_OUTCOMES) or (
        event.event_type == "message_state_changed" and event.new_state in DEFERRED_MESSAGE_STATES
    )


def timeline_peeler_retry_burst_item(events, engine):
    ordered = sorted(
        events,
        key=lambda event: (
            event.wall_time_ms or 0,
            event.line_number,
            event.id,
        ),
    )
    first = ordered[0]
    message_ids = unique_in_order(
        msg_id for event in ordered for msg_id in event_message_ids(event)
    )
    outcomes = [primary_outcome(event) for event in ordered if primary_outcome(event)]
    reasons = [primary_reason(event) for event in ordered if primary_reason(event)]
    message_count = len(message_ids)
    event_count = len(ordered)
    message_word = "" if message_count == 1 else "s"
    event_word = "" if event_count == 1 else "s"
    item = {
        "id": min(event.id for event in ordered),
        "engine": engine,
        "t": first.wall_time_ms,
        "seq": first.seq,
        "type": "peeler_retry_burst",
        "tone": "warning",
        "msg_id": message_ids[0] if message_count == 1 else "",
        "message_ids": message_ids,
        "message_count": message_count,
        "event_count": event_count,
        "source_event_ids": [event.id for event in ordered],
        "outcome": "deferred",
        "outcome_summary": summarize_counts(outcomes),
        "reason": summarize_counts(reasons),
        "summary": (
            f"peeler retry/defer burst · {message_count} message{message_word} · "
            f"{event_count} event{event_word}"
        ),
        "line": min(event.line_number for event in ordered),
        "file_id": first.audit_file_id,
    }
    if message_count == 1:
        item["related_key"] = message_ids[0]
    return compact_item(item)


def unique_in_order(values):
    seen = set()
    result = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def summarize_counts(values, limit: int = 3) -> str:
    counts = Counter(value for value in values if value)
    parts = [
        f"{value} x{count}" if count > 1 else value for value, count in counts.most_common(limit)
    ]
    extra = len(counts) - limit
    if extra > 0:
        parts.append(f"+{extra} more")
    return ", ".join(parts)


def compact_item(item):
    return {key: value for key, value in item.items() if value is not None and value != ""}


def timeline_item_sort_key(item):
    return (
        item["t"],
        item.get("line", 0),
        item["id"],
    )
