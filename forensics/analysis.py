from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime
from itertools import count

from django.db.models import Count, Exists, Max, Min, OuterRef, Q

from .models import AuditEvent, AuditFile, AuditGroup

FORK_EVENT_TYPES = (
    "fork_resolution",
    "convergence_decision",
    "epoch_confirmed",
    "epoch_rolled_back",
)

PEELER_EVENT_TYPES = ("peeler_outcome", "rejection", "message_state_changed")

FAILED_MESSAGE_STATES = {"failed", "epoch_invalidated", "peel_deferred"}

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

VIZ_PALETTE_SIZE = 8
GROUP_REF_FULL_DISPLAY_MAX = 80
GROUP_REF_EDGE_DISPLAY_CHARS = 32


def audit_files_for_group(group):
    return (
        AuditFile.objects.filter(events__group=group)
        .prefetch_related("events__group")
        .distinct()
        .order_by("-created_at", "-id")
    )


def valid_events_for_group(group):
    return (
        AuditEvent.objects.filter(
            group=group,
            audit_file__validation_status=AuditFile.STATUS_VALID,
            parse_status=AuditEvent.STATUS_VALID,
        )
        .select_related("audit_file")
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
            "group_event_count": audit_file.events.filter(group=group).count(),
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


def annotated_group_list():
    valid = Q(
        audit_events__parse_status=AuditEvent.STATUS_VALID,
        audit_events__audit_file__validation_status=AuditFile.STATUS_VALID,
    )
    confirmed = valid & Q(audit_events__event_type="epoch_confirmed")
    fork_activity = AuditEvent.objects.filter(
        group=OuterRef("pk"),
        parse_status=AuditEvent.STATUS_VALID,
        audit_file__validation_status=AuditFile.STATUS_VALID,
        event_type__in=["fork_resolution", "epoch_rolled_back"],
    )
    return AuditGroup.objects.annotate(
        audit_file_count=Count("audit_events__audit_file", distinct=True),
        event_count=Count("audit_events", filter=valid, distinct=True),
        engine_count=Count(
            "audit_events__engine_id",
            filter=valid & ~Q(audit_events__engine_id=""),
            distinct=True,
        ),
        epoch_min=Min("audit_events__from_epoch", filter=confirmed),
        epoch_max=Max("audit_events__to_epoch", filter=confirmed),
        last_activity_ms=Max("audit_events__wall_time_ms", filter=valid),
        has_fork_activity=Exists(fork_activity),
    )


def group_list_rows():
    groups = list(annotated_group_list())
    divergent = divergent_counts_for_groups(groups)
    for group in groups:
        search_ref = group.group_ref or group.slug
        group.search_ref = search_ref
        group.display_ref = display_group_ref(search_ref)
        group.divergent_count = divergent.get(group.pk, 0)
        group.last_activity = _last_activity_datetime(group.last_activity_ms)
    return groups


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
    """Per-group count of messages not observed by every engine.

    Missing-observation logic spans three id columns plus a JSON list and a
    set difference per group, so it stays in Python: one batched query, then
    message_traces_from_events per group bucket. Fine while groups are few and
    events per group are bounded; persist the count (AnalysisRun or a column)
    if that stops being true.
    """
    events = AuditEvent.objects.filter(
        group__in=[group.pk for group in groups],
        parse_status=AuditEvent.STATUS_VALID,
        audit_file__validation_status=AuditFile.STATUS_VALID,
    )
    by_group = defaultdict(list)
    for event in events:
        by_group[event.group_id].append(event)
    counts = {}
    for group_id, group_events in by_group.items():
        engines = {event.engine_id for event in group_events if event.engine_id}
        traces = message_traces_from_events(group_events, engines)
        counts[group_id] = sum(
            1 for trace in traces if trace["missing_engines"] and trace["engines"]
        )
    return counts


# ---------------------------------------------------------------------------
# Message traces
# ---------------------------------------------------------------------------


def message_traces_for_group(group, events=None):
    if events is None:
        events = list(valid_events_for_group(group))
    all_engines = {event.engine_id for event in events if event.engine_id}
    return message_traces_from_events(events, all_engines)


def message_traces_from_events(events, all_engines):
    by_msg = defaultdict(list)
    for event in events:
        for msg_id in event_message_ids(event):
            by_msg[msg_id].append(event)

    traces = []
    for msg_id, msg_events in sorted(by_msg.items()):
        engines = sorted({event.engine_id for event in msg_events if event.engine_id})
        event_types = sorted({event.event_type for event in msg_events if event.event_type})
        states = sorted(
            {
                value
                for event in msg_events
                for value in (event.new_state, event.outcome, event.outcome_kind, event.reason)
                if value
            }
        )
        traces.append(
            {
                "msg_id": msg_id,
                "engines": engines,
                "missing_engines": sorted(set(all_engines) - set(engines)),
                "event_types": event_types,
                "states": states,
                "first_wall_time_ms": min(
                    (event.wall_time_ms for event in msg_events if event.wall_time_ms is not None),
                    default=None,
                ),
                "last_wall_time_ms": max(
                    (event.wall_time_ms for event in msg_events if event.wall_time_ms is not None),
                    default=None,
                ),
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
    return [trace for trace in traces if trace["missing_engines"] and trace["engines"]]


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
            event.event_type == "message_state_changed" and event.new_state in FAILED_MESSAGE_STATES
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
    if event.event_type in {"peeler_outcome", "rejection"}:
        tone = "error"
    if event.event_type == "message_state_changed" and event.new_state in FAILED_MESSAGE_STATES:
        tone = "error"
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
    ids = []
    for value in (event.msg_id, event.outbound_msg_id, event.invalidated_msg_id):
        if value:
            ids.append(value)
    ids.extend(event.outbound_welcome_msg_ids or [])
    ids.extend(event.human_action_message_ids or [])
    return ids


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
# Epoch timeline payload
# ---------------------------------------------------------------------------
#
# Server-side contract for the client geometry engine
# (forensics/static/forensics/js/timeline/). The client does all pixel math;
# this payload carries semantics only:
#   - engines[]: column order, labels, deterministic viz color
#   - epochs[]:  per-epoch confirmations (commit node = first timed confirm,
#                the rest are "applied" ticks), fork/rollback/snapshot detail
#                for the rail, stub entries for referenced-but-unconfirmed
#                epochs (confirmed: false)
#   - items[]:   every placed event, sorted (t, line, id); engine refs are
#                indexes into engines[]; empty fields omitted
# Timestamps are per-device wall clocks (time.basis); the client must not
# assume cross-engine monotonicity. Epoch numbers are real and may be sparse.


def timeline_payload_for_group(group, events, audit_files):
    ordered = sorted_timeline_events(events)
    engines, engine_idx = timeline_engines(ordered)
    epochs, roles = timeline_epochs(ordered, engine_idx, len(engines))
    items, excluded = timeline_items(ordered, engine_idx, roles)
    traces = message_traces_from_events(ordered, {engine["engine_id"] for engine in engines})
    placed = [item["t"] for item in items]
    return {
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
        "integrity": group_integrity_summary(group, events=ordered, traces=traces),
        "excluded": excluded,
    }


def group_integrity_summary(group, events=None, traces=None):
    if events is None:
        events = list(valid_events_for_group(group))
    if traces is None:
        traces = message_traces_for_group(group, events=events)
    missing = [trace for trace in traces if trace["missing_engines"] and trace["engines"]]
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
    forks = defaultdict(list)
    convergences = defaultdict(list)
    rollbacks = defaultdict(list)
    snapshots = defaultdict(list)
    referenced = set()
    message_counts = Counter()
    roles = {}

    for event in events:
        engine = engine_idx.get(event.engine_id)
        if event.event_type == "epoch_confirmed" and event.to_epoch is not None:
            confirmations[event.to_epoch].append(
                {
                    "engine": engine,
                    "t": event.wall_time_ms,
                    "from_epoch": event.from_epoch,
                    "pending_kind": event.pending_kind or "",
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
    for number in sorted(set(confirmations) | referenced):
        confs = sorted(
            confirmations.get(number, []),
            key=lambda conf: (conf["t"] is None, conf["t"] or 0, conf["item_id"]),
        )
        seen_engines = set()
        for conf in confs:
            conf["repeat"] = conf["engine"] in seen_engines
            if conf["engine"] is not None:
                seen_engines.add(conf["engine"])
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
                "confirmations": confs,
                "unconfirmed_engines": sorted(set(range(engine_count)) - seen_engines)
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


def timeline_items(events, engine_idx, roles):
    items = []
    excluded_ids = []
    by_reason = {"no_wall_time": 0, "no_engine": 0}
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
        items.append(
            {key: value for key, value in item.items() if value is not None and value != ""}
        )
    excluded = {
        "count": len(excluded_ids),
        "by_reason": by_reason,
        "event_ids": excluded_ids,
    }
    return items, excluded
