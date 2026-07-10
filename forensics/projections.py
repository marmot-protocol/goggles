from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from django.db import transaction
from django.db.models import F

from .analysis import structural_quarantine_exclusion
from .models import (
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
    RecipientExpectation,
    StateDelta,
)


@dataclass(frozen=True)
class MessageRef:
    msg_id: str
    artifact_kind: str = ""


NETWORK_EVENT_TYPES = {
    "transport_received",
    "ingest_entry",
    "ingest_outcome",
    "ingest_error",
    "publish_attempt",
    "publish_outcome",
    "publish_failure",
}
CONVERGENCE_EVENT_TYPES = {"convergence_run_state", "convergence_decision"}
AUDIT_SCHEMA_VERSION_V2 = "marmot-forensics-audit/v2"
INFERRED_CONVERGENCE_TERMINAL_PHASES = {
    "applied",
    "blocked",
    "failed",
    "stable",
    "unrecoverable",
}
INFERRED_CONVERGENCE_TERMINAL_EPOCH_STATES = {
    "committed",
    "failed",
    "stable",
    "unrecoverable",
}

# Projection work must never hydrate the verbatim per-line JSON or the parent
# AuditFile row. In particular, ``select_related("audit_file")`` repeats the
# complete AuditFile.raw_text once for every event in the SQL result: a 50 MiB
# upload with 1,000 events becomes roughly 50 GiB before projection even starts.
# Keep this list explicit so projection helpers can use normal model attributes
# without triggering deferred-field queries while the heavy evidence columns
# remain outside the worker heap.
PROJECTION_EVENT_FIELDS = (
    "id",
    "audit_file_id",
    "group_id",
    "line_number",
    "wall_time_ms",
    "engine_id",
    "account_ref",
    "audit_data_mode",
    "event_type",
    "context_convergence",
    "context_transport",
    "human_action_message_ids",
    "msg_id",
    "outbound_msg_id",
    "outbound_welcome_msg_ids",
    "invalidated_msg_id",
    "raw_kind",
    "relay_urls",
    "accepted_relay_urls",
    "failed_relays",
    "required_acks",
    "met_required_acks",
    "epoch",
    "pending_epoch",
    "payload_len",
    "payload_digest",
    "outcome",
    "outcome_kind",
    "reason",
    "new_state",
    "pending_kind",
    "result_kind",
    "selected_branch_id",
    "selected_fork_epoch",
    "selected_tip_epoch",
    "current_tip_epoch",
    "max_rewind_commits",
)


@dataclass
class ProjectionState:
    active_inferred_convergence_runs: dict[tuple[int, str], ConvergenceRun]


def rebuild_file_projections(audit_file: AuditFile) -> None:
    """Project an uploaded file's newly stored events onto existing projections.

    Projecting incrementally — only this file's valid events, onto the
    projection rows already built for the touched groups — keeps the ingest hot
    path proportional to the *upload*, not the whole group. A small append no
    longer deletes and re-inserts every projection row for the entire group
    (marmot-protocol/goggles#127). The projection helpers are idempotent upserts
    keyed on ``(group, artifact_id)`` / ``(artifact, engine_id)`` /
    ``(group, engine_id, run_id)``, and each stored ``AuditEvent`` is projected
    exactly once across uploads (a re-uploaded file short-circuits on its
    ``file_sha256`` before any event is stored), so appending new evidence to
    existing rows needs no full clear. Use ``rebuild_group_projections`` (the
    management-command path) for an explicit full rebuild from raw evidence.
    """
    if AUDIT_SCHEMA_VERSION_V2 not in (audit_file.schema_versions or []):
        return
    group_ids = set(audit_file.groups.values_list("id", flat=True))
    group_ids.update(
        AuditEvent.objects.filter(audit_file=audit_file, group__isnull=False).values_list(
            "group_id", flat=True
        )
    )
    if not group_ids:
        return
    project_file_events(audit_file, sorted(group_ids))


@transaction.atomic
def project_file_events(audit_file: AuditFile, group_ids: list[int]) -> None:
    # Lock the touched groups in a stable order so concurrent uploads to the
    # same group serialize on the projection writes without deadlocking, but
    # only re-project this file's own newly stored events instead of the whole
    # group's history.
    locked_groups = list(
        AuditGroup.objects.select_for_update().filter(id__in=group_ids).order_by("id")
    )
    events = list(
        AuditEvent.objects.only(*PROJECTION_EVENT_FIELDS)
        .filter(
            structural_quarantine_exclusion(),
            audit_file=audit_file,
            parse_status=AuditEvent.STATUS_VALID,
            group__isnull=False,
            group_id__in=group_ids,
        )
        .order_by("wall_time_ms", "engine_id", "line_number", "id")
    )
    # The incremental fast path assumes each upload is a chronological append.
    # If this file backfills a convergence-relevant event that sorts *before*
    # an already-projected one in the same group, inferred-run stitching cannot
    # be replayed in place, so fall back to a full rebuild for those groups
    # (marmot-protocol/goggles#127). Chronological appends keep the fast path.
    backfilled_group_ids = groups_with_out_of_order_convergence_backfill(audit_file, events)
    if backfilled_group_ids:
        groups_by_id = {group.id: group for group in locked_groups}
        for group_id in sorted(backfilled_group_ids):
            group = groups_by_id.get(group_id)
            if group is not None:
                rebuild_locked_group_projections(group)
        events = [event for event in events if event.group_id not in backfilled_group_ids]
    state = ProjectionState(
        active_inferred_convergence_runs=active_inferred_runs_for_events(events),
    )
    for event in events:
        project_event(event, state)


def groups_with_out_of_order_convergence_backfill(
    audit_file: AuditFile,
    events: list[AuditEvent],
) -> set[int]:
    """Find groups whose uploaded convergence events predate stored ones.

    Inferred-run stitching depends on processing convergence-relevant events in
    ``(wall_time_ms, engine_id, line_number)`` order. The incremental path only
    projects this file's events, so it can only stay correct when those events
    are a chronological append. For each touched group we compare the earliest
    convergence-relevant event in this upload against the latest already-stored
    one (from prior uploads): if the upload sorts first, the group must be
    rebuilt from full evidence instead of appended.
    """
    earliest_uploaded: dict[int, tuple[bool, int, str, int]] = {}
    for event in events:
        if event.group_id is None or not event_may_need_inferred_convergence_state(event):
            continue
        key = convergence_order_key(event)
        current = earliest_uploaded.get(event.group_id)
        if current is None or key < current:
            earliest_uploaded[event.group_id] = key
    if not earliest_uploaded:
        return set()
    backfilled: set[int] = set()
    stored = (
        AuditEvent.objects.filter(
            group_id__in=earliest_uploaded.keys(),
            parse_status=AuditEvent.STATUS_VALID,
        )
        .exclude(audit_file=audit_file)
        .only(
            "group_id",
            "event_type",
            "engine_id",
            "line_number",
            "wall_time_ms",
            "context_convergence",
        )
    )
    for event in stored.iterator(chunk_size=2_000):
        if event.group_id in backfilled:
            continue
        if not event_may_need_inferred_convergence_state(event):
            continue
        # A stored convergence event that sorts after this upload's earliest
        # convergence event means the upload backfills history out of order.
        if earliest_uploaded[event.group_id] < convergence_order_key(event):
            backfilled.add(event.group_id)
    return backfilled


def convergence_order_key(event: AuditEvent) -> tuple[bool, int, str, int]:
    # Stable, content-derived ordering shared with the full-rebuild sort,
    # excluding the row ``id`` (which is not comparable across uploads). Treat
    # NULL wall_time_ms as latest, matching inferred-run evidence ordering.
    return (
        event.wall_time_ms is None,
        event.wall_time_ms or 0,
        event.engine_id or "",
        event.line_number,
    )


def active_inferred_runs_for_events(
    events: list[AuditEvent],
) -> dict[tuple[int, str], ConvergenceRun]:
    """Reconstruct the in-flight inferred convergence runs an append may continue.

    Inferred runs (no explicit ``run_id``) are stitched across events keyed on
    ``(group_id, engine_id)`` and stay "active" until a terminal event closes
    them. When an upload appends more convergence evidence to a run opened by an
    earlier upload, the fresh :class:`ProjectionState` must already know about
    that open run so the new events extend it instead of spawning a duplicate.

    Reconstruction is bounded to the convergence-relevant ``(group_id, engine_id)``
    pairs this file actually touches (not the whole group): the latest inferred
    run for each such pair is treated as active when its most recent evidence
    event was not itself terminal.
    """
    keys = {
        (event.group_id, event.engine_id)
        for event in events
        if event.group_id is not None
        and event.engine_id
        and event_may_need_inferred_convergence_state(event)
    }
    active: dict[tuple[int, str], ConvergenceRun] = {}
    for group_id, engine_id in sorted(keys):
        run = (
            ConvergenceRun.objects.filter(
                group_id=group_id,
                engine_id=engine_id,
                inferred=True,
            )
            .order_by(F("started_at_ms").desc(nulls_first=True), "-id")
            .first()
        )
        if run is not None and run_is_active_inferred(run):
            active[(group_id, engine_id)] = run
    return active


def event_may_need_inferred_convergence_state(event: AuditEvent) -> bool:
    if event.event_type in CONVERGENCE_EVENT_TYPES or event.event_type == "epoch_state_changed":
        return True
    context = event.context_convergence if isinstance(event.context_convergence, dict) else {}
    return bool(context and not str(context.get("run_id") or ""))


def run_is_active_inferred(run: ConvergenceRun) -> bool:
    # Only the run's most recent evidence row decides whether it is still open,
    # so fetch just that row instead of loading the whole evidence set. NULL
    # ``wall_time_ms`` sorts last to match the projection ordering above.
    last_event = (
        run.evidence_events.only(
            "id",
            "event_type",
            "new_state",
            "wall_time_ms",
            "engine_id",
            "line_number",
        )
        .order_by(
            F("wall_time_ms").asc(nulls_last=True),
            "engine_id",
            "line_number",
            "id",
        )
        .last()
    )
    if last_event is None:
        return True
    return not inferred_convergence_event_is_terminal(last_event, run.phase)


@transaction.atomic
def rebuild_group_projections(group: AuditGroup) -> None:
    group = AuditGroup.objects.select_for_update().get(pk=group.pk)
    rebuild_locked_group_projections(group)


def rebuild_locked_group_projections(group: AuditGroup) -> None:
    """Clear and re-project a group from its full valid evidence.

    The caller must already hold the ``select_for_update`` lock on ``group``.
    """
    clear_group_projections(group)
    events = (
        AuditEvent.objects.only(*PROJECTION_EVENT_FIELDS)
        .filter(
            structural_quarantine_exclusion(),
            group=group,
            parse_status=AuditEvent.STATUS_VALID,
        )
        .order_by("wall_time_ms", "engine_id", "line_number", "id")
    )
    state = ProjectionState(active_inferred_convergence_runs={})
    for event in events.iterator(chunk_size=500):
        project_event(event, state)


def clear_group_projections(group: AuditGroup) -> None:
    NetworkObservation.objects.filter(group=group).delete()
    StateDelta.objects.filter(group=group).delete()
    EpochStateTransition.objects.filter(group=group).delete()
    DeliveryArtifact.objects.filter(group=group).delete()
    ConvergenceRun.objects.filter(group=group).delete()


def project_event(event: AuditEvent, state: ProjectionState | None = None) -> None:
    artifacts = [artifact_for_message(event, ref) for ref in message_refs_for_event(event)]
    artifacts = [artifact for artifact in artifacts if artifact is not None]
    for artifact in artifacts:
        project_delivery_observation(event, artifact)
        project_recipient_expectations(event, artifact)
    if event.event_type in NETWORK_EVENT_TYPES:
        project_network_observation(event, artifacts[0] if artifacts else None)
    if should_project_convergence(event, state):
        project_convergence(event, state)
    if event.event_type == "group_state_changed":
        project_state_delta(event)
    if event.event_type == "epoch_state_changed":
        project_epoch_transition(event)


def message_refs_for_event(event: AuditEvent) -> list[MessageRef]:
    kind = event.raw_kind if isinstance(event.raw_kind, dict) else {}
    refs: list[MessageRef] = []

    def add(msg_id: Any, artifact_kind: Any = "") -> None:
        if isinstance(msg_id, str) and msg_id and all(ref.msg_id != msg_id for ref in refs):
            refs.append(
                MessageRef(
                    msg_id=msg_id,
                    artifact_kind=artifact_kind if isinstance(artifact_kind, str) else "",
                )
            )

    add(event.msg_id, kind.get("artifact_kind"))
    add(event.outbound_msg_id)
    for msg_id in event.outbound_welcome_msg_ids or []:
        add(msg_id, "welcome")
    for msg_id in event.human_action_message_ids or []:
        add(msg_id)
    add(event.invalidated_msg_id)
    add(kind.get("msg_id"), kind.get("artifact_kind"))
    for outbound in kind.get("outbound_messages") or []:
        if isinstance(outbound, dict):
            add(outbound.get("msg_id"), outbound.get("artifact_kind"))
    return refs


def artifact_for_message(event: AuditEvent, ref: MessageRef) -> DeliveryArtifact | None:
    if event.group_id is None:
        return None
    artifact, _created = DeliveryArtifact.objects.get_or_create(
        group_id=event.group_id,
        artifact_id=ref.msg_id,
        defaults={
            "artifact_kind": ref.artifact_kind,
            "first_seen_ms": event.wall_time_ms,
            "last_seen_ms": event.wall_time_ms,
            "audit_data_modes": [event.audit_data_mode] if event.audit_data_mode else [],
        },
    )
    changed = False
    if ref.artifact_kind and artifact.artifact_kind in {"", "unknown"}:
        artifact.artifact_kind = ref.artifact_kind
        changed = True
    if event.wall_time_ms is not None:
        if artifact.first_seen_ms is None or event.wall_time_ms < artifact.first_seen_ms:
            artifact.first_seen_ms = event.wall_time_ms
            changed = True
        if artifact.last_seen_ms is None or event.wall_time_ms > artifact.last_seen_ms:
            artifact.last_seen_ms = event.wall_time_ms
            changed = True
    if append_json_value(artifact.audit_data_modes, event.audit_data_mode):
        changed = True

    kind = event.raw_kind if isinstance(event.raw_kind, dict) else {}
    if event.event_type == "message_content_decoded":
        for field in ("author", "decoded_payload", "decoded_app_event"):
            value = kind.get(field)
            if isinstance(value, dict) and getattr(artifact, field) != value:
                setattr(artifact, field, value)
                changed = True

    if changed:
        artifact.save()
    artifact.evidence_events.add(event)
    return artifact


def project_delivery_observation(event: AuditEvent, artifact: DeliveryArtifact) -> None:
    if not event.engine_id:
        return
    observation, _created = DeliveryObservation.objects.get_or_create(
        artifact=artifact,
        engine_id=event.engine_id,
        defaults={
            "account_ref": event.account_ref,
            "first_seen_ms": event.wall_time_ms,
            "last_seen_ms": event.wall_time_ms,
        },
    )
    changed = False
    if event.account_ref and not observation.account_ref:
        observation.account_ref = event.account_ref
        changed = True
    if event.wall_time_ms is not None:
        if observation.first_seen_ms is None or event.wall_time_ms < observation.first_seen_ms:
            observation.first_seen_ms = event.wall_time_ms
            changed = True
        if observation.last_seen_ms is None or event.wall_time_ms > observation.last_seen_ms:
            observation.last_seen_ms = event.wall_time_ms
            changed = True

    state = delivery_state_for_event(event)
    if state:
        states = list(observation.states or [])
        state_entry = {
            "state": state,
            "event_type": event.event_type,
            "event_id": event.id,
            "wall_time_ms": event.wall_time_ms,
        }
        states.append(state_entry)
        observation.states = states
        observation.latest_state = state
        changed = True
    if changed:
        observation.save()
    observation.evidence_events.add(event)


def delivery_state_for_event(event: AuditEvent) -> str:
    if event.event_type == "message_state_changed" and event.new_state:
        return event.new_state
    if event.event_type == "ingest_outcome" and event.outcome_kind:
        return f"ingest:{event.outcome_kind}"
    if event.event_type == "send_outcome" and event.result_kind:
        return f"send:{event.result_kind}"
    if event.event_type == "publish_outcome":
        return "publish:acked" if event.met_required_acks else "publish:partial"
    if event.event_type == "publish_failure":
        return "publish:failed"
    if event.event_type == "message_content_decoded":
        return "decoded"
    if event.event_type == "recipient_expectation":
        return "expected"
    return event.event_type


def project_recipient_expectations(event: AuditEvent, artifact: DeliveryArtifact) -> None:
    kind = event.raw_kind if isinstance(event.raw_kind, dict) else {}
    expectations: list[dict[str, Any]] = []
    if event.event_type == "recipient_expectation" and isinstance(kind.get("expectation"), dict):
        expectations.append(kind["expectation"])
    for outbound in kind.get("outbound_messages") or []:
        if not isinstance(outbound, dict) or outbound.get("msg_id") != artifact.artifact_id:
            continue
        expectation = outbound.get("recipient_expectation")
        if isinstance(expectation, dict):
            expectations.append(expectation)

    for expectation in expectations:
        RecipientExpectation.objects.create(
            artifact=artifact,
            artifact_kind=str(expectation.get("artifact_kind") or artifact.artifact_kind),
            recipient_scope=str(expectation.get("recipient_scope") or "unknown"),
            membership_epoch=int_or_none(expectation.get("membership_epoch")),
            basis_commit_id=str(expectation.get("basis_commit_id") or ""),
            expected_member_refs=list_or_empty(expectation.get("expected_member_refs")),
            expected_pubkeys_hex=list_or_empty(expectation.get("expected_pubkeys_hex")),
            expected_count=int_or_none(expectation.get("expected_count")),
            evidence_event=event,
        )


def project_network_observation(
    event: AuditEvent,
    artifact: DeliveryArtifact | None,
) -> None:
    kind = event.raw_kind if isinstance(event.raw_kind, dict) else {}
    wire = wire_for_event(event, kind)
    message_id = artifact.artifact_id if artifact else str(kind.get("msg_id") or event.msg_id or "")
    NetworkObservation.objects.create(
        group_id=event.group_id,
        artifact=artifact,
        audit_event=event,
        direction=network_direction(event.event_type),
        phase=event.event_type,
        message_id=message_id,
        artifact_kind=str(
            kind.get("artifact_kind") or (artifact.artifact_kind if artifact else "")
        ),
        engine_id=event.engine_id,
        account_ref=event.account_ref,
        wall_time_ms=event.wall_time_ms,
        transport_source=str(kind.get("transport_source") or wire.get("transport") or ""),
        delivery_plane=str(wire.get("delivery_plane") or context_delivery_plane(event)),
        relay_url=relay_url_for_event(event, kind, wire),
        subscription_id=str(wire.get("subscription_id") or ""),
        wire_id=str(wire.get("wire_id") or ""),
        wire_kind=str(wire.get("wire_kind") or ""),
        wire_pubkey_hex=str(wire.get("wire_pubkey_hex") or ""),
        transport_group_id=str(wire.get("transport_group_id") or ""),
        nostr_event_id=str(wire.get("nostr_event_id") or ""),
        nostr_kind=int_or_none(wire.get("nostr_kind")),
        nostr_pubkey_hex=str(wire.get("nostr_pubkey_hex") or ""),
        gift_wrap_event_id=str(wire.get("gift_wrap_event_id") or ""),
        welcome_nostr_event_id=str(wire.get("welcome_nostr_event_id") or ""),
        welcome_rumor_event_id=str(wire.get("welcome_rumor_event_id") or ""),
        welcome_key_package_tag=str(wire.get("welcome_key_package_tag") or ""),
        publish_result_id=str(wire.get("publish_result_id") or ""),
        payload_len=event.payload_len,
        payload_digest=event.payload_digest,
        outcome=network_outcome(event),
        accepted_relay_urls=event.accepted_relay_urls or [],
        failed_relays=event.failed_relays or [],
        required_acks=event.required_acks,
        met_required_acks=event.met_required_acks,
    )


def wire_for_event(event: AuditEvent, kind: dict[str, Any]) -> dict[str, Any]:
    wire = kind.get("transport")
    if isinstance(wire, dict):
        return wire
    context = event.context_transport if isinstance(event.context_transport, dict) else {}
    context_wire = context.get("wire")
    if isinstance(context_wire, dict):
        return context_wire
    return {}


def context_delivery_plane(event: AuditEvent) -> str:
    context = event.context_transport if isinstance(event.context_transport, dict) else {}
    return str(context.get("delivery_plane") or "")


def relay_url_for_event(
    event: AuditEvent,
    kind: dict[str, Any],
    wire: dict[str, Any],
) -> str:
    if wire.get("relay_url"):
        return str(wire["relay_url"])
    relay_url = kind.get("relay_url")
    if isinstance(relay_url, str) and relay_url:
        return relay_url
    relays = kind.get("relay_urls") or event.relay_urls or event.accepted_relay_urls or []
    if relays and isinstance(relays, list) and isinstance(relays[0], str):
        return relays[0]
    context = event.context_transport if isinstance(event.context_transport, dict) else {}
    return str(context.get("relay_url") or "")


def network_direction(event_type: str) -> str:
    if event_type.startswith("publish") or event_type in {"send_outcome", "create_group_outcome"}:
        return "outbound"
    return "inbound"


def network_outcome(event: AuditEvent) -> str:
    return (
        event.outcome
        or event.outcome_kind
        or event.result_kind
        or event.reason
        or ("met_required_acks" if event.met_required_acks else "")
    )


def should_project_convergence(event: AuditEvent, state: ProjectionState | None) -> bool:
    if event.event_type in CONVERGENCE_EVENT_TYPES or event.context_convergence:
        return True
    return bool(
        event.event_type == "epoch_state_changed"
        and state
        and event.group_id is not None
        and event.engine_id
        and inferred_convergence_key(event) in state.active_inferred_convergence_runs
    )


def project_convergence(event: AuditEvent, state: ProjectionState | None = None) -> None:
    if event.group_id is None or not event.engine_id:
        return
    kind = event.raw_kind if isinstance(event.raw_kind, dict) else {}
    context = event.context_convergence if isinstance(event.context_convergence, dict) else {}
    explicit_run_id = str(context.get("run_id") or "")
    if explicit_run_id:
        run_id = explicit_run_id
        if state:
            state.active_inferred_convergence_runs.pop(inferred_convergence_key(event), None)
        run, _created = ConvergenceRun.objects.get_or_create(
            group_id=event.group_id,
            engine_id=event.engine_id,
            run_id=run_id,
            defaults={"account_ref": event.account_ref, "inferred": False},
        )
    else:
        run = inferred_convergence_run_for_event(event, state)

    update_run_from_event(run, event, context, kind)
    run.evidence_events.add(event)
    if event.event_type == "convergence_decision":
        project_convergence_decision(run, kind)
    if state and not explicit_run_id and inferred_convergence_event_is_terminal(event, run.phase):
        state.active_inferred_convergence_runs.pop(inferred_convergence_key(event), None)


def inferred_convergence_run_for_event(
    event: AuditEvent,
    state: ProjectionState | None,
) -> ConvergenceRun:
    key = inferred_convergence_key(event)
    active = state.active_inferred_convergence_runs.get(key) if state else None
    if active is not None:
        return active
    run = ConvergenceRun.objects.create(
        group_id=event.group_id,
        engine_id=event.engine_id,
        run_id=f"inferred-{event.engine_id}-{event.id}",
        account_ref=event.account_ref,
        inferred=True,
    )
    if state:
        state.active_inferred_convergence_runs[key] = run
    return run


def inferred_convergence_key(event: AuditEvent) -> tuple[int, str]:
    return (event.group_id, event.engine_id)


def inferred_convergence_event_is_terminal(event: AuditEvent, phase: str) -> bool:
    if event.event_type == "epoch_state_changed":
        return event.new_state in INFERRED_CONVERGENCE_TERMINAL_EPOCH_STATES
    if event.event_type == "convergence_run_state":
        return phase in INFERRED_CONVERGENCE_TERMINAL_PHASES
    return False


def update_run_from_event(
    run: ConvergenceRun,
    event: AuditEvent,
    context: dict[str, Any],
    kind: dict[str, Any],
) -> None:
    changed = False
    if event.account_ref and not run.account_ref:
        run.account_ref = event.account_ref
        changed = True
    phase = str(
        kind.get("phase")
        or context.get("phase")
        or inferred_phase_for_event(event)
        or event.outcome
    )
    if phase:
        run.phase = phase
        changed = True
    if context.get("inferred") is not None:
        run.inferred = bool(context.get("inferred"))
        changed = True
    if event.wall_time_ms is not None:
        if run.started_at_ms is None or event.wall_time_ms < run.started_at_ms:
            run.started_at_ms = event.wall_time_ms
            changed = True
        if run.ended_at_ms is None or event.wall_time_ms > run.ended_at_ms:
            run.ended_at_ms = event.wall_time_ms
            changed = True
    for field in (
        "current_tip_epoch",
        "selected_branch_id",
        "selected_fork_epoch",
        "selected_tip_epoch",
        "max_rewind_commits",
    ):
        value = getattr(event, field)
        if value not in (None, "") and getattr(run, field) != value:
            setattr(run, field, value)
            changed = True
    for field in ("losing_branch_ids", "error_kinds"):
        value = kind.get(field)
        if isinstance(value, list) and getattr(run, field) != value:
            setattr(run, field, value)
            changed = True
    if changed:
        run.save()


def inferred_phase_for_event(event: AuditEvent) -> str:
    if event.event_type == "convergence_decision":
        return "selected" if event.selected_branch_id else "decision"
    if event.event_type == "epoch_state_changed":
        return event.new_state
    return ""


def project_convergence_decision(run: ConvergenceRun, kind: dict[str, Any]) -> None:
    for candidate in kind.get("candidates") or []:
        if not isinstance(candidate, dict):
            continue
        branch_id = str(candidate.get("branch_id") or "")
        if not branch_id:
            continue
        ConvergenceCandidate.objects.update_or_create(
            run=run,
            branch_id=branch_id,
            defaults={
                "fork_epoch": int_or_none(candidate.get("fork_epoch")),
                "tip_epoch": int_or_none(candidate.get("tip_epoch")),
                "commit_ids": list_or_empty(candidate.get("commit_ids")),
                "commit_count": int_or_none(candidate.get("commit_count")),
                "state_digest": str(candidate.get("state_digest") or ""),
                "tip_digest": str(candidate.get("tip_digest") or ""),
                "tip_priority": str(candidate.get("tip_priority") or ""),
                "tip_committer_ref": str(candidate.get("tip_committer_ref") or ""),
                "tip_committer_pubkey_hex": str(candidate.get("tip_committer_pubkey_hex") or ""),
                "retained_anchor_status": str(candidate.get("retained_anchor_status") or ""),
                "last_input_time_ms": int_or_none(candidate.get("last_input_time_ms")),
                "eligible": bool_or_none(candidate.get("eligible")),
                "rejection_reasons": list_or_empty(candidate.get("rejection_reasons")),
                "score": dict_or_empty(candidate.get("score")),
                "app_witnesses": list_or_empty(candidate.get("app_witnesses")),
            },
        )

    for sequence, rule in enumerate(kind.get("rule_trace") or []):
        if not isinstance(rule, dict):
            continue
        ConvergenceRuleEvaluation.objects.create(
            run=run,
            rule_name=str(rule.get("rule_name") or ""),
            scope=str(rule.get("scope") or ""),
            candidate_branch_id=str(rule.get("candidate_branch_id") or ""),
            other_candidate_branch_id=str(rule.get("other_candidate_branch_id") or ""),
            inputs=dict_or_empty(rule.get("inputs")),
            result=rule.get("result") if rule.get("result") is not None else {},
            decisive=bool(rule.get("decisive")),
            selected_branch_id=str(rule.get("selected_branch_id") or ""),
            rejected_branch_id=str(rule.get("rejected_branch_id") or ""),
            sequence=sequence,
        )


def project_state_delta(event: AuditEvent) -> None:
    kind = event.raw_kind if isinstance(event.raw_kind, dict) else {}
    StateDelta.objects.create(
        group_id=event.group_id,
        audit_event=event,
        epoch=event.epoch,
        change_kind=str(kind.get("change_kind") or event.outcome_kind or ""),
        membership_change_source=str(kind.get("membership_change_source") or ""),
        actor_member_ref=str(kind.get("actor_member_ref") or ""),
        actor_pubkey_hex=str(kind.get("actor_pubkey_hex") or ""),
        subject_member_ref=str(kind.get("subject_member_ref") or ""),
        subject_pubkey_hex=str(kind.get("subject_pubkey_hex") or ""),
        origin_commit_id=str(kind.get("origin_commit_id") or ""),
        fields=list_or_empty(kind.get("fields")),
        component_ids=list_or_empty(kind.get("component_ids")),
        value=dict_or_empty(kind.get("value")),
        audit_data_mode=event.audit_data_mode,
        wall_time_ms=event.wall_time_ms,
    )


def project_epoch_transition(event: AuditEvent) -> None:
    EpochStateTransition.objects.create(
        group_id=event.group_id,
        audit_event=event,
        engine_id=event.engine_id,
        account_ref=event.account_ref,
        previous_state=event.outcome,
        new_state=event.new_state,
        epoch=event.epoch,
        reason=event.reason,
        pending_ref=event.pending_epoch,
        pending_kind=event.pending_kind,
        wall_time_ms=event.wall_time_ms,
    )


def append_json_value(values: list[Any], value: Any) -> bool:
    if not value or value in values:
        return False
    values.append(value)
    values.sort()
    return True


def int_or_none(value: Any) -> int | None:
    return value if type(value) is int and value >= 0 else None


def bool_or_none(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def list_or_empty(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def dict_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
