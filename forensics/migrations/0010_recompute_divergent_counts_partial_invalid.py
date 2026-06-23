# Recompute AuditGroup.divergent_message_count with the unified "events that
# count for a group" predicate (goggles#103). Migration 0006 backfilled the
# original definition and 0009 re-derived it with the membership-aware rule;
# both are frozen history. This migration re-derives the counts again because
# goggles#103 widened the persisted predicate: divergent_counts_for_group_ids()
# now counts the parse_status=VALID events that live in a *partially*-invalid
# file (one marked INVALID for a non-structural reason, e.g. a single malformed
# JSONL line) instead of dropping every event of any non-VALID file. Only the
# *structural* quarantine errors (multi-engine / multi-account uploads) still
# exclude a file wholesale, matching forensics.analysis.valid_events_for_group.
#
# Without this backfill, any group whose only — or additional — events live in
# a partially-invalid file keeps its old valid-files-only persisted count after
# deploy until some later ingest happens to touch that group. The landing-page
# and group-detail-header divergent badge would then disagree with the Messages
# tab / agent export (which read the live trace), exactly the symptom #103
# reported. Re-deriving here repairs existing rows immediately.
#
# The computation is intentionally self-contained (migrations must not import
# app code, which drifts under future refactors); it mirrors
# forensics.analysis.divergent_counts_for_group_ids and is kept honest by the
# runtime parity regression test.

from collections import defaultdict

from django.db import migrations
from django.db.models import Q

VALID = "valid"
GROUP_BATCH_SIZE = 500
EVENT_CHUNK_SIZE = 2_000

# Mirrors forensics.analysis.STRUCTURAL_QUARANTINE_ERRORS. A file flagged with
# one of these is structurally untrustworthy (its engine/account attribution is
# ambiguous) and must be dropped wholesale; any other INVALID reason still
# contributes its parse_status=VALID events.
STRUCTURAL_QUARANTINE_ERRORS = (
    "audit log contains multiple engine_ids",
    "audit log contains multiple account_refs",
)


def message_id_values(
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


def iter_group_id_batches(AuditGroup):
    batch = []
    group_ids = AuditGroup.objects.order_by("id").values_list("id", flat=True)
    for group_id in group_ids.iterator(chunk_size=GROUP_BATCH_SIZE):
        batch.append(group_id)
        if len(batch) == GROUP_BATCH_SIZE:
            yield batch
            batch = []
    if batch:
        yield batch


def structural_quarantine_exclusion():
    """Exclude events whose file is *structurally* quarantined (multi-engine /
    multi-account). Mirrors forensics.analysis.structural_quarantine_exclusion
    for a queryset already rooted on AuditEvent."""
    predicate = Q()
    for error in STRUCTURAL_QUARANTINE_ERRORS:
        predicate &= ~Q(audit_file__validation_error__icontains=error)
    return predicate


def divergent_counts_for_group_ids(AuditEvent, group_ids):
    counts = dict.fromkeys(group_ids, 0)
    engines_by_group = defaultdict(set)
    windows_by_group = defaultdict(dict)
    message_engines_by_group = defaultdict(lambda: defaultdict(set))
    message_reference_by_group = defaultdict(dict)
    rows = AuditEvent.objects.filter(
        structural_quarantine_exclusion(),
        group_id__in=group_ids,
        parse_status=VALID,
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
    ) in rows.iterator(chunk_size=EVENT_CHUNK_SIZE):
        if not engine_id:
            continue
        engines_by_group[group_id].add(engine_id)
        if wall_time_ms is not None:
            windows = windows_by_group[group_id]
            first, last = windows.get(engine_id, (wall_time_ms, wall_time_ms))
            windows[engine_id] = (min(first, wall_time_ms), max(last, wall_time_ms))
        for message_id in message_id_values(
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
            reference_ms = references.get(message_id)
            if reference_ms is None:
                continue
            missing = set()
            for engine_id in all_engines:
                if engine_id in observers:
                    continue
                window = windows.get(engine_id)
                if window is not None and window[0] <= reference_ms <= window[1]:
                    missing.add(engine_id)
            if observers and missing:
                divergent += 1
        counts[group_id] = divergent
    return counts


def recompute_divergent_message_counts(apps, _schema_editor):
    AuditEvent = apps.get_model("forensics", "AuditEvent")
    AuditGroup = apps.get_model("forensics", "AuditGroup")

    for group_ids in iter_group_id_batches(AuditGroup):
        counts = divergent_counts_for_group_ids(AuditEvent, group_ids)
        updates = []
        groups = AuditGroup.objects.filter(id__in=group_ids).only(
            "id",
            "divergent_message_count",
        )
        for group in groups.iterator(chunk_size=GROUP_BATCH_SIZE):
            count = counts.get(group.id, 0)
            if group.divergent_message_count != count:
                group.divergent_message_count = count
                updates.append(group)

        if updates:
            AuditGroup.objects.bulk_update(
                updates,
                ["divergent_message_count"],
                batch_size=GROUP_BATCH_SIZE,
            )


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("forensics", "0009_recompute_divergent_counts_membership_aware"),
    ]

    operations = [
        # The reverse is a no-op: the partial-invalid-aware counts are a strict
        # widening of the 0009 backfill and there is no value in restoring the
        # narrower valid-files-only counts. Re-running 0009's logic forward is
        # not desired either.
        migrations.RunPython(
            recompute_divergent_message_counts,
            migrations.RunPython.noop,
        ),
    ]
