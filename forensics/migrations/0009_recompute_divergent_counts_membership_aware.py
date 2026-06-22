# Recompute AuditGroup.divergent_message_count with the membership-aware
# divergence definition (goggles P1). Migration 0006 backfilled the original
# "any engine in the group missed it" definition; it is frozen history. This
# migration re-derives the counts so an existing deployment's landing-page
# badges reflect *real* breaks — messages a demonstrably-present engine missed —
# rather than benign late-joiner gaps, without waiting for each group to be
# re-ingested.
#
# The computation is intentionally self-contained (migrations must not import
# app code); it mirrors forensics.analysis.divergent_counts_for_group_ids and is
# kept honest by the runtime parity regression test.

from collections import defaultdict

from django.db import migrations

VALID = "valid"
GROUP_BATCH_SIZE = 500
EVENT_CHUNK_SIZE = 2_000


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


def divergent_counts_for_group_ids(AuditEvent, group_ids):
    counts = dict.fromkeys(group_ids, 0)
    engines_by_group = defaultdict(set)
    windows_by_group = defaultdict(dict)
    message_engines_by_group = defaultdict(lambda: defaultdict(set))
    message_reference_by_group = defaultdict(dict)
    rows = AuditEvent.objects.filter(
        group_id__in=group_ids,
        parse_status=VALID,
        audit_file__validation_status=VALID,
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
        ("forensics", "0008_merge_20260622_1517"),
    ]

    operations = [
        # The reverse is a no-op: the membership-aware counts are a strict
        # refinement of the 0006 backfill and there is no value in restoring the
        # looser counts. Re-running 0006's logic forward is not desired either.
        migrations.RunPython(
            recompute_divergent_message_counts,
            migrations.RunPython.noop,
        ),
    ]
