# Backfill AuditFile.source_local_member_ref for files ingested before 0018.
#
# The value is derived only from each file's own retained events, never from
# another segment, so the column stays an exact summary of that file. The rule
# mirrors forensics.ingest.body_source_metadata: the first line (by line order)
# whose source context carries a non-empty local_member_ref, truncated to the
# column length. Migrations must not import app code, which drifts under
# future refactors; a parity regression test keeps the two rules in step.

from django.db import migrations

FILE_BATCH_SIZE = 500
EVENT_CHUNK_SIZE = 2_000
LOCAL_MEMBER_REF_MAX_LENGTH = 32


def backfill_source_local_member_refs(apps, _schema_editor):
    AuditEvent = apps.get_model("forensics", "AuditEvent")
    AuditFile = apps.get_model("forensics", "AuditFile")

    events = (
        AuditEvent.objects.filter(
            audit_file__source_local_member_ref="",
            context_source__has_key="local_member_ref",
        )
        .order_by("audit_file_id", "line_number")
        .values_list("audit_file_id", "context_source")
    )
    updates = []
    last_file_id = None
    for file_id, source in events.iterator(chunk_size=EVENT_CHUNK_SIZE):
        if file_id == last_file_id:
            continue
        ref = source.get("local_member_ref")
        if not isinstance(ref, str) or not ref:
            continue
        last_file_id = file_id
        updates.append(
            AuditFile(id=file_id, source_local_member_ref=ref[:LOCAL_MEMBER_REF_MAX_LENGTH])
        )
        if len(updates) == FILE_BATCH_SIZE:
            AuditFile.objects.bulk_update(updates, ["source_local_member_ref"])
            updates = []
    if updates:
        AuditFile.objects.bulk_update(updates, ["source_local_member_ref"])


class Migration(migrations.Migration):
    dependencies = [
        ("forensics", "0018_auditfile_source_local_member_ref"),
    ]

    operations = [
        # The reverse is a no-op: reversing 0018 drops the column anyway.
        migrations.RunPython(
            backfill_source_local_member_refs,
            migrations.RunPython.noop,
        ),
    ]
