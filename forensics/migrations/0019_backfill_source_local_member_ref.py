# Backfill AuditFile.source_local_member_ref for files ingested before 0018.
#
# The value is derived only from each file's own retained raw text, never from
# another segment, so the column stays an exact summary of that file. Events
# are not a sufficient source: deduplication discards lines already stored by
# an earlier upload, such as the leading source_context of a re-uploaded file.
# The rule mirrors forensics.ingest.body_source_metadata: the first line whose
# source carries a non-empty local_member_ref, truncated to the column length.
# Migrations must not import app code, which drifts under future refactors; a
# parity regression test keeps the two rules in step.

import json

from django.db import migrations

FILE_BATCH_SIZE = 500
LOCAL_MEMBER_REF_MAX_LENGTH = 32


def line_source(event):
    # Ingest normalizes context.source first; a source_context kind then wins.
    kind = event.get("kind") or {}
    if kind.get("type") == "source_context" and isinstance(kind.get("source"), dict):
        return kind["source"]
    source = (event.get("context") or {}).get("source")
    return source if isinstance(source, dict) else {}


def first_local_member_ref(raw_text):
    for raw_line in raw_text.split("\n"):
        try:
            event = json.loads(raw_line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        ref = line_source(event).get("local_member_ref")
        if isinstance(ref, str) and ref:
            return ref[:LOCAL_MEMBER_REF_MAX_LENGTH]
    return ""


def backfill_source_local_member_refs(apps, _schema_editor):
    AuditFile = apps.get_model("forensics", "AuditFile")

    files = AuditFile.objects.filter(
        source_local_member_ref="",
        raw_text__contains="local_member_ref",
    ).values_list("id", "raw_text")
    updates = []
    # Uploads reach 64 MiB, so hold one raw body at a time.
    for file_id, raw_text in files.iterator(chunk_size=1):
        ref = first_local_member_ref(raw_text)
        if not ref:
            continue
        updates.append(AuditFile(id=file_id, source_local_member_ref=ref))
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
