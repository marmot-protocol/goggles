# Backfill AuditFile.source_local_member_ref for files ingested before 0018.
#
# The value is derived only from each file's own retained raw text, never from
# another segment, so the column stays an exact summary of that file. Events
# are not a sufficient source: deduplication discards lines already stored by
# an earlier upload, such as the leading source_context of a re-uploaded file.
# Only v4 lines of valid files are trusted. The rule mirrors
# forensics.ingest.file_local_member_ref: refs compare lowercase, and a file
# whose refs disagree or are malformed stays unknown. Migrations must not
# import app code, which drifts under future refactors; parity regression tests
# keep the two rules in step.

import json
import re

from django.db import migrations

SCHEMA_VERSION = "marmot-forensics-audit/v4"
LOCAL_MEMBER_REF_PATTERN = re.compile(r"[0-9a-f]{32}")


def line_source(event):
    # Ingest normalizes context.source first; a source_context kind then wins.
    kind = event.get("kind") or {}
    if kind.get("type") == "source_context" and isinstance(kind.get("source"), dict):
        return kind["source"]
    source = (event.get("context") or {}).get("source")
    return source if isinstance(source, dict) else {}


def raw_sources(raw_text):
    for raw_line in raw_text.split("\n"):
        try:
            event = json.loads(raw_line)
        except ValueError:
            continue
        if isinstance(event, dict) and event.get("schema_version") == SCHEMA_VERSION:
            yield line_source(event)


def file_local_member_ref(sources):
    refs = {str(source.get("local_member_ref") or "").lower() for source in sources} - {""}
    ref = refs.pop() if len(refs) == 1 else ""
    return ref if LOCAL_MEMBER_REF_PATTERN.fullmatch(ref) else ""


def backfill_source_local_member_refs(apps, _schema_editor):
    AuditFile = apps.get_model("forensics", "AuditFile")

    # Collect ids first rather than update the table while iterating it.
    file_ids = list(
        AuditFile.objects.filter(
            validation_status="valid",
            source_local_member_ref="",
            raw_text__contains="local_member_ref",
        ).values_list("id", flat=True)
    )
    # Uploads reach 64 MiB, so hold one raw body at a time.
    for file_id in file_ids:
        raw_text = AuditFile.objects.values_list("raw_text", flat=True).get(id=file_id)
        ref = file_local_member_ref(raw_sources(raw_text))
        if ref:
            AuditFile.objects.filter(id=file_id).update(source_local_member_ref=ref)


class Migration(migrations.Migration):
    # Each update commits on its own; the backfill is idempotent if interrupted.
    atomic = False

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
