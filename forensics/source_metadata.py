"""Resolve retained v4 source evidence across segments of the same recorder.

Never join by engine alone: a later app launch may have a different version.
Missing session/account identity is unknown, not permission to borrow metadata.
"""

from django.db.models import Q
from django.db.models.fields.json import KeyTextTransform
from django.db.models.functions import Substr

from .audit_schema import SCHEMA_VERSION
from .models import AuditEvent, AuditFile

SOURCE_KEYS = ("device_id", "hardware_model", "platform", "app_version", "upload_trigger")


def session_source_contexts(sessions):
    sessions = sorted({tuple(session) for session in sessions if all(session)})
    # Bound SQL parameters/expression depth even for long-lived groups.
    for offset in range(0, len(sessions), 100):
        matches = Q()
        for engine_id, account_ref, recorder_session_id in sessions[offset : offset + 100]:
            matches |= Q(
                engine_id=engine_id,
                account_ref=account_ref,
                recorder_session_id=recorder_session_id,
            )
        rows = (
            AuditEvent.objects.filter(
                matches,
                schema_version=SCHEMA_VERSION,
                parse_status=AuditEvent.STATUS_VALID,
                audit_file__validation_status=AuditFile.STATUS_VALID,
            )
            .exclude(context_source={})
            .annotate(
                **{
                    "source_" + key: Substr(
                        KeyTextTransform(key, "context_source"),
                        1,
                        AuditFile._meta.get_field("source_" + key).max_length,
                    )
                    for key in SOURCE_KEYS
                }
            )
            .order_by("seq", "id")
            .values("engine_id", *("source_" + key for key in SOURCE_KEYS))
            .iterator(chunk_size=500)
        )
        for row in rows:
            yield row["engine_id"], {key: row["source_" + key] for key in SOURCE_KEYS}
