"""Transaction-local upload safeguards; never change read/retention deadlines."""

import hashlib

from django.conf import settings
from django.db import connection


class IngestionBusy(Exception):
    pass


def begin_ingestion(engine_ids):
    """Called inside atomic(), before any evidence or group write.

    Recorder locks protect cross-file line deduplication, including ungrouped
    source events. They also prevent identical files waiting on the unique hash
    while their first request projects. Hash collisions only cause a retry.
    Transaction locks release on commit, rollback, or connection loss.
    """
    if connection.vendor != "postgresql":
        return
    if connection.pg_version < 170000:
        raise RuntimeError("Bounded ingestion requires PostgreSQL 17 or later")
    with connection.cursor() as cursor:
        for name, value in (
            ("lock_timeout", settings.GOGGLES_INGEST_LOCK_TIMEOUT_MS),
            ("statement_timeout", settings.GOGGLES_INGEST_STATEMENT_TIMEOUT_MS),
            ("idle_in_transaction_session_timeout", settings.GOGGLES_INGEST_IDLE_TIMEOUT_MS),
            ("transaction_timeout", settings.GOGGLES_INGEST_TRANSACTION_TIMEOUT_MS),
        ):
            cursor.execute("SELECT set_config(%s, %s, true)", [name, f"{value}ms"])
        for engine_id in sorted(set(engine_ids)):
            key = int.from_bytes(
                hashlib.sha256(f"goggles-ingest-recorder:{engine_id}".encode()).digest()[:8],
                signed=True,
            )
            cursor.execute("SELECT pg_try_advisory_xact_lock(%s)", [key])
            if not cursor.fetchone()[0]:
                raise IngestionBusy
