"""Cross-process exclusion for the scheduled and manually invoked pruner."""

from contextlib import contextmanager

from django.core.management.base import CommandError
from django.db import connection

RETENTION_LOCK = 0x476F67676C657301


@contextmanager
def retention_lock():
    if connection.vendor != "postgresql":
        yield
        return
    # Session-scoped: do not hold a transaction open over the entire prune or
    # VACUUM. The scheduler waits for its child, and manual/extra schedulers
    # fail promptly instead of accumulating overlapping maintenance jobs.
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_try_advisory_lock(%s)", [RETENTION_LOCK])
        if not cursor.fetchone()[0]:
            raise CommandError("Another audit retention run is already active.")
    try:
        yield
    finally:
        if connection.is_usable():
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_unlock(%s)", [RETENTION_LOCK])
        else:
            connection.close()
