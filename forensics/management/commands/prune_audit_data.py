from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import connection
from django.utils import timezone

from forensics.models import AuditEvent, AuditFile, AuditGroup, UploadRejection
from forensics.projections import rebuild_group_projections

# PostgreSQL reclaims disk space from deleted raw_text/event rows only after a
# VACUUM. Scope it to the two heavy tables rather than the whole database, and
# only after an actual prune, so a no-op startup stays fast. VACUUM cannot run
# inside a transaction block; the delete above commits per batch in autocommit,
# so this executes in autocommit mode too. On non-Postgres backends (e.g.
# SQLite in dev) this is a no-op.
VACUUM_TABLES = ("forensics_auditfile", "forensics_auditevent")

# Keep each delete bounded: a 50 MiB raw_text row will not be held in a single
# DELETE statement alongside thousands of siblings.
DELETE_BATCH_SIZE = 200


class Command(BaseCommand):
    help = (
        "Delete audit evidence (uploaded files and their events) and recorded upload "
        "rejections older than the retention window, and rebuild projections for "
        "affected groups. "
        "Retention defaults to settings.GOGGLES_AUDIT_RETENTION_DAYS (14 days); "
        "override with --retention-days."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--retention-days",
            type=int,
            metavar="N",
            help="Keep evidence younger than this many days (default: the setting).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report how much would be pruned without deleting anything.",
        )

    def handle(self, *args, **options):
        retention_days = options["retention_days"]
        if retention_days is None:
            retention_days = settings.GOGGLES_AUDIT_RETENTION_DAYS
        if retention_days <= 0:
            raise CommandError("retention-days must be a positive integer.")
        cutoff = timezone.now() - timedelta(days=retention_days)

        stale_file_ids = list(
            AuditFile.objects.defer("raw_text", "user_agent")
            .filter(created_at__lt=cutoff)
            .values_list("id", flat=True)
        )
        # Rejection rows carry a source IP and user agent, so they age out on
        # the same window as the evidence they failed to become.
        stale_rejections = UploadRejection.objects.filter(created_at__lt=cutoff)
        stale_rejection_count = stale_rejections.count()
        if not stale_file_ids and not stale_rejection_count:
            self.stdout.write(
                f"Retention window of {retention_days} day(s): nothing to prune. "
                f"Cutoff was {cutoff:%Y-%m-%d %H:%M:%S}."
            )
            return

        stale_group_ids = touched_group_ids(stale_file_ids)
        self.stdout.write(
            f"Retention window of {retention_days} day(s): "
            f"{len(stale_file_ids)} audit file(s) and {stale_rejection_count} upload "
            f"rejection(s) exceed it (cutoff {cutoff:%Y-%m-%d %H:%M:%S})."
        )

        if options["dry_run"]:
            self.stdout.write(
                "Would prune stale evidence touching "
                f"{len(stale_group_ids)} group(s). Dry run only; nothing deleted."
            )
            return

        stale_rejections.delete()
        if stale_file_ids:
            delete_files(stale_file_ids)
            vacuum_audit_data()
        for group in AuditGroup.objects.filter(id__in=sorted(stale_group_ids)):
            # Rebuild each touched group from its surviving evidence so derived
            # projections stop referencing now-deleted events.
            rebuild_group_projections(group)

        self.stdout.write(
            self.style.SUCCESS(
                f"Pruned {len(stale_file_ids)} audit file(s) and {stale_rejection_count} "
                f"upload rejection(s); rebuilt projections for {len(stale_group_ids)} group(s)."
            )
        )


def touched_group_ids(file_ids: list[int]) -> set[int]:
    """Groups linked to the files either via the upload-bound M2M or events."""
    group_ids = set()
    for audit_file in AuditFile.objects.filter(id__in=file_ids).only("id"):
        group_ids.update(audit_file.groups.values_list("id", flat=True))
        group_ids.update(
            AuditEvent.objects.filter(audit_file=audit_file, group__isnull=False).values_list(
                "group_id", flat=True
            )
        )
    return group_ids


def delete_files(file_ids: list[int]) -> None:
    # AuditFile deletion cascades to every stored AuditEvent for that file; the
    # event rows are the bulk of the disk usage.
    for start in range(0, len(file_ids), DELETE_BATCH_SIZE):
        batch = file_ids[start : start + DELETE_BATCH_SIZE]
        AuditFile.objects.filter(id__in=batch).delete()


def vacuum_audit_data() -> None:
    if connection.vendor != "postgresql":
        return
    with connection.cursor() as cursor:
        for table in VACUUM_TABLES:
            cursor.execute(f"VACUUM ANALYZE {table}")
