from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import transaction

from forensics.models import AnalysisRun, AuditEvent, AuditFile, AuditGroup

CONFIRM_FLAG = "--confirm-delete-audit-data"


class Command(BaseCommand):
    help = (
        "Delete preserved audit uploads, raw events, group workspaces, projections, "
        "and saved reports while preserving users and upload tokens."
    )

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Print table counts without deleting anything.",
        )
        parser.add_argument(
            "--confirm-delete-audit-data",
            action="store_true",
            help="Required to perform the destructive purge.",
        )

    def handle(self, *args, **options):
        before_counts = audit_data_counts()
        self.stdout.write("Audit data before purge: " + format_counts(before_counts))

        if options["dry_run"]:
            self.stdout.write(self.style.WARNING("Dry run only; no audit data was deleted."))
            return

        if not options["confirm_delete_audit_data"]:
            raise CommandError(
                f"Refusing to delete audit data without {CONFIRM_FLAG}. "
                "Run with --dry-run first to inspect current counts."
            )

        with transaction.atomic():
            # AuditFile is the raw-evidence root: deleting it cascades to
            # AuditEvent rows. AuditEvent.group uses SET_NULL, so deleting groups
            # first would strand raw events instead of purging them.
            AuditFile.objects.all().delete()
            # AuditGroup cascades to projections and saved reports.
            AuditGroup.objects.all().delete()

        after_counts = audit_data_counts()
        self.stdout.write(self.style.SUCCESS("Audit data purge complete."))
        self.stdout.write("Audit data after purge: " + format_counts(after_counts))


def audit_data_counts() -> dict[str, int]:
    return {
        "audit_files": AuditFile.objects.count(),
        "audit_events": AuditEvent.objects.count(),
        "audit_groups": AuditGroup.objects.count(),
        "saved_reports": AnalysisRun.objects.count(),
    }


def format_counts(counts: dict[str, int]) -> str:
    return ", ".join(f"{name}={count}" for name, count in counts.items())
