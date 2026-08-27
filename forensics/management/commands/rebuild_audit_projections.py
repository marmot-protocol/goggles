from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import transaction

from forensics.models import (
    AuditEvent,
    AuditFile,
    AuditGroup,
    ConvergenceCandidate,
    ConvergenceRuleEvaluation,
    ConvergenceRun,
    DeliveryArtifact,
    DeliveryObservation,
    EpochStateTransition,
    NetworkObservation,
    RecipientExpectation,
    StateDelta,
)
from forensics.projections import PROJECTION_AUDIT_SCHEMA_VERSIONS, rebuild_group_projections

PROJECTION_MODELS = (
    DeliveryArtifact,
    DeliveryObservation,
    RecipientExpectation,
    NetworkObservation,
    ConvergenceRun,
    ConvergenceCandidate,
    ConvergenceRuleEvaluation,
    StateDelta,
    EpochStateTransition,
)


class Command(BaseCommand):
    help = "Drop and rebuild derived audit-log projections from preserved raw evidence."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--group",
            action="append",
            dest="groups",
            metavar="SLUG_OR_REF",
            help="Rebuild projections for one group slug or group ref. Repeat for multiple groups.",
        )
        parser.add_argument(
            "--audit-file-id",
            action="append",
            dest="audit_file_ids",
            type=int,
            metavar="ID",
            help="Rebuild projections for groups touched by one audit file. Repeat as needed.",
        )

    def handle(self, *args, **options):
        groups = self.selected_groups(options["groups"], options["audit_file_ids"])
        for group in groups:
            with transaction.atomic():
                rebuild_group_projections(group)
        after_counts = projection_counts()

        self.stdout.write(
            self.style.SUCCESS(
                "Rebuilt audit projections for "
                f"{len(groups)} group(s): {format_projection_counts(after_counts)}"
            )
        )

    def selected_groups(
        self,
        group_selectors: list[str] | None,
        audit_file_ids: list[int] | None,
    ) -> list[AuditGroup]:
        if group_selectors:
            return groups_from_selectors(group_selectors)
        if audit_file_ids:
            return groups_from_audit_file_ids(audit_file_ids)
        return groups_with_projection_evidence()


def groups_from_selectors(selectors: list[str]) -> list[AuditGroup]:
    groups = []
    seen_ids = set()
    for selector in selectors:
        try:
            group = AuditGroup.objects.get(slug=selector)
        except AuditGroup.DoesNotExist:
            try:
                group = AuditGroup.objects.get(group_ref=selector)
            except AuditGroup.DoesNotExist as exc:
                raise CommandError(
                    "No audit group matched one of the requested selectors."
                ) from exc
        if group.id not in seen_ids:
            seen_ids.add(group.id)
            groups.append(group)
    return groups


def groups_from_audit_file_ids(audit_file_ids: list[int]) -> list[AuditGroup]:
    groups = []
    seen_group_ids = set()
    for audit_file_id in audit_file_ids:
        try:
            audit_file = AuditFile.objects.defer("raw_text", "user_agent").get(id=audit_file_id)
        except AuditFile.DoesNotExist as exc:
            raise CommandError("No audit file matched one of the requested ids.") from exc
        group_ids = set(audit_file.groups.values_list("id", flat=True))
        group_ids.update(
            AuditEvent.objects.filter(audit_file=audit_file, group__isnull=False).values_list(
                "group_id", flat=True
            )
        )
        for group in AuditGroup.objects.filter(id__in=group_ids).order_by("id"):
            if group.id not in seen_group_ids:
                seen_group_ids.add(group.id)
                groups.append(group)
    return groups


def groups_with_projection_evidence() -> list[AuditGroup]:
    group_ids = (
        AuditEvent.objects.filter(
            parse_status=AuditEvent.STATUS_VALID,
            schema_version__in=PROJECTION_AUDIT_SCHEMA_VERSIONS,
            group__isnull=False,
        )
        .values_list("group_id", flat=True)
        .distinct()
    )
    return list(AuditGroup.objects.filter(id__in=group_ids).order_by("id"))


def projection_counts() -> dict[str, int]:
    return {model.__name__: model.objects.count() for model in PROJECTION_MODELS}


def format_projection_counts(counts: dict[str, int]) -> str:
    return ", ".join(f"{name}={count}" for name, count in counts.items())
