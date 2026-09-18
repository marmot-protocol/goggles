"""Shared validity rules for retained audit evidence."""

from django.db.models import Q

STRUCTURAL_QUARANTINE_ERRORS = (
    "audit log contains multiple engine_ids",
    "audit log contains multiple account_refs",
)


def structural_quarantine_exclusion(field_prefix: str = "") -> Q:
    """The ``Q`` that excludes events belonging to a *structurally* quarantined
    file (multi-engine / multi-account uploads), the single definition shared by
    every "events that count for a group" path.

    A file marked ``validation_status=INVALID`` for a non-structural reason
    (e.g. one malformed JSONL line) still contributes its ``parse_status=VALID``
    events to the group: those events are real evidence and are rendered in the
    timeline/tabs/export (goggles#80, commit ``0ac4442``). Only the structural
    quarantine errors above mean the *whole* file's engine/account attribution
    is untrustworthy and must be dropped wholesale.

    ``field_prefix`` adapts the predicate to the relation path of the caller:
    ``""`` for a queryset already rooted on ``AuditEvent``
    (``audit_file__validation_error``), or ``"audit_events__"`` for the
    reverse relation used when annotating ``AuditGroup``
    (``audit_events__audit_file__validation_error``).
    """
    predicate = Q()
    for error in STRUCTURAL_QUARANTINE_ERRORS:
        predicate &= ~Q(**{f"{field_prefix}audit_file__validation_error__icontains": error})
    return predicate
