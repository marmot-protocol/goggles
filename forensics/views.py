from __future__ import annotations

import ipaddress

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.core.exceptions import RequestDataTooBig, TooManyFilesSent
from django.core.files.uploadhandler import FileUploadHandler
from django.core.paginator import Paginator
from django.db.models import Count, Max, Min, Prefetch, Q
from django.db.models.functions import Length, Substr
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.defaultfilters import slugify
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .analysis import (
    agent_state_export_for_group,
    audit_files_for_group,
    color_index,
    engine_initials,
    event_row,
    file_rows_for_group,
    group_list_rows,
    human_action_groups_for_group,
    structural_quarantine_exclusion,
    valid_events_for_group,
)
from .ingest import ingest_audit_log_bytes
from .models import (
    AnalysisRun,
    AuditEvent,
    AuditFile,
    AuditGroup,
    ConvergenceRun,
    DeliveryArtifact,
    DeliveryObservation,
    EpochStateTransition,
    NetworkObservation,
    RecipientExpectation,
    StateDelta,
    UploadToken,
)

UPLOAD_TOO_LARGE_ERROR = "audit log exceeds maximum upload size"
AUDIT_FILE_EVENT_PAGE_SIZE = 100
RAW_TEXT_PREVIEW_CHARS = 32 * 1024
GROUP_ENGINE_PREVIEW_LIMIT = 12
GROUP_DETAIL_TAB_EVENT_LIMIT = 100
GROUP_PROJECTION_API_DEFAULT_LIMIT = 500
GROUP_PROJECTION_API_MAX_LIMIT = 5_000
FULL_DATA_AUDIT_MODE = "full_data"
ERROR_SEVERITY_TOKENS = (
    "error",
    "failed",
    "failure",
    "reject",
    "rejected",
    "unrecoverable",
)
WARNING_SEVERITY_TOKENS = (
    "blocked",
    "missing",
    "partial",
    "rollback",
    "stale",
    "warning",
)
GROUP_EPOCH_FIELDS = (
    "epoch",
    "source_epoch",
    "to_epoch",
    "pending_epoch",
    "current_tip_epoch",
    "selected_tip_epoch",
)
GROUP_DETAIL_TAB_TEMPLATES = {
    "overview": "forensics/partials/group_overview.html",
    "delivery": "forensics/partials/group_delivery.html",
    "network": "forensics/partials/group_network.html",
    "convergence": "forensics/partials/group_convergence.html",
    "state": "forensics/partials/group_state.html",
    "evidence": "forensics/partials/group_evidence.html",
    "exports": "forensics/partials/group_exports.html",
}


def healthz(_request: HttpRequest):
    return JsonResponse({"status": "ok"})


@login_required
def group_list(request: HttpRequest):
    groups = group_list_rows()
    total_logs = AuditFile.objects.count()
    return render(
        request,
        "forensics/group_list.html",
        {"groups": groups, "total_logs": total_logs},
    )


@login_required
def upload_log_list(request: HttpRequest):
    audit_files = (
        AuditFile.objects.select_related("upload_token")
        .only(
            # Restrict to the columns the upload-log template actually renders so
            # Postgres/Django never transfers or instantiates the heavy
            # AuditFile.raw_text (or user_agent) for the recent-uploads list.
            # Adding a new column to upload_log_list.html means adding it here.
            "created_at",
            "byte_size",
            "validation_status",
            "validation_error",
            "source_name",
            "source_account_label",
            "source_device_label",
            "source_platform",
            "source_app_version",
            "valid_event_count",
            "invalid_event_count",
            "duplicate_event_count",
            "engine_ids",
            "group_refs",
            "source_ip",
            # select_related("upload_token") joins these columns; list them so the
            # related row is populated without a deferred-field follow-up query.
            "upload_token__name",
            "upload_token__token_prefix",
        )
        # Count the explicit AuditFile.groups M2M (#37) rather than inferring
        # links from stored AuditEvent rows (events__group), so duplicate-heavy
        # uploads whose group events were all deduplicated away still report
        # their linked-group count correctly. The annotation does not need a
        # matching .only() entry — it is computed, not a deferred column.
        .annotate(group_count=Count("groups", distinct=True))
        .order_by("-created_at", "-id")[:100]
    )
    stats = AuditFile.objects.aggregate(
        total=Count("id"),
        valid=Count("id", filter=Q(validation_status=AuditFile.STATUS_VALID)),
        invalid=Count("id", filter=Q(validation_status=AuditFile.STATUS_INVALID)),
    )
    # The template only renders latest_upload.created_at, so restrict this row to
    # that column too — otherwise .first() loads the full row (incl. raw_text) for
    # one potentially near-limit upload. See #39.
    latest_upload = AuditFile.objects.only("created_at").order_by("-created_at", "-id").first()
    return render(
        request,
        "forensics/upload_log_list.html",
        {
            "audit_files": audit_files,
            "stats": stats,
            "latest_upload": latest_upload,
        },
    )


@login_required
def group_detail(request: HttpRequest, slug: str):
    group = get_object_or_404(AuditGroup, slug=slug)
    return render(
        request,
        "forensics/group_detail.html",
        {
            "group": group,
            **group_detail_shell_context(group),
        },
    )


def valid_group_event_queryset(group: AuditGroup):
    # The canonical "events that count for this group": valid-parse events,
    # excluding only structurally-quarantined files. This MUST match
    # analysis.valid_events_for_group so the header summary, tab-count badges and
    # engine preview (which read this queryset) agree with the timeline/tab
    # bodies and the agent export (which read valid_events_for_group). See
    # goggles#103 — a file marked INVALID for a non-structural reason still
    # contributes its valid events to both.
    return AuditEvent.objects.filter(
        structural_quarantine_exclusion(),
        group=group,
        parse_status=AuditEvent.STATUS_VALID,
    )


def group_detail_shell_context(group: AuditGroup) -> dict:
    return {
        **group_summary_context(group),
        "overview": group_overview_context(group),
    }


def group_summary_context(group: AuditGroup) -> dict:
    valid_events = valid_group_event_queryset(group)
    event_stats = valid_events.aggregate(
        event_count=Count("id"),
        engine_count=Count("engine_id", filter=~Q(engine_id=""), distinct=True),
        group_count=Count("group_ref", filter=~Q(group_ref=""), distinct=True),
        message_count=Count("msg_id", filter=~Q(msg_id=""), distinct=True),
    )
    file_count = AuditFile.objects.filter(groups=group).count()
    invalid_event_count = AuditEvent.objects.filter(
        group=group, parse_status=AuditEvent.STATUS_INVALID
    ).count()
    epoch_count = group_epoch_count(valid_events)
    engine_preview = group_engine_rows(
        group,
        valid_events=valid_events,
        limit=GROUP_ENGINE_PREVIEW_LIMIT,
    )
    engine_count = event_stats["engine_count"] or 0
    delivery_count = DeliveryArtifact.objects.filter(group=group).count()
    network_count = NetworkObservation.objects.filter(group=group).count()
    convergence_count = ConvergenceRun.objects.filter(group=group).count()
    raw_message_count = event_stats["message_count"] or 0
    state_count = (
        StateDelta.objects.filter(group=group).count()
        + EpochStateTransition.objects.filter(group=group).count()
    )
    return {
        "summary": {
            "file_count": file_count,
            "event_count": event_stats["event_count"],
            "invalid_event_count": invalid_event_count,
            "engine_count": engine_count,
            "group_count": event_stats["group_count"],
            "message_count": raw_message_count,
            "raw_message_count": raw_message_count,
            "delivery_count": delivery_count,
            "network_count": network_count,
            "convergence_count": convergence_count,
            "state_count": state_count,
        },
        "timeline_summary": {
            "engines": engine_preview,
            "engine_overflow_count": max(engine_count - len(engine_preview), 0),
            "epoch_count": epoch_count,
        },
        "tab_counts": {
            "overview": event_stats["event_count"],
            "delivery": delivery_count,
            "network": network_count,
            "convergence": convergence_count,
            "state": state_count,
            "evidence": file_count,
            "exports": "",
        },
        "overview": group_overview_context(group),
        "tab_event_limit": GROUP_DETAIL_TAB_EVENT_LIMIT,
    }


def group_epoch_count(valid_events) -> int:
    epoch_queries = [
        valid_events.exclude(**{f"{field}__isnull": True}).order_by().values_list(field, flat=True)
        for field in GROUP_EPOCH_FIELDS
    ]
    return epoch_queries[0].union(*epoch_queries[1:]).count()


ENGINE_SOURCE_FIELD_MAP = (
    ("account_labels", "source_account_label", "account_label"),
    ("device_labels", "source_device_label", "device_label"),
    ("device_ids", "source_device_id", "device_id"),
    ("device_names", "source_device_name", "device_name"),
    ("platforms", "source_platform", "platform"),
    ("app_versions", "source_app_version", "app_version"),
    ("upload_triggers", "source_upload_trigger", "upload_trigger"),
    ("account_pubkeys_hex", "source_account_pubkey_hex", "account_pubkey_hex"),
    ("account_npubs", "source_account_npub", "account_npub"),
)


def group_engine_rows(
    group: AuditGroup,
    *,
    valid_events=None,
    limit: int | None = None,
) -> list[dict]:
    valid_events = valid_events if valid_events is not None else valid_group_event_queryset(group)
    rows = (
        valid_events.exclude(engine_id="")
        .values("engine_id")
        .annotate(
            event_count=Count("id"),
            first_event_ms=Min("wall_time_ms"),
            last_event_ms=Max("wall_time_ms"),
            account_ref=Min("account_ref"),
        )
        .order_by("first_event_ms", "engine_id")
    )
    if limit is not None:
        rows = rows[:limit]

    source_values = engine_source_values(group)
    engines = []
    for idx, row in enumerate(rows):
        engine_id = row["engine_id"]
        metadata = source_values.get(engine_id, empty_engine_source_metadata())
        display_label = engine_display_label(metadata, engine_id)
        account_refs = sorted({row["account_ref"], *metadata.get("account_refs", [])} - {None, ""})
        account_ref = row["account_ref"] or (account_refs[0] if account_refs else "")
        engines.append(
            {
                "engine_id": engine_id,
                "account_ref": account_ref,
                "account_refs": account_refs,
                "label": display_label,
                "source_metadata": metadata,
                "color_index": color_index(engine_id),
                "first_event_ms": row["first_event_ms"],
                "last_event_ms": row["last_event_ms"],
                "event_count": row["event_count"],
                "sensitivity": sensitivity_payload(engine_sensitive_field_paths(metadata)),
                "idx": idx,
                "short": engine_id[:8],
                "initials": engine_initials(display_label, engine_id),
            }
        )
    return engines


def engine_source_values(group: AuditGroup) -> dict[str, dict[str, list[str]]]:
    values_by_engine: dict[str, dict[str, set[str]]] = {}
    events = (
        valid_group_event_queryset(group)
        .exclude(engine_id="")
        .select_related("audit_file")
        .only(
            "engine_id",
            "account_ref",
            "context_source",
            "audit_file__source_account_label",
            "audit_file__source_device_label",
            "audit_file__source_device_id",
            "audit_file__source_device_name",
            "audit_file__source_platform",
            "audit_file__source_app_version",
            "audit_file__source_upload_trigger",
            "audit_file__source_account_pubkey_hex",
            "audit_file__source_account_npub",
        )
    )
    for event in events:
        engine_values = values_by_engine.setdefault(
            event.engine_id,
            {key: set() for key, _file_field, _context_key in ENGINE_SOURCE_FIELD_MAP}
            | {"account_refs": set()},
        )
        if event.account_ref:
            engine_values["account_refs"].add(event.account_ref)
        context_source = event.context_source if isinstance(event.context_source, dict) else {}
        for key, file_field, context_key in ENGINE_SOURCE_FIELD_MAP:
            append_engine_source_value(
                engine_values[key], getattr(event.audit_file, file_field, "")
            )
            append_engine_source_value(engine_values[key], context_source.get(context_key))

    return {
        engine_id: {key: sorted(values) for key, values in engine_values.items()}
        for engine_id, engine_values in values_by_engine.items()
    }


def append_engine_source_value(values: set[str], value) -> None:
    if isinstance(value, str) and value:
        values.add(value)


def empty_engine_source_metadata() -> dict[str, list[str]]:
    return {key: [] for key in ("account_refs", *(field[0] for field in ENGINE_SOURCE_FIELD_MAP))}


def engine_display_label(metadata: dict[str, list[str]], engine_id: str) -> str:
    account = first_metadata_value(metadata, "account_labels")
    device = first_metadata_value(metadata, "device_names") or first_metadata_value(
        metadata,
        "device_labels",
    )
    platform = first_metadata_value(metadata, "platforms")
    parts = [part for part in (account, device, platform) if part]
    return " / ".join(parts) or engine_id[:8]


def first_metadata_value(metadata: dict[str, list[str]], key: str) -> str:
    values = metadata.get(key) or []
    return values[0] if values else ""


def engine_sensitive_field_paths(metadata: dict[str, list[str]]) -> list[str]:
    field_paths = ["engine_id"]
    if metadata.get("account_refs"):
        field_paths.append("account_refs")
    if metadata.get("device_ids"):
        field_paths.append("source_metadata.device_ids")
    if metadata.get("account_pubkeys_hex"):
        field_paths.append("source_metadata.account_pubkeys_hex")
    if metadata.get("account_npubs"):
        field_paths.append("source_metadata.account_npubs")
    return field_paths


def group_overview_context(group: AuditGroup) -> dict:
    audit_files = list(audit_files_for_group(group)[:GROUP_DETAIL_TAB_EVENT_LIMIT])
    engines = group_engine_rows(group, limit=GROUP_DETAIL_TAB_EVENT_LIMIT)
    action_filters = {**default_action_filters(), "limit": 5}
    action_groups = action_groups_for_api(group, action_filters)
    engine_count = (
        valid_group_event_queryset(group)
        .exclude(engine_id="")
        .values("engine_id")
        .distinct()
        .count()
    )
    mode_change_events = list(
        audit_data_mode_change_queryset(group).order_by("-wall_time_ms", "-id")[
            :GROUP_DETAIL_TAB_EVENT_LIMIT
        ]
    )
    mode_change_count = audit_data_mode_change_queryset(group).count()
    network_by_phase = list(
        NetworkObservation.objects.filter(group=group)
        .values("phase")
        .annotate(count=Count("id"))
        .order_by("-count", "phase")[:12]
    )
    delivery_by_kind = list(
        DeliveryArtifact.objects.filter(group=group)
        .values("artifact_kind")
        .annotate(count=Count("id"))
        .order_by("-count", "artifact_kind")[:12]
    )
    convergence_by_phase = list(
        ConvergenceRun.objects.filter(group=group)
        .values("phase")
        .annotate(count=Count("id"))
        .order_by("-count", "phase")[:12]
    )
    state_by_kind = list(
        StateDelta.objects.filter(group=group)
        .values("change_kind")
        .annotate(count=Count("id"))
        .order_by("-count", "change_kind")[:12]
    )
    return {
        "audit_files": file_rows_for_group(audit_files, group),
        "audit_files_limited": len(audit_files) == GROUP_DETAIL_TAB_EVENT_LIMIT,
        "engines": engines,
        "engines_limited": engine_count > len(engines),
        "audit_data_mode_changes": [
            audit_data_mode_change_payload(event) for event in mode_change_events
        ],
        "audit_data_mode_changes_limited": mode_change_count > len(mode_change_events),
        "network_by_phase": network_by_phase,
        "delivery_by_kind": delivery_by_kind,
        "convergence_by_phase": convergence_by_phase,
        "state_by_kind": state_by_kind,
        "audit_data_modes": audit_data_modes_for_group(group),
        "classification": group_classification(group),
        "action_origin_counts": action_origin_counts(group),
        "recent_user_actions": action_attribution_section(action_groups, "user", action_filters),
        "recent_system_attribution": action_attribution_section(
            action_groups,
            "system",
            action_filters,
        ),
        "recent_other_attribution": action_attribution_section(
            action_groups,
            "other",
            action_filters,
        ),
    }


def audit_data_modes_for_group(group: AuditGroup) -> list[dict]:
    counts: dict[str, int] = {}
    for modes in AuditFile.objects.filter(groups=group).values_list("audit_data_modes", flat=True):
        for mode in modes or []:
            counts[mode] = counts.get(mode, 0) + 1
    return [{"mode": mode, "count": count} for mode, count in sorted(counts.items())]


@login_required
def group_tab(request: HttpRequest, slug: str, tab: str):
    template_name = GROUP_DETAIL_TAB_TEMPLATES.get(tab)
    if template_name is None:
        raise Http404("unknown group detail tab")
    group = get_object_or_404(AuditGroup, slug=slug)
    return render(request, template_name, group_tab_context(group, tab))


def group_tab_context(group: AuditGroup, tab: str) -> dict:
    if tab == "overview":
        return {"group": group, "overview": group_overview_context(group)}
    if tab == "evidence":
        audit_files = list(audit_files_for_group(group))
        return {
            "group": group,
            "audit_files": file_rows_for_group(audit_files, group),
            "recent_events": recent_evidence_rows(group),
            "tab_event_limit": GROUP_DETAIL_TAB_EVENT_LIMIT,
        }
    if tab == "delivery":
        artifacts, has_more = limited_tab_events(
            delivery_artifact_queryset()
            .filter(group=group)
            .order_by("first_seen_ms", "artifact_id")
        )
        delivery_engines = group_engine_rows(group)
        attach_delivery_matrices(artifacts, group, engines=delivery_engines)
        return {
            "group": group,
            "artifacts": artifacts,
            "delivery_engines": delivery_engines,
            "artifacts_limited": has_more,
            "tab_event_limit": GROUP_DETAIL_TAB_EVENT_LIMIT,
        }
    if tab == "network":
        observations, has_more = limited_tab_events(
            NetworkObservation.objects.filter(group=group)
            .select_related("artifact", "audit_event")
            .order_by("wall_time_ms", "engine_id", "id")
        )
        return {
            "group": group,
            "observations": observations,
            "observations_limited": has_more,
            "tab_event_limit": GROUP_DETAIL_TAB_EVENT_LIMIT,
        }
    if tab == "convergence":
        runs, has_more = limited_tab_events(
            ConvergenceRun.objects.filter(group=group)
            .prefetch_related("candidates", "rule_evaluations", "evidence_events")
            .order_by("started_at_ms", "engine_id", "run_id")
        )
        attach_decisive_rules(runs)
        return {
            "group": group,
            "runs": runs,
            "runs_limited": has_more,
            "tab_event_limit": GROUP_DETAIL_TAB_EVENT_LIMIT,
        }
    if tab == "state":
        deltas, deltas_has_more = limited_tab_events(
            StateDelta.objects.filter(group=group).select_related("audit_event")
        )
        transitions, transitions_has_more = limited_tab_events(
            EpochStateTransition.objects.filter(group=group).select_related("audit_event")
        )
        return {
            "group": group,
            "state_deltas": deltas,
            "epoch_transitions": transitions,
            "state_deltas_limited": deltas_has_more,
            "epoch_transitions_limited": transitions_has_more,
            "tab_event_limit": GROUP_DETAIL_TAB_EVENT_LIMIT,
        }
    if tab == "exports":
        return {
            "group": group,
            "summary": group_summary_context(group)["summary"],
            "classification": group_classification(group),
            "saved_reports": list(group.analysis_runs.select_related("created_by")[:20]),
        }
    raise Http404("unknown group detail tab")


@login_required
def account_investigation(request: HttpRequest, account_ref: str):
    groups = investigation_group_rows(
        AuditGroup.objects.all(),
        subject_filter=Q(audit_events__account_ref=account_ref),
    )
    return render(
        request,
        "forensics/subject_investigation.html",
        {
            "subject_kind": "Account",
            "subject_ref": account_ref,
            "groups": groups,
            "api_url_name": "api-account-groups",
        },
    )


@login_required
def engine_investigation(request: HttpRequest, engine_id: str):
    groups = investigation_group_rows(
        AuditGroup.objects.all(),
        subject_filter=Q(audit_events__engine_id=engine_id),
    )
    return render(
        request,
        "forensics/subject_investigation.html",
        {
            "subject_kind": "Engine",
            "subject_ref": engine_id,
            "groups": groups,
            "api_url_name": "api-engine-groups",
        },
    )


def investigation_group_rows(queryset, *, subject_filter: Q) -> list[AuditGroup]:
    annotated = queryset.annotate(
        subject_event_count=Count("audit_events", filter=subject_filter),
        subject_engine_count=Count(
            "audit_events__engine_id",
            filter=subject_filter & ~Q(audit_events__engine_id=""),
            distinct=True,
        ),
        subject_account_count=Count(
            "audit_events__account_ref",
            filter=subject_filter & ~Q(audit_events__account_ref=""),
            distinct=True,
        ),
        subject_first_ms=Min("audit_events__wall_time_ms", filter=subject_filter),
        subject_last_ms=Max("audit_events__wall_time_ms", filter=subject_filter),
    )
    return list(annotated.filter(subject_event_count__gt=0).order_by("-subject_last_ms", "slug"))


def limited_tab_events(queryset, limit: int = GROUP_DETAIL_TAB_EVENT_LIMIT):
    rows = list(queryset[: limit + 1])
    return rows[:limit], len(rows) > limit


def attach_decisive_rules(runs: list[ConvergenceRun]) -> None:
    for run in runs:
        run.decisive_rules = [rule for rule in run.rule_evaluations.all() if rule.decisive]


def recent_evidence_rows(group: AuditGroup) -> list[dict]:
    events = list(
        AuditEvent.objects.filter(group=group)
        .select_related("audit_file")
        .order_by("-wall_time_ms", "-id")[:GROUP_DETAIL_TAB_EVENT_LIMIT]
    )
    rows = []
    for event in events:
        row = event_row(event)
        row["audit_file_id"] = event.audit_file_id
        row["line_hash"] = event.line_hash
        rows.append(row)
    return rows


@login_required
def group_agent_export(request: HttpRequest, slug: str):
    group = get_object_or_404(AuditGroup, slug=slug)
    audit_files = list(audit_files_for_group(group))
    events = list(valid_events_for_group(group, include_export_fields=True))
    pretty = request.GET.get("pretty", "").lower() in {"1", "true", "yes"}
    json_dumps_params = {"sort_keys": True}
    if pretty:
        json_dumps_params["indent"] = 2
    else:
        json_dumps_params["separators"] = (",", ":")
    payload = agent_state_export_for_group(group, events, audit_files)
    payload["derived_projections"] = group_projection_payload(group, filters=default_api_filters())
    response = JsonResponse(payload, json_dumps_params=json_dumps_params)
    response["Content-Disposition"] = f'attachment; filename="{group.slug}-agent-state.json"'
    return response


@login_required
@require_POST
def create_saved_report(request: HttpRequest, slug: str):
    group = get_object_or_404(AuditGroup, slug=slug)
    title = (request.POST.get("title") or "Group forensic snapshot").strip()[:160]
    notes = (request.POST.get("notes") or "").strip()
    projection = group_projection_payload(group, filters=default_api_filters())
    saved = AnalysisRun.objects.create(
        group=group,
        created_by=request.user,
        title=title,
        notes=notes,
        report_json={
            "schema_version": "goggles-saved-investigation/v1",
            "saved_at": timezone.now().isoformat(),
            "title": title,
            "notes": notes,
            "projection": projection,
        },
    )
    messages.success(request, "Saved investigation report.")
    return redirect("saved-report-detail", pk=saved.pk)


@login_required
def saved_report_detail(request: HttpRequest, pk: int):
    report = get_object_or_404(
        AnalysisRun.objects.select_related("group", "created_by"),
        pk=pk,
    )
    return render(
        request,
        "forensics/saved_report_detail.html",
        {
            "report": report,
            "snapshot_summary": saved_report_projection_summary(report.report_json),
        },
    )


@login_required
def saved_report_json(request: HttpRequest, pk: int):
    report = get_object_or_404(AnalysisRun, pk=pk)
    return JsonResponse(
        report.report_json,
        json_dumps_params={"separators": (",", ":")},
    )


SAVED_REPORT_PROJECTION_SECTIONS = (
    ("Delivery artifacts", ("delivery_artifacts",), ("delivery_artifacts",)),
    ("Network observations", ("network_observations",), ("network_observations",)),
    ("Convergence runs", ("convergence_runs",), ("convergence_runs",)),
    ("State deltas", ("state_deltas",), ("state_deltas",)),
    (
        "Epoch state transitions",
        ("epoch_state_transitions",),
        ("epoch_state_transitions",),
    ),
    (
        "Audit mode changes",
        ("audit_data_mode_changes",),
        ("audit_data_mode_changes",),
    ),
    (
        "User actions",
        ("action_attribution", "user_actions"),
        ("action_attribution", "user_actions"),
    ),
    (
        "System attribution",
        ("action_attribution", "system_attribution"),
        ("action_attribution", "system_attribution"),
    ),
    (
        "Other attribution",
        ("action_attribution", "other_attribution"),
        ("action_attribution", "other_attribution"),
    ),
)


def saved_report_projection_summary(report_json: dict) -> list[dict]:
    projection = report_json.get("projection") if isinstance(report_json, dict) else {}
    if not isinstance(projection, dict):
        projection = {}
    pagination = projection.get("pagination")
    if not isinstance(pagination, dict):
        pagination = {}
    rows = []
    for label, data_path, pagination_path in SAVED_REPORT_PROJECTION_SECTIONS:
        values = nested_json_value(projection, data_path)
        page = nested_json_value(pagination, pagination_path)
        rows.append(
            {
                "label": label,
                "count": len(values) if isinstance(values, list) else 0,
                "has_more": bool(page.get("has_more")) if isinstance(page, dict) else False,
                "next_offset": page.get("next_offset") if isinstance(page, dict) else None,
            }
        )
    return rows


def nested_json_value(value: dict, path: tuple[str, ...]):
    current = value
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


@login_required
def api_group_list(request: HttpRequest):
    groups = group_list_rows()
    return JsonResponse(
        {
            "schema_version": "goggles-groups/v1",
            "groups": [group_list_api_payload(group) for group in groups],
        },
        json_dumps_params={"separators": (",", ":")},
    )


@login_required
def api_group_detail(request: HttpRequest, slug: str):
    group = get_object_or_404(AuditGroup, slug=slug)
    return JsonResponse(
        {
            "schema_version": "goggles-group/v1",
            "group": group_api_payload(group),
            "classification": group_classification(group),
        },
        json_dumps_params={"separators": (",", ":")},
    )


@login_required
def api_group_delivery(request: HttpRequest, slug: str):
    group = get_object_or_404(AuditGroup, slug=slug)
    filters = api_filter_values(request)
    artifacts = filtered_delivery_artifacts(group, filters)
    identity_index = delivery_identity_index(group)
    delivery_artifacts, pagination = paginated_payloads(
        artifacts,
        order_by=("first_seen_ms", "artifact_id"),
        filters=filters,
        payload_factory=lambda artifact: delivery_artifact_payload(artifact, identity_index),
        severity_factory=delivery_payload_severity,
    )
    return JsonResponse(
        {
            "schema_version": "goggles-delivery/v1",
            "group": group_api_payload(group),
            "classification": group_classification(group),
            "filters": filters,
            "pagination": pagination,
            "delivery_artifacts": delivery_artifacts,
        },
        json_dumps_params={"separators": (",", ":")},
    )


@login_required
def api_group_delivery_artifact(request: HttpRequest, slug: str, artifact_id: str):
    group = get_object_or_404(AuditGroup, slug=slug)
    artifact = get_object_or_404(
        delivery_artifact_queryset().filter(group=group),
        artifact_id=artifact_id,
    )
    return JsonResponse(
        {
            "schema_version": "goggles-delivery-artifact/v1",
            "group": group_api_payload(group),
            "classification": group_classification(group),
            "delivery_artifact": delivery_artifact_payload(
                artifact,
                delivery_identity_index(group),
            ),
        },
        json_dumps_params={"separators": (",", ":")},
    )


@login_required
def api_message_detail(request: HttpRequest, message_id: str):
    filters = normalized_projection_filters(
        {**api_filter_values(request), "message_id": message_id}
    )
    artifacts = filtered_message_delivery_artifacts(message_id, filters)
    identity_indexes: dict[int, dict[str, set[str]]] = {}

    def payload_factory(artifact: DeliveryArtifact) -> dict:
        identity_index = identity_indexes.setdefault(
            artifact.group_id,
            delivery_identity_index(artifact.group),
        )
        related_filters = {**filters, "offset": 0}
        return {
            "group": group_api_payload(artifact.group),
            "classification": group_classification(artifact.group),
            "delivery_artifact": delivery_artifact_payload(artifact, identity_index),
            "related": message_related_projection_payload(artifact.group, related_filters),
        }

    matches, pagination = paginated_payloads(
        artifacts,
        order_by=("group__slug", "first_seen_ms", "artifact_id"),
        filters=filters,
        payload_factory=payload_factory,
        severity_factory=message_delivery_match_severity,
    )
    return JsonResponse(
        {
            "schema_version": "goggles-message/v1",
            "message_id": message_id,
            "filters": filters,
            "pagination": pagination,
            "matches": matches,
        },
        json_dumps_params={"separators": (",", ":")},
    )


def message_related_projection_payload(group: AuditGroup, filters: dict) -> dict:
    network_observations, network_pagination = paginated_payloads(
        filtered_network_observations(group, filters),
        order_by=("wall_time_ms", "engine_id", "id"),
        filters=filters,
        payload_factory=network_observation_payload,
        severity_factory=network_payload_severity,
    )
    convergence_runs, convergence_pagination = paginated_payloads(
        filtered_convergence_runs(group, filters),
        order_by=("started_at_ms", "engine_id", "run_id"),
        filters=filters,
        payload_factory=convergence_run_payload,
        severity_factory=convergence_payload_severity,
        payload_filter=(convergence_payload_matches_filters if filters.get("message_id") else None),
    )
    state_deltas, state_delta_pagination = paginated_payloads(
        filtered_state_deltas(group, filters),
        order_by=("epoch", "wall_time_ms", "id"),
        filters=filters,
        payload_factory=state_delta_payload,
        severity_factory=state_delta_payload_severity,
    )
    epoch_transitions, transition_pagination = paginated_payloads(
        filtered_epoch_transitions(group, filters),
        order_by=("wall_time_ms", "engine_id", "id"),
        filters=filters,
        payload_factory=epoch_transition_payload,
        severity_factory=epoch_transition_payload_severity,
    )
    action_groups = action_groups_for_api(group, filters)
    return {
        "pagination": {
            "network_observations": network_pagination,
            "convergence_runs": convergence_pagination,
            "state_deltas": state_delta_pagination,
            "epoch_state_transitions": transition_pagination,
            "action_attribution": attribution_pagination_payload(action_groups, filters),
        },
        "network_observations": network_observations,
        "convergence_runs": convergence_runs,
        "state_deltas": state_deltas,
        "epoch_state_transitions": epoch_transitions,
        "action_attribution": {
            "origin_counts": action_origin_counts(group),
            "user_actions": action_attribution_section(action_groups, "user", filters),
            "system_attribution": action_attribution_section(action_groups, "system", filters),
            "other_attribution": action_attribution_section(action_groups, "other", filters),
        },
    }


@login_required
def api_group_network(request: HttpRequest, slug: str):
    group = get_object_or_404(AuditGroup, slug=slug)
    filters = api_filter_values(request)
    network = filtered_network_observations(group, filters)
    network_observations, pagination = paginated_payloads(
        network,
        order_by=("wall_time_ms", "engine_id", "id"),
        filters=filters,
        payload_factory=network_observation_payload,
        severity_factory=network_payload_severity,
    )
    return JsonResponse(
        {
            "schema_version": "goggles-network/v1",
            "group": group_api_payload(group),
            "classification": group_classification(group),
            "filters": filters,
            "pagination": pagination,
            "network_observations": network_observations,
        },
        json_dumps_params={"separators": (",", ":")},
    )


@login_required
def api_group_convergence_runs(request: HttpRequest, slug: str):
    group = get_object_or_404(AuditGroup, slug=slug)
    filters = api_filter_values(request)
    convergence = filtered_convergence_runs(group, filters)
    convergence_runs, pagination = paginated_payloads(
        convergence,
        order_by=("started_at_ms", "engine_id", "run_id"),
        filters=filters,
        payload_factory=convergence_run_payload,
        severity_factory=convergence_payload_severity,
        payload_filter=(convergence_payload_matches_filters if filters.get("message_id") else None),
    )
    return JsonResponse(
        {
            "schema_version": "goggles-convergence-runs/v1",
            "group": group_api_payload(group),
            "classification": group_classification(group),
            "filters": filters,
            "pagination": pagination,
            "convergence_runs": convergence_runs,
        },
        json_dumps_params={"separators": (",", ":")},
    )


@login_required
def api_group_convergence_run(request: HttpRequest, slug: str, run_id: str):
    group = get_object_or_404(AuditGroup, slug=slug)
    filters = api_filter_values(request)
    runs = convergence_run_queryset().filter(group=group, run_id=run_id)
    if filters["engine_id"]:
        runs = runs.filter(engine_id=filters["engine_id"])
    matches = list(runs.order_by("engine_id", "started_at_ms", "id")[:2])
    if not matches:
        raise Http404("convergence run not found")
    if len(matches) > 1:
        return JsonResponse(
            {
                "schema_version": "goggles-convergence-run-ambiguous/v1",
                "group": group_api_payload(group),
                "classification": group_classification(group),
                "filters": filters,
                "error": "multiple_convergence_runs",
                "message": (
                    "Multiple engines emitted this convergence run id. Retry with engine_id."
                ),
                "matches": [
                    {
                        "run_id": match.run_id,
                        "engine_id": match.engine_id,
                        "account_ref": match.account_ref,
                        "inferred": match.inferred,
                        "phase": match.phase,
                        "started_at_ms": match.started_at_ms,
                        "ended_at_ms": match.ended_at_ms,
                    }
                    for match in matches
                ],
            },
            status=409,
            json_dumps_params={"separators": (",", ":")},
        )
    run = matches[0]
    return JsonResponse(
        {
            "schema_version": "goggles-convergence-run/v1",
            "group": group_api_payload(group),
            "classification": group_classification(group),
            "filters": filters,
            "convergence_run": convergence_run_payload(run),
        },
        json_dumps_params={"separators": (",", ":")},
    )


@login_required
def api_group_state(request: HttpRequest, slug: str):
    group = get_object_or_404(AuditGroup, slug=slug)
    filters = api_filter_values(request)
    deltas = filtered_state_deltas(group, filters)
    transitions = filtered_epoch_transitions(group, filters)
    state_deltas, delta_pagination = paginated_payloads(
        deltas,
        order_by=("epoch", "wall_time_ms", "id"),
        filters=filters,
        payload_factory=state_delta_payload,
        severity_factory=state_delta_payload_severity,
    )
    epoch_transitions, transition_pagination = paginated_payloads(
        transitions,
        order_by=("wall_time_ms", "engine_id", "id"),
        filters=filters,
        payload_factory=epoch_transition_payload,
        severity_factory=epoch_transition_payload_severity,
    )
    return JsonResponse(
        {
            "schema_version": "goggles-state/v1",
            "group": group_api_payload(group),
            "classification": group_classification(group),
            "filters": filters,
            "pagination": {
                "state_deltas": delta_pagination,
                "epoch_state_transitions": transition_pagination,
            },
            "state_deltas": state_deltas,
            "epoch_state_transitions": epoch_transitions,
        },
        json_dumps_params={"separators": (",", ":")},
    )


@login_required
def api_group_engines(request: HttpRequest, slug: str):
    group = get_object_or_404(AuditGroup, slug=slug)
    return JsonResponse(
        {
            "schema_version": "goggles-engines/v1",
            "group": group_api_payload(group),
            "classification": group_classification(group),
            "engines": group_engine_rows(group),
        },
        json_dumps_params={"separators": (",", ":")},
    )


@login_required
def api_group_evidence(request: HttpRequest, slug: str):
    group = get_object_or_404(AuditGroup, slug=slug)
    filters = api_filter_values(request)
    events = filtered_evidence_events(group, filters)
    evidence_rows, pagination = paginated_payloads(
        events,
        order_by=("wall_time_ms", "engine_id", "line_number", "id"),
        filters=filters,
        payload_factory=evidence_row_payload,
        severity_factory=evidence_row_payload_severity,
    )
    return JsonResponse(
        {
            "schema_version": "goggles-evidence-list/v1",
            "group": group_api_payload(group),
            "classification": group_classification(group),
            "filters": filters,
            "pagination": pagination,
            "evidence": evidence_rows,
        },
        json_dumps_params={"separators": (",", ":")},
    )


@login_required
def api_group_actions(request: HttpRequest, slug: str):
    group = get_object_or_404(AuditGroup, slug=slug)
    filters = action_filter_values(request)
    action_groups = action_groups_for_api(group, filters)
    return JsonResponse(
        {
            "schema_version": "goggles-action-attribution/v1",
            "group": group_api_payload(group),
            "classification": group_classification(group),
            "filters": filters,
            "origin_counts": action_origin_counts(group),
            "pagination": attribution_pagination_payload(action_groups, filters),
            "user_actions": action_attribution_section(action_groups, "user", filters),
            "system_attribution": action_attribution_section(action_groups, "system", filters),
            "other_attribution": action_attribution_section(action_groups, "other", filters),
        },
        json_dumps_params={"separators": (",", ":")},
    )


@login_required
def api_account_groups(request: HttpRequest, account_ref: str):
    groups = AuditGroup.objects.filter(audit_events__account_ref=account_ref).distinct()
    return JsonResponse(
        {
            "schema_version": "goggles-account-groups/v1",
            "account_ref": account_ref,
            "groups": [group_api_payload(group) for group in groups.order_by("slug")],
        },
        json_dumps_params={"separators": (",", ":")},
    )


@login_required
def api_engine_groups(request: HttpRequest, engine_id: str):
    groups = AuditGroup.objects.filter(audit_events__engine_id=engine_id).distinct()
    return JsonResponse(
        {
            "schema_version": "goggles-engine-groups/v1",
            "engine_id": engine_id,
            "groups": [group_api_payload(group) for group in groups.order_by("slug")],
        },
        json_dumps_params={"separators": (",", ":")},
    )


@login_required
def api_event_evidence(request: HttpRequest, event_id: int):
    event = get_object_or_404(
        AuditEvent.objects.select_related("audit_file", "group"),
        pk=event_id,
    )
    return JsonResponse(
        {
            "schema_version": "goggles-event-evidence/v1",
            "evidence_ref": evidence_ref_payload(event),
            "sensitivity": sensitivity_payload(
                event_sensitive_field_paths(event),
                audit_data_modes=[event.audit_data_mode] if event.audit_data_mode else [],
            ),
            "group": group_api_payload(event.group) if event.group_id else None,
            "event": {
                "parse_status": event.parse_status,
                "validation_error": event.validation_error,
                "seq": event.seq,
                "schema_version": event.schema_version,
                "recorder_session_id": event.recorder_session_id,
                "audit_data_mode": event.audit_data_mode,
                "account_ref": event.account_ref,
                "engine_id": event.engine_id,
                "group_ref": event.group_ref,
                "event_type": event.event_type,
                "context": event.raw_context,
                "kind": event.raw_kind,
                "raw_event": event.raw_event,
                "raw_line": event.raw_line,
            },
            "source_file": audit_file_api_payload(event.audit_file),
        },
        json_dumps_params={"separators": (",", ":")},
    )


@login_required
def api_group_projections(request: HttpRequest, slug: str):
    group = get_object_or_404(AuditGroup, slug=slug)
    payload = group_projection_payload(group, filters=action_filter_values(request))
    response = JsonResponse(payload, json_dumps_params={"separators": (",", ":")})
    if request.GET.get("download", "").lower() in {"1", "true", "yes"}:
        response["Content-Disposition"] = (
            f'attachment; filename="{group.slug}-forensic-projections.json"'
        )
    return response


def group_projection_payload(
    group: AuditGroup,
    *,
    filters: dict | None = None,
) -> dict:
    filters = normalized_projection_filters(filters)
    artifacts = filtered_delivery_artifacts(group, filters)
    network = filtered_network_observations(group, filters)
    convergence = filtered_convergence_runs(group, filters)
    state_deltas = filtered_state_deltas(group, filters)
    transitions = filtered_epoch_transitions(group, filters)
    mode_changes = filtered_audit_data_mode_changes(group, filters)
    action_groups = action_groups_for_api(group, filters)
    identity_index = delivery_identity_index(group)
    delivery_artifacts, delivery_pagination = paginated_payloads(
        artifacts,
        order_by=("first_seen_ms", "artifact_id"),
        filters=filters,
        payload_factory=lambda artifact: delivery_artifact_payload(artifact, identity_index),
        severity_factory=delivery_payload_severity,
    )
    network_observations, network_pagination = paginated_payloads(
        network,
        order_by=("wall_time_ms", "engine_id", "id"),
        filters=filters,
        payload_factory=network_observation_payload,
        severity_factory=network_payload_severity,
    )
    convergence_runs, convergence_pagination = paginated_payloads(
        convergence.prefetch_related("candidates", "rule_evaluations"),
        order_by=("started_at_ms", "engine_id", "run_id"),
        filters=filters,
        payload_factory=convergence_run_payload,
        severity_factory=convergence_payload_severity,
        payload_filter=(convergence_payload_matches_filters if filters.get("message_id") else None),
    )
    state_delta_payloads, state_delta_pagination = paginated_payloads(
        state_deltas,
        order_by=("epoch", "wall_time_ms", "id"),
        filters=filters,
        payload_factory=state_delta_payload,
        severity_factory=state_delta_payload_severity,
    )
    epoch_transition_payloads, epoch_transition_pagination = paginated_payloads(
        transitions,
        order_by=("wall_time_ms", "engine_id", "id"),
        filters=filters,
        payload_factory=epoch_transition_payload,
        severity_factory=epoch_transition_payload_severity,
    )
    mode_change_payloads, mode_change_pagination = paginated_payloads(
        mode_changes,
        order_by=("wall_time_ms", "engine_id", "id"),
        filters=filters,
        payload_factory=audit_data_mode_change_payload,
        severity_factory=audit_data_mode_change_payload_severity,
    )
    return {
        "schema_version": "goggles-audit-projections/v1",
        "group": group_api_payload(group),
        "classification": group_classification(group),
        "filters": filters,
        "pagination": {
            "delivery_artifacts": delivery_pagination,
            "network_observations": network_pagination,
            "convergence_runs": convergence_pagination,
            "state_deltas": state_delta_pagination,
            "epoch_state_transitions": epoch_transition_pagination,
            "audit_data_mode_changes": mode_change_pagination,
            "action_attribution": attribution_pagination_payload(action_groups, filters),
        },
        "delivery_artifacts": delivery_artifacts,
        "network_observations": network_observations,
        "convergence_runs": convergence_runs,
        "state_deltas": state_delta_payloads,
        "epoch_state_transitions": epoch_transition_payloads,
        "audit_data_mode_changes": mode_change_payloads,
        "action_attribution": {
            "origin_counts": action_origin_counts(group),
            "user_actions": action_attribution_section(action_groups, "user", filters),
            "system_attribution": action_attribution_section(action_groups, "system", filters),
            "other_attribution": action_attribution_section(action_groups, "other", filters),
        },
    }


def group_list_api_payload(group) -> dict:
    return {
        "slug": group.slug,
        "name": group.name,
        "group_ref": group.group_ref,
        "display_ref": getattr(group, "display_ref", group.group_ref or group.slug),
        "audit_file_count": getattr(group, "audit_file_count", None),
        "event_count": getattr(group, "event_count", None),
        "engine_count": getattr(group, "engine_count", None),
        "divergent_message_count": getattr(group, "divergent_count", None),
        "updated_at": group.updated_at.isoformat() if group.updated_at else None,
    }


def group_api_payload(group: AuditGroup) -> dict:
    shell = group_summary_context(group)
    return {
        "slug": group.slug,
        "name": group.name,
        "group_ref": group.group_ref,
        "summary": shell["summary"],
        "tab_counts": shell["tab_counts"],
        "updated_at": group.updated_at.isoformat() if group.updated_at else None,
    }


def audit_file_api_payload(audit_file: AuditFile) -> dict:
    return {
        "id": audit_file.id,
        "source_name": audit_file.source_name,
        "source": source_response(audit_file),
        "validation_status": audit_file.validation_status,
        "validation_error": audit_file.validation_error,
        "file_sha256": audit_file.file_sha256,
        "byte_size": audit_file.byte_size,
        "total_line_count": audit_file.total_line_count,
        "valid_event_count": audit_file.valid_event_count,
        "invalid_event_count": audit_file.invalid_event_count,
        "duplicate_event_count": audit_file.duplicate_event_count,
        "schema_versions": audit_file.schema_versions,
        "audit_data_modes": audit_file.audit_data_modes,
        "account_refs": audit_file.account_refs,
        "engine_ids": audit_file.engine_ids,
        "group_refs": audit_file.group_refs,
        "created_at": audit_file.created_at.isoformat() if audit_file.created_at else None,
    }


def group_classification(group: AuditGroup) -> dict:
    modes = [row["mode"] for row in audit_data_modes_for_group(group)]
    contains_full_data = FULL_DATA_AUDIT_MODE in modes
    return {
        "audit_data_modes": modes,
        "contains_full_data": contains_full_data,
        "may_include_decrypted_message_content": contains_full_data,
        "may_include_full_transport_identifiers": contains_full_data,
    }


def sensitivity_payload(
    field_paths: list[str],
    *,
    audit_data_modes: list[str] | None = None,
) -> dict:
    modes = audit_data_modes or []
    return {
        "contains_sensitive_data": bool(field_paths),
        "contains_full_data": FULL_DATA_AUDIT_MODE in modes,
        "audit_data_modes": modes,
        "sensitive_field_paths": field_paths,
        "authorization": {
            "required": "authenticated_internal_user",
            "granted": True,
        },
    }


def delivery_artifact_sensitive_field_paths(artifact: DeliveryArtifact) -> list[str]:
    field_paths = []
    if artifact.decoded_payload:
        field_paths.append("decoded_payload")
    if artifact.decoded_app_event:
        field_paths.append("decoded_app_event")
    author = artifact.author if isinstance(artifact.author, dict) else {}
    if author.get("account_pubkey_hex"):
        field_paths.append("author.account_pubkey_hex")
    if author.get("npub"):
        field_paths.append("author.npub")
    decoded_app_event = (
        artifact.decoded_app_event if isinstance(artifact.decoded_app_event, dict) else {}
    )
    if decoded_app_event.get("pubkey_hex"):
        field_paths.append("decoded_app_event.pubkey_hex")
    if decoded_app_event.get("content"):
        field_paths.append("decoded_app_event.content")
    return field_paths


def network_sensitive_field_paths(observation: NetworkObservation) -> list[str]:
    fields = (
        "wire_id",
        "wire_pubkey_hex",
        "transport_group_id",
        "nostr_event_id",
        "nostr_pubkey_hex",
        "gift_wrap_event_id",
        "welcome_nostr_event_id",
        "welcome_rumor_event_id",
        "welcome_key_package_tag",
        "publish_result_id",
    )
    return [field for field in fields if getattr(observation, field)]


def convergence_sensitive_field_paths(run: ConvergenceRun) -> list[str]:
    field_paths = []
    if run.account_ref:
        field_paths.append("account_ref")
    for candidate in run.candidates.all():
        if candidate.tip_committer_pubkey_hex:
            field_paths.append("candidates[].tip_committer_pubkey_hex")
            break
    return field_paths


def state_delta_sensitive_field_paths(delta: StateDelta) -> list[str]:
    field_paths = []
    if delta.actor_pubkey_hex:
        field_paths.append("actor_pubkey_hex")
    if delta.subject_pubkey_hex:
        field_paths.append("subject_pubkey_hex")
    value = delta.value if isinstance(delta.value, dict) else {}
    if value.get("text"):
        field_paths.append("value.text")
    return field_paths


def audit_data_mode_change_sensitive_field_paths(event: AuditEvent) -> list[str]:
    field_paths = []
    if event.engine_id:
        field_paths.append("engine_id")
    if event.account_ref:
        field_paths.append("account_ref")
    if event.recorder_session_id:
        field_paths.append("recorder_session_id")
    return field_paths


def evidence_row_sensitive_field_paths(event: AuditEvent) -> list[str]:
    field_paths = ["line_hash", "event_type"]
    if event.engine_id:
        field_paths.append("engine_id")
    if event.account_ref:
        field_paths.append("account_ref")
    if event.msg_id:
        field_paths.append("message_id")
    if event.outbound_msg_id:
        field_paths.append("outbound_msg_id")
    if event.recorder_session_id:
        field_paths.append("recorder_session_id")
    if event.audit_data_mode == FULL_DATA_AUDIT_MODE:
        field_paths.append("audit_data_mode:full_data")
    return field_paths


def event_sensitive_field_paths(event: AuditEvent) -> list[str]:
    field_paths = ["raw_line", "raw_event"]
    if event.raw_kind:
        field_paths.append("kind")
    if event.raw_context:
        field_paths.append("context")
    if event.audit_data_mode == FULL_DATA_AUDIT_MODE:
        field_paths.append("audit_data_mode:full_data")
    return field_paths


def api_filter_values(request: HttpRequest) -> dict:
    return {
        "engine_id": request.GET.get("engine_id", ""),
        "account_ref": request.GET.get("account_ref", ""),
        "audit_data_mode": request.GET.get("audit_data_mode", ""),
        "message_id": request.GET.get("message_id", ""),
        "event_type": request.GET.get("event_type", ""),
        "severity": request.GET.get("severity", "").lower(),
        "epoch": optional_positive_int(request.GET.get("epoch")),
        "from_ms": optional_positive_int(request.GET.get("from_ms")),
        "to_ms": optional_positive_int(request.GET.get("to_ms")),
        "limit": bounded_positive_int(
            request.GET.get("limit"),
            default=GROUP_PROJECTION_API_DEFAULT_LIMIT,
            maximum=GROUP_PROJECTION_API_MAX_LIMIT,
        ),
        "offset": bounded_nonnegative_int(request.GET.get("offset")),
    }


def action_filter_values(request: HttpRequest) -> dict:
    filters = api_filter_values(request)
    filters["origin"] = request.GET.get("origin", "")
    filters["action"] = request.GET.get("action", "")
    return filters


def default_action_filters() -> dict:
    return {**default_api_filters(), "origin": "", "action": ""}


def normalized_projection_filters(filters: dict | None) -> dict:
    normalized = {**default_action_filters()}
    if filters:
        normalized.update(filters)
    return normalized


def default_api_filters() -> dict:
    return {
        "engine_id": "",
        "account_ref": "",
        "audit_data_mode": "",
        "message_id": "",
        "event_type": "",
        "severity": "",
        "epoch": None,
        "from_ms": None,
        "to_ms": None,
        "limit": GROUP_PROJECTION_API_DEFAULT_LIMIT,
        "offset": 0,
    }


def optional_positive_int(value: str | None) -> int | None:
    try:
        parsed = int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None
    if parsed is None or parsed < 0:
        return None
    return parsed


def bounded_nonnegative_int(value: str | None) -> int:
    try:
        parsed = int(value) if value not in (None, "") else 0
    except (TypeError, ValueError):
        return 0
    return max(parsed, 0)


def paginated_payloads(
    queryset,
    *,
    order_by: tuple[str, ...],
    filters: dict,
    payload_factory,
    severity_factory,
    payload_filter=None,
) -> tuple[list[dict], dict]:
    limit = filters["limit"]
    offset = filters["offset"]
    severity = filters.get("severity", "")
    ordered = queryset.order_by(*order_by)
    if severity or payload_filter is not None:
        page = []
        matched = 0
        has_more = False
        for item in ordered_payload_items(ordered, chunk_size=limit + 1):
            payload = payload_factory(item)
            if severity and severity_factory(payload) != severity:
                continue
            if payload_filter is not None and not payload_filter(payload, filters):
                continue
            if matched < offset:
                matched += 1
                continue
            if len(page) >= limit:
                has_more = True
                break
            page.append(payload)
            matched += 1
        return page, pagination_payload(limit, offset, len(page), has_more)

    rows = list(ordered[offset : offset + limit + 1])
    page_rows = rows[:limit]
    payloads = [payload_factory(row) for row in page_rows]
    has_more = len(rows) > limit
    return payloads, pagination_payload(limit, offset, len(payloads), has_more)


def ordered_payload_items(ordered, *, chunk_size: int):
    iterator = getattr(ordered, "iterator", None)
    if callable(iterator):
        return iterator(chunk_size=max(1, chunk_size))
    return iter(ordered)


def pagination_payload(limit: int, offset: int, returned: int, has_more: bool) -> dict:
    return {
        "limit": limit,
        "offset": offset,
        "returned": returned,
        "has_more": has_more,
        "next_offset": offset + returned if has_more else None,
    }


def severity_from_values(*values) -> str:
    text = " ".join(str(value).lower() for value in values if value not in (None, "", []))
    if any(token in text for token in ERROR_SEVERITY_TOKENS):
        return "error"
    if any(token in text for token in WARNING_SEVERITY_TOKENS):
        return "warning"
    return "info"


def delivery_payload_severity(payload: dict) -> str:
    if any(
        row.get("status")
        in {
            "missing_inferred",
            "missing_count_inferred",
            "partial_count_inferred",
            "observed_count_exceeds_expected",
            "unobserved_no_uploaded_engine",
        }
        for row in payload.get("recipient_matrix", [])
    ):
        return "warning"
    return severity_from_values(
        *(observation.get("latest_state") for observation in payload.get("engine_observations", []))
    )


def message_delivery_match_severity(payload: dict) -> str:
    return payload["delivery_artifact"]["severity"]


def network_payload_severity(payload: dict) -> str:
    severity = severity_from_values(payload.get("phase"), payload.get("outcome"))
    if severity == "error":
        return severity
    if payload.get("met_required_acks") is False or payload.get("failed_relays"):
        return "warning"
    return severity


def convergence_payload_severity(payload: dict) -> str:
    severity = severity_from_values(payload.get("phase"), payload.get("error_kinds"))
    if severity == "error":
        return severity
    if any(candidate.get("eligible") is False for candidate in payload.get("candidates", [])):
        return "warning"
    if any(candidate.get("rejection_reasons") for candidate in payload.get("candidates", [])):
        return "warning"
    return severity


def state_delta_payload_severity(payload: dict) -> str:
    return severity_from_values(payload.get("change_kind"), payload.get("fields"))


def epoch_transition_payload_severity(payload: dict) -> str:
    return severity_from_values(
        payload.get("previous_state"),
        payload.get("new_state"),
        payload.get("reason"),
    )


def evidence_row_payload_severity(payload: dict) -> str:
    if payload.get("parse_status") != AuditEvent.STATUS_VALID:
        return "error"
    severity = severity_from_values(
        payload.get("event_type"),
        payload.get("validation_error"),
        payload.get("summary"),
    )
    if severity == "info" and payload.get("audit_data_mode") == FULL_DATA_AUDIT_MODE:
        return "warning"
    return severity


def audit_data_mode_change_payload_severity(payload: dict) -> str:
    if payload.get("new_mode") == FULL_DATA_AUDIT_MODE:
        return "warning"
    return severity_from_values(payload.get("reason"))


def delivery_artifact_queryset():
    return DeliveryArtifact.objects.prefetch_related(
        Prefetch("evidence_events", queryset=AuditEvent.objects.select_related("audit_file")),
        "engine_observations",
        Prefetch(
            "engine_observations__evidence_events",
            queryset=AuditEvent.objects.select_related("audit_file"),
        ),
        "recipient_expectations",
        "recipient_expectations__evidence_event",
    )


def filtered_delivery_artifacts(group: AuditGroup, filters: dict):
    return apply_delivery_artifact_filters(
        delivery_artifact_queryset().filter(group=group), filters
    )


def filtered_message_delivery_artifacts(message_id: str, filters: dict):
    return apply_delivery_artifact_filters(
        delivery_artifact_queryset().select_related("group").filter(artifact_id=message_id),
        filters,
    )


def apply_delivery_artifact_filters(artifacts, filters: dict):
    if filters["engine_id"]:
        artifacts = artifacts.filter(engine_observations__engine_id=filters["engine_id"])
    if filters["account_ref"]:
        artifacts = artifacts.filter(engine_observations__account_ref=filters["account_ref"])
    if filters["audit_data_mode"]:
        artifacts = artifacts.filter(evidence_events__audit_data_mode=filters["audit_data_mode"])
    if filters["message_id"]:
        artifacts = artifacts.filter(artifact_id=filters["message_id"])
    if filters["event_type"]:
        artifacts = artifacts.filter(evidence_events__event_type=filters["event_type"])
    if filters["from_ms"] is not None:
        artifacts = artifacts.filter(last_seen_ms__gte=filters["from_ms"])
    if filters["to_ms"] is not None:
        artifacts = artifacts.filter(first_seen_ms__lte=filters["to_ms"])
    return artifacts.distinct()


def network_observation_queryset():
    return NetworkObservation.objects.select_related("artifact", "audit_event", "group")


def filtered_network_observations(group: AuditGroup, filters: dict):
    network = network_observation_queryset().filter(group=group)
    if filters["engine_id"]:
        network = network.filter(engine_id=filters["engine_id"])
    if filters["account_ref"]:
        network = network.filter(account_ref=filters["account_ref"])
    if filters["audit_data_mode"]:
        network = network.filter(audit_event__audit_data_mode=filters["audit_data_mode"])
    if filters["message_id"]:
        network = network.filter(message_id=filters["message_id"])
    if filters["event_type"]:
        network = network.filter(phase=filters["event_type"])
    if filters["from_ms"] is not None:
        network = network.filter(wall_time_ms__gte=filters["from_ms"])
    if filters["to_ms"] is not None:
        network = network.filter(wall_time_ms__lte=filters["to_ms"])
    return network


def convergence_run_queryset():
    return ConvergenceRun.objects.prefetch_related(
        "evidence_events",
        "candidates",
        "rule_evaluations",
    )


def filtered_convergence_runs(group: AuditGroup, filters: dict):
    convergence = convergence_run_queryset().filter(group=group)
    if filters["engine_id"]:
        convergence = convergence.filter(engine_id=filters["engine_id"])
    if filters["account_ref"]:
        convergence = convergence.filter(account_ref=filters["account_ref"])
    if filters["audit_data_mode"]:
        convergence = convergence.filter(
            evidence_events__audit_data_mode=filters["audit_data_mode"]
        )
    if filters["epoch"] is not None:
        convergence = convergence.filter(
            Q(current_tip_epoch=filters["epoch"])
            | Q(selected_fork_epoch=filters["epoch"])
            | Q(selected_tip_epoch=filters["epoch"])
            | Q(candidates__fork_epoch=filters["epoch"])
            | Q(candidates__tip_epoch=filters["epoch"])
            | Q(evidence_events__epoch=filters["epoch"])
            | Q(evidence_events__current_tip_epoch=filters["epoch"])
            | Q(evidence_events__selected_fork_epoch=filters["epoch"])
            | Q(evidence_events__selected_tip_epoch=filters["epoch"])
        )
    if filters["event_type"]:
        convergence = convergence.filter(evidence_events__event_type=filters["event_type"])
    if filters["from_ms"] is not None:
        convergence = convergence.filter(ended_at_ms__gte=filters["from_ms"])
    if filters["to_ms"] is not None:
        convergence = convergence.filter(started_at_ms__lte=filters["to_ms"])
    return convergence.distinct()


def convergence_payload_matches_filters(payload: dict, filters: dict) -> bool:
    message_id = filters.get("message_id", "")
    if not message_id:
        return True
    if message_id in payload.get("losing_branch_ids", []):
        return True
    if message_id == payload.get("selected_branch_id"):
        return True
    for candidate in payload.get("candidates", []):
        if message_id == candidate.get("branch_id"):
            return True
        if message_id in candidate.get("commit_ids", []):
            return True
    for ref in payload.get("evidence_refs", []):
        if message_id == ref.get("message_id"):
            return True
    return False


def state_delta_queryset():
    return StateDelta.objects.select_related("audit_event", "group")


def filtered_state_deltas(group: AuditGroup, filters: dict):
    deltas = state_delta_queryset().filter(group=group)
    if filters["engine_id"]:
        deltas = deltas.filter(audit_event__engine_id=filters["engine_id"])
    if filters["account_ref"]:
        deltas = deltas.filter(audit_event__account_ref=filters["account_ref"])
    if filters["audit_data_mode"]:
        deltas = deltas.filter(audit_data_mode=filters["audit_data_mode"])
    if filters["message_id"]:
        deltas = deltas.filter(
            Q(origin_commit_id=filters["message_id"])
            | Q(audit_event__msg_id=filters["message_id"])
            | Q(audit_event__outbound_msg_id=filters["message_id"])
            | Q(audit_event__invalidated_msg_id=filters["message_id"])
        )
    if filters["epoch"] is not None:
        deltas = deltas.filter(epoch=filters["epoch"])
    if filters["event_type"]:
        deltas = deltas.filter(change_kind=filters["event_type"])
    if filters["from_ms"] is not None:
        deltas = deltas.filter(wall_time_ms__gte=filters["from_ms"])
    if filters["to_ms"] is not None:
        deltas = deltas.filter(wall_time_ms__lte=filters["to_ms"])
    return deltas


def epoch_transition_queryset():
    return EpochStateTransition.objects.select_related("audit_event", "group")


def filtered_epoch_transitions(group: AuditGroup, filters: dict):
    transitions = epoch_transition_queryset().filter(group=group)
    if filters["engine_id"]:
        transitions = transitions.filter(engine_id=filters["engine_id"])
    if filters["account_ref"]:
        transitions = transitions.filter(account_ref=filters["account_ref"])
    if filters["audit_data_mode"]:
        transitions = transitions.filter(audit_event__audit_data_mode=filters["audit_data_mode"])
    if filters["message_id"]:
        transitions = transitions.filter(
            Q(audit_event__msg_id=filters["message_id"])
            | Q(audit_event__outbound_msg_id=filters["message_id"])
            | Q(audit_event__invalidated_msg_id=filters["message_id"])
        )
    if filters["epoch"] is not None:
        transitions = transitions.filter(epoch=filters["epoch"])
    if filters["event_type"]:
        transitions = transitions.filter(new_state=filters["event_type"])
    if filters["from_ms"] is not None:
        transitions = transitions.filter(wall_time_ms__gte=filters["from_ms"])
    if filters["to_ms"] is not None:
        transitions = transitions.filter(wall_time_ms__lte=filters["to_ms"])
    return transitions


def audit_data_mode_change_queryset(group: AuditGroup):
    return valid_group_event_queryset(group).filter(event_type="audit_data_mode_changed")


def filtered_audit_data_mode_changes(group: AuditGroup, filters: dict):
    events = audit_data_mode_change_queryset(group)
    if filters["engine_id"]:
        events = events.filter(engine_id=filters["engine_id"])
    if filters["account_ref"]:
        events = events.filter(account_ref=filters["account_ref"])
    if filters["audit_data_mode"]:
        events = events.filter(audit_data_mode=filters["audit_data_mode"])
    if filters["event_type"] and filters["event_type"] != "audit_data_mode_changed":
        events = events.none()
    if filters["from_ms"] is not None:
        events = events.filter(wall_time_ms__gte=filters["from_ms"])
    if filters["to_ms"] is not None:
        events = events.filter(wall_time_ms__lte=filters["to_ms"])
    return events.select_related("audit_file", "group")


def evidence_event_queryset(group: AuditGroup):
    return AuditEvent.objects.filter(group=group).select_related("audit_file", "group")


def filtered_evidence_events(group: AuditGroup, filters: dict):
    events = evidence_event_queryset(group)
    if filters["engine_id"]:
        events = events.filter(engine_id=filters["engine_id"])
    if filters["account_ref"]:
        events = events.filter(account_ref=filters["account_ref"])
    if filters["audit_data_mode"]:
        events = events.filter(audit_data_mode=filters["audit_data_mode"])
    if filters["message_id"]:
        events = events.filter(
            Q(msg_id=filters["message_id"]) | Q(outbound_msg_id=filters["message_id"])
        )
    if filters["event_type"]:
        events = events.filter(event_type=filters["event_type"])
    if filters["epoch"] is not None:
        events = events.filter(
            Q(epoch=filters["epoch"])
            | Q(source_epoch=filters["epoch"])
            | Q(to_epoch=filters["epoch"])
            | Q(pending_epoch=filters["epoch"])
            | Q(current_tip_epoch=filters["epoch"])
            | Q(selected_tip_epoch=filters["epoch"])
        )
    if filters["from_ms"] is not None:
        events = events.filter(wall_time_ms__gte=filters["from_ms"])
    if filters["to_ms"] is not None:
        events = events.filter(wall_time_ms__lte=filters["to_ms"])
    return events


def action_event_queryset(group: AuditGroup):
    return (
        valid_group_event_queryset(group)
        .exclude(human_action_action="")
        .select_related("audit_file", "group")
        .order_by("wall_time_ms", "engine_id", "line_number", "id")
    )


def filtered_action_events(group: AuditGroup, filters: dict):
    events = action_event_queryset(group)
    if filters["engine_id"]:
        events = events.filter(engine_id=filters["engine_id"])
    if filters["account_ref"]:
        events = events.filter(account_ref=filters["account_ref"])
    if filters["audit_data_mode"]:
        events = events.filter(audit_data_mode=filters["audit_data_mode"])
    if filters["event_type"]:
        events = events.filter(event_type=filters["event_type"])
    if filters["epoch"] is not None:
        events = events.filter(Q(from_epoch=filters["epoch"]) | Q(to_epoch=filters["epoch"]))
    if filters["origin"]:
        events = events.filter(human_action_origin=filters["origin"])
    if filters["action"]:
        events = events.filter(human_action_action=filters["action"])
    if filters["from_ms"] is not None:
        events = events.filter(wall_time_ms__gte=filters["from_ms"])
    if filters["to_ms"] is not None:
        events = events.filter(wall_time_ms__lte=filters["to_ms"])
    return events


ACTION_ATTRIBUTION_PAGE_KEYS = {
    "user": "user_actions",
    "system": "system_attribution",
    "other": "other_attribution",
}


def action_groups_for_api(group: AuditGroup, filters: dict) -> list[dict]:
    events = list(filtered_action_events(group, filters))
    if filters["message_id"]:
        events = [
            event for event in events if filters["message_id"] in action_event_message_ids(event)
        ]
    event_by_id = {event.id: event for event in events}
    groups = [
        action_group_payload(action_group, event_by_id)
        for action_group in human_action_groups_for_group(events)
    ]
    if filters["severity"]:
        groups = [
            action_group
            for action_group in groups
            if action_attribution_payload_severity(action_group) == filters["severity"]
        ]
    return groups


def action_origin_counts(group: AuditGroup) -> list[dict]:
    rows = (
        action_event_queryset(group)
        .values("human_action_origin")
        .annotate(count=Count("id"))
        .order_by("human_action_origin")
    )
    return [
        {
            "origin": row["human_action_origin"] or "",
            "attribution_kind": action_attribution_kind(row["human_action_origin"] or ""),
            "count": row["count"],
        }
        for row in rows
    ]


def action_attribution_section(
    action_groups: list[dict],
    kind: str,
    filters: dict,
) -> list[dict]:
    rows = [row for row in action_groups if row["attribution_kind"] == kind]
    offset = filters["offset"]
    limit = filters["limit"]
    return rows[offset : offset + limit]


def attribution_pagination_payload(action_groups: list[dict], filters: dict) -> dict:
    limit = filters["limit"]
    offset = filters["offset"]
    payload = {}
    for kind, page_key in ACTION_ATTRIBUTION_PAGE_KEYS.items():
        total = len([row for row in action_groups if row["attribution_kind"] == kind])
        returned = min(max(total - offset, 0), limit)
        payload[page_key] = pagination_payload(limit, offset, returned, total > offset + limit)
    return payload


def action_attribution_kind(origin: str) -> str:
    if origin == "local_user":
        return "user"
    if origin == "system":
        return "system"
    return "other"


def action_group_payload(action_group: dict, event_by_id: dict[int, AuditEvent]) -> dict:
    events = []
    audit_data_modes = set()
    for row in action_group["events"]:
        event = event_by_id.get(row["id"])
        if event and event.audit_data_mode:
            audit_data_modes.add(event.audit_data_mode)
        events.append(
            {
                "event_id": row["id"],
                "event_type": row["event_type"],
                "engine_id": row["engine_id"],
                "account_ref": row["account_ref"],
                "audit_data_mode": event.audit_data_mode if event else "",
                "wall_time_ms": row["wall_time_ms"],
                "message_ids": row["message_ids"],
                "summary": row["summary"],
                "evidence_ref": evidence_ref_payload(event) if event else None,
            }
        )

    payload = {
        "attribution_kind": action_attribution_kind(action_group["origin"] or ""),
        "operation_id": action_group["operation_id"],
        "action": action_group["action"],
        "action_label": action_group["action_label"],
        "origin": action_group["origin"],
        "phase": action_group["phase"],
        "fields": action_group["fields"],
        "component_ids": action_group["component_ids"],
        "target_count": action_group["target_count"],
        "from_epoch": action_group["from_epoch"],
        "to_epoch": action_group["to_epoch"],
        "message_ids": action_group["message_ids"],
        "first_wall_time_ms": action_group["first_wall_time_ms"],
        "last_wall_time_ms": action_group["last_wall_time_ms"],
        "event_count": len(events),
        "audit_data_modes": sorted(audit_data_modes),
        "events": events,
        "evidence_refs": [event["evidence_ref"] for event in events if event["evidence_ref"]],
    }
    payload["sensitivity"] = sensitivity_payload(
        action_group_sensitive_field_paths(payload),
        audit_data_modes=payload["audit_data_modes"],
    )
    payload["severity"] = action_attribution_payload_severity(payload)
    return payload


def action_event_message_ids(event: AuditEvent) -> set[str]:
    values = {
        event.msg_id,
        event.outbound_msg_id,
        event.invalidated_msg_id,
        *(event.outbound_welcome_msg_ids or []),
        *(event.human_action_message_ids or []),
    }
    return {value for value in values if value}


def action_group_sensitive_field_paths(payload: dict) -> list[str]:
    field_paths = []
    if payload["operation_id"]:
        field_paths.append("operation_id")
    if payload["message_ids"]:
        field_paths.append("message_ids")
    if payload["evidence_refs"]:
        field_paths.append("evidence_refs[].line_hash")
    if any(event["engine_id"] for event in payload["events"]):
        field_paths.append("events[].engine_id")
    if any(event["account_ref"] for event in payload["events"]):
        field_paths.append("events[].account_ref")
    return field_paths


def action_attribution_payload_severity(payload: dict) -> str:
    return severity_from_values(
        payload.get("action"),
        payload.get("origin"),
        payload.get("phase"),
        *(event.get("summary") for event in payload.get("events", [])),
    )


def evidence_ref_payload(event: AuditEvent) -> dict:
    return {
        "event_id": event.id,
        "audit_file_id": event.audit_file_id,
        "line_number": event.line_number,
        "line_hash": event.line_hash,
        "schema_version": event.schema_version,
        "audit_data_mode": event.audit_data_mode,
        "event_type": event.event_type,
        "wall_time_ms": event.wall_time_ms,
        "api_path": reverse("api-event-evidence", kwargs={"event_id": event.id}),
    }


def evidence_refs_payload(events) -> list[dict]:
    return [evidence_ref_payload(event) for event in events.all()]


def delivery_identity_index(group: AuditGroup) -> dict[str, set[str]]:
    index = {"account_refs": set(), "pubkeys_hex": set(), "engine_ids": set()}
    events = (
        AuditEvent.objects.filter(group=group, parse_status=AuditEvent.STATUS_VALID)
        .select_related("audit_file")
        .only(
            "account_ref",
            "engine_id",
            "context_source",
            "audit_file__source_account_pubkey_hex",
        )
    )
    for event in events:
        if event.account_ref:
            index["account_refs"].add(event.account_ref)
        if event.engine_id:
            index["engine_ids"].add(event.engine_id)
        if event.audit_file.source_account_pubkey_hex:
            index["pubkeys_hex"].add(event.audit_file.source_account_pubkey_hex)
        if isinstance(event.context_source, dict) and event.context_source.get(
            "account_pubkey_hex"
        ):
            index["pubkeys_hex"].add(event.context_source["account_pubkey_hex"])
    return index


def attach_delivery_matrices(
    artifacts: list[DeliveryArtifact],
    group: AuditGroup,
    *,
    engines: list[dict] | None = None,
) -> None:
    identity_index = delivery_identity_index(group)
    delivery_engines = engines if engines is not None else group_engine_rows(group)
    for artifact in artifacts:
        matrix = delivery_recipient_matrix(artifact, identity_index)
        artifact.recipient_matrix = matrix
        artifact.delivery_engine_cells = delivery_engine_cells(
            artifact,
            delivery_engines,
            matrix,
        )
        artifact.has_inferred_missing = any(
            row["status"]
            in {"missing_inferred", "missing_count_inferred", "partial_count_inferred"}
            for row in matrix
        )


def delivery_engine_cells(
    artifact: DeliveryArtifact,
    engines: list[dict],
    recipient_matrix: list[dict],
) -> list[dict]:
    observations_by_engine = {
        observation.engine_id: observation for observation in artifact.engine_observations.all()
    }
    return [
        delivery_engine_cell(
            engine,
            observations_by_engine.get(engine["engine_id"]),
            recipient_matrix,
        )
        for engine in engines
    ]


def delivery_engine_cell(
    engine: dict,
    observation: DeliveryObservation | None,
    recipient_matrix: list[dict],
) -> dict:
    if observation is not None:
        status = observation.latest_state or "observed"
        states = observation.states or []
        latest_evidence_id = next(
            (state.get("event_id") for state in reversed(states) if state.get("event_id")),
            None,
        )
        return {
            "engine": engine,
            "status": status,
            "status_label": status,
            "badge_class": delivery_observation_badge_class(status),
            "states": states,
            "first_seen_ms": observation.first_seen_ms,
            "last_seen_ms": observation.last_seen_ms,
            "latest_evidence_id": latest_evidence_id,
        }

    missing_status = delivery_missing_status_for_engine(engine, recipient_matrix)
    status = missing_status or "not_observed"
    return {
        "engine": engine,
        "status": status,
        "status_label": delivery_status_label(status),
        "badge_class": delivery_matrix_status_badge_class(status),
        "states": [],
        "first_seen_ms": None,
        "last_seen_ms": None,
        "latest_evidence_id": None,
    }


def delivery_missing_status_for_engine(engine: dict, recipient_matrix: list[dict]) -> str:
    missing_statuses = {"missing_inferred", "partial_count_inferred", "missing_count_inferred"}
    for row in recipient_matrix:
        if row["status"] in missing_statuses and delivery_engine_matches_recipient(engine, row):
            return row["status"]
    return ""


def delivery_engine_matches_recipient(engine: dict, recipient: dict) -> bool:
    recipient_id = recipient.get("recipient_id")
    if not recipient_id:
        return False
    if recipient.get("recipient_type") == "member_ref":
        return recipient_id in set(engine.get("account_refs") or [engine.get("account_ref")])
    if recipient.get("recipient_type") == "pubkey_hex":
        source = engine.get("source_metadata") or {}
        return recipient_id in set(source.get("account_pubkeys_hex") or [])
    return False


def delivery_observation_badge_class(status: str) -> str:
    severity = severity_from_values(status)
    if severity == "error":
        return "badge--danger"
    if severity == "warning":
        return "badge--warning"
    return "badge--accent"


def delivery_matrix_status_badge_class(status: str) -> str:
    if status in {"missing_inferred", "missing_count_inferred"}:
        return "badge--danger"
    if status == "partial_count_inferred":
        return "badge--warning"
    return ""


def delivery_recipient_matrix(
    artifact: DeliveryArtifact,
    identity_index: dict[str, set[str]] | None = None,
) -> list[dict]:
    identity_index = identity_index or delivery_identity_index(artifact.group)
    observations = list(artifact.engine_observations.all())
    observation_identities = {
        observation.id: observation_identity_values(observation) for observation in observations
    }
    rows = []
    matched_observation_ids: set[int] = set()

    for expectation in artifact.recipient_expectations.all():
        expected_rows = expectation_identity_rows(expectation)
        if not expected_rows and expectation.expected_count is not None:
            counted_observations, excluded_observations = count_only_recipient_observations(
                expectation,
                observations,
                observation_identities,
            )
            matched_observation_ids.update(observation.id for observation in counted_observations)
            observed_count = len(counted_observations)
            missing_count = max(expectation.expected_count - observed_count, 0)
            status = count_only_expectation_status(expectation.expected_count, observed_count)
            rows.append(
                {
                    "recipient_type": "count_only",
                    "recipient_id": "",
                    "status": status,
                    "status_label": delivery_status_label(status),
                    "recipient_scope": expectation.recipient_scope,
                    "expected_count": expectation.expected_count,
                    "observed_count": observed_count,
                    "missing_count": missing_count,
                    "excluded_observation_count": len(excluded_observations),
                    "membership_epoch": expectation.membership_epoch,
                    "observations": [
                        delivery_observation_payload(observation)
                        for observation in counted_observations
                    ],
                    "evidence_ref": evidence_ref_payload(expectation.evidence_event),
                }
            )
            continue

        for expected in expected_rows:
            matched = [
                observation
                for observation in observations
                if observation_matches_expected(
                    observation_identities[observation.id],
                    expected["recipient_type"],
                    expected["recipient_id"],
                )
            ]
            matched_observation_ids.update(observation.id for observation in matched)
            status = delivery_expected_status(expected, matched, identity_index)
            rows.append(
                {
                    **expected,
                    "status": status,
                    "status_label": delivery_status_label(status),
                    "recipient_scope": expectation.recipient_scope,
                    "expected_count": expectation.expected_count,
                    "membership_epoch": expectation.membership_epoch,
                    "observations": [
                        delivery_observation_payload(observation) for observation in matched
                    ],
                    "evidence_ref": evidence_ref_payload(expectation.evidence_event),
                }
            )

    for observation in observations:
        if observation.id in matched_observation_ids:
            continue
        identities = observation_identities[observation.id]
        rows.append(
            {
                "recipient_type": "engine",
                "recipient_id": observation.account_ref
                or next(iter(identities["pubkeys_hex"]), "")
                or observation.engine_id,
                "status": "observed_not_expected",
                "status_label": "observed, not expected",
                "recipient_scope": "",
                "expected_count": None,
                "membership_epoch": None,
                "observations": [delivery_observation_payload(observation)],
                "evidence_ref": None,
            }
        )
    return rows


def expectation_identity_rows(expectation: RecipientExpectation) -> list[dict]:
    rows = [
        {"recipient_type": "member_ref", "recipient_id": member_ref}
        for member_ref in expectation.expected_member_refs
    ]
    rows.extend(
        {"recipient_type": "pubkey_hex", "recipient_id": pubkey}
        for pubkey in expectation.expected_pubkeys_hex
    )
    return rows


def count_only_recipient_observations(
    expectation: RecipientExpectation,
    observations: list[DeliveryObservation],
    observation_identities: dict[int, dict[str, set[str]]],
) -> tuple[list[DeliveryObservation], list[DeliveryObservation]]:
    counted = []
    excluded = []
    for observation in observations:
        if recipient_scope_excludes_expectation_source(
            expectation.recipient_scope
        ) and observation_matches_expectation_source(
            observation,
            observation_identities[observation.id],
            expectation.evidence_event,
        ):
            excluded.append(observation)
            continue
        counted.append(observation)
    return counted, excluded


def recipient_scope_excludes_expectation_source(scope: str) -> bool:
    return scope in {"all_other_current_group_members", "all_other_group_members"}


def observation_matches_expectation_source(
    observation: DeliveryObservation,
    identities: dict[str, set[str]],
    event: AuditEvent,
) -> bool:
    if event.engine_id and observation.engine_id == event.engine_id:
        return True
    if event.account_ref and event.account_ref in identities["account_refs"]:
        return True
    source = event.context_source if isinstance(event.context_source, dict) else {}
    pubkey = source.get("account_pubkey_hex")
    return bool(isinstance(pubkey, str) and pubkey in identities["pubkeys_hex"])


def count_only_expectation_status(expected_count: int, observed_count: int) -> str:
    if observed_count < expected_count:
        return "missing_count_inferred" if observed_count == 0 else "partial_count_inferred"
    if observed_count == expected_count:
        return "expected_count_satisfied"
    return "observed_count_exceeds_expected"


def observation_identity_values(observation: DeliveryObservation) -> dict[str, set[str]]:
    identities = {"account_refs": set(), "pubkeys_hex": set(), "engine_ids": set()}
    if observation.account_ref:
        identities["account_refs"].add(observation.account_ref)
    if observation.engine_id:
        identities["engine_ids"].add(observation.engine_id)
    for event in observation.evidence_events.all():
        if event.audit_file.source_account_pubkey_hex:
            identities["pubkeys_hex"].add(event.audit_file.source_account_pubkey_hex)
        if isinstance(event.context_source, dict) and event.context_source.get(
            "account_pubkey_hex"
        ):
            identities["pubkeys_hex"].add(event.context_source["account_pubkey_hex"])
    return identities


def observation_matches_expected(
    identities: dict[str, set[str]],
    recipient_type: str,
    recipient_id: str,
) -> bool:
    if recipient_type == "member_ref":
        return recipient_id in identities["account_refs"]
    if recipient_type == "pubkey_hex":
        return recipient_id in identities["pubkeys_hex"]
    return False


def delivery_expected_status(
    expected: dict,
    matched: list[DeliveryObservation],
    identity_index: dict[str, set[str]],
) -> str:
    if matched:
        return "observed"
    if expected["recipient_type"] == "member_ref":
        if expected["recipient_id"] in identity_index["account_refs"]:
            return "missing_inferred"
        return "unobserved_no_uploaded_engine"
    if expected["recipient_type"] == "pubkey_hex":
        if expected["recipient_id"] in identity_index["pubkeys_hex"]:
            return "missing_inferred"
        return "unobserved_no_uploaded_engine"
    return "unknown"


def delivery_status_label(status: str) -> str:
    return {
        "observed": "observed",
        "missing_inferred": "missing inferred",
        "missing_count_inferred": "missing count inferred",
        "partial_count_inferred": "partial count inferred",
        "unobserved_no_uploaded_engine": "no uploaded engine",
        "observed_not_expected": "observed, not expected",
        "expected_count_satisfied": "expected count satisfied",
        "observed_count_exceeds_expected": "observed count exceeds expected",
        "not_observed": "not observed",
    }.get(status, status)


def delivery_observation_payload(observation: DeliveryObservation) -> dict:
    return {
        "engine_id": observation.engine_id,
        "account_ref": observation.account_ref,
        "first_seen_ms": observation.first_seen_ms,
        "last_seen_ms": observation.last_seen_ms,
        "latest_state": observation.latest_state,
        "states": delivery_observation_state_payloads(observation),
        "missing_inferred": observation.missing_inferred,
        "evidence_refs": evidence_refs_payload(observation.evidence_events),
    }


def delivery_observation_state_payloads(observation: DeliveryObservation) -> list[dict]:
    refs_by_event_id = {
        ref["event_id"]: ref for ref in evidence_refs_payload(observation.evidence_events)
    }
    states = []
    for state in observation.states or []:
        state_payload = dict(state)
        state_payload["evidence_ref"] = refs_by_event_id.get(state.get("event_id"))
        states.append(state_payload)
    return states


def delivery_artifact_payload(
    artifact: DeliveryArtifact,
    identity_index: dict[str, set[str]] | None = None,
) -> dict:
    payload = {
        "artifact_id": artifact.artifact_id,
        "artifact_kind": artifact.artifact_kind,
        "first_seen_ms": artifact.first_seen_ms,
        "last_seen_ms": artifact.last_seen_ms,
        "audit_data_modes": artifact.audit_data_modes,
        "author": artifact.author,
        "decoded_payload": artifact.decoded_payload,
        "decoded_app_event": artifact.decoded_app_event,
        "sensitivity": sensitivity_payload(
            delivery_artifact_sensitive_field_paths(artifact),
            audit_data_modes=artifact.audit_data_modes,
        ),
        "evidence_refs": evidence_refs_payload(artifact.evidence_events),
        "engine_observations": [
            delivery_observation_payload(observation)
            for observation in artifact.engine_observations.all()
        ],
        "recipient_expectations": [
            {
                "recipient_scope": expectation.recipient_scope,
                "artifact_kind": expectation.artifact_kind,
                "membership_epoch": expectation.membership_epoch,
                "basis_commit_id": expectation.basis_commit_id,
                "expected_member_refs": expectation.expected_member_refs,
                "expected_pubkeys_hex": expectation.expected_pubkeys_hex,
                "expected_count": expectation.expected_count,
                "evidence_ref": evidence_ref_payload(expectation.evidence_event),
            }
            for expectation in artifact.recipient_expectations.all()
        ],
        "recipient_matrix": delivery_recipient_matrix(artifact, identity_index),
    }
    payload["severity"] = delivery_payload_severity(payload)
    return payload


def network_observation_payload(observation: NetworkObservation) -> dict:
    payload = {
        "direction": observation.direction,
        "phase": observation.phase,
        "message_id": observation.message_id,
        "artifact_kind": observation.artifact_kind,
        "engine_id": observation.engine_id,
        "account_ref": observation.account_ref,
        "wall_time_ms": observation.wall_time_ms,
        "transport_source": observation.transport_source,
        "delivery_plane": observation.delivery_plane,
        "relay_url": observation.relay_url,
        "subscription_id": observation.subscription_id,
        "wire_id": observation.wire_id,
        "wire_kind": observation.wire_kind,
        "wire_pubkey_hex": observation.wire_pubkey_hex,
        "transport_group_id": observation.transport_group_id,
        "nostr_event_id": observation.nostr_event_id,
        "nostr_kind": observation.nostr_kind,
        "nostr_pubkey_hex": observation.nostr_pubkey_hex,
        "gift_wrap_event_id": observation.gift_wrap_event_id,
        "welcome_nostr_event_id": observation.welcome_nostr_event_id,
        "welcome_rumor_event_id": observation.welcome_rumor_event_id,
        "welcome_key_package_tag": observation.welcome_key_package_tag,
        "publish_result_id": observation.publish_result_id,
        "payload_len": observation.payload_len,
        "payload_digest": observation.payload_digest,
        "outcome": observation.outcome,
        "accepted_relay_urls": observation.accepted_relay_urls,
        "failed_relays": observation.failed_relays,
        "required_acks": observation.required_acks,
        "met_required_acks": observation.met_required_acks,
        "sensitivity": sensitivity_payload(
            network_sensitive_field_paths(observation),
            audit_data_modes=(
                [observation.audit_event.audit_data_mode]
                if observation.audit_event.audit_data_mode
                else []
            ),
        ),
        "evidence_ref": evidence_ref_payload(observation.audit_event),
    }
    payload["severity"] = network_payload_severity(payload)
    return payload


def convergence_run_payload(run: ConvergenceRun) -> dict:
    evidence_refs = evidence_refs_payload(run.evidence_events)
    decision_evidence_refs = [
        ref for ref in evidence_refs if ref["event_type"] == "convergence_decision"
    ]
    payload = {
        "run_id": run.run_id,
        "engine_id": run.engine_id,
        "account_ref": run.account_ref,
        "inferred": run.inferred,
        "phase": run.phase,
        "started_at_ms": run.started_at_ms,
        "ended_at_ms": run.ended_at_ms,
        "current_tip_epoch": run.current_tip_epoch,
        "selected_branch_id": run.selected_branch_id,
        "selected_fork_epoch": run.selected_fork_epoch,
        "selected_tip_epoch": run.selected_tip_epoch,
        "max_rewind_commits": run.max_rewind_commits,
        "losing_branch_ids": run.losing_branch_ids,
        "error_kinds": run.error_kinds,
        "sensitivity": sensitivity_payload(convergence_sensitive_field_paths(run)),
        "evidence_refs": evidence_refs,
        "candidates": [
            {
                "branch_id": candidate.branch_id,
                "fork_epoch": candidate.fork_epoch,
                "tip_epoch": candidate.tip_epoch,
                "commit_ids": candidate.commit_ids,
                "commit_count": candidate.commit_count,
                "state_digest": candidate.state_digest,
                "tip_digest": candidate.tip_digest,
                "tip_priority": candidate.tip_priority,
                "tip_committer_ref": candidate.tip_committer_ref,
                "tip_committer_pubkey_hex": candidate.tip_committer_pubkey_hex,
                "retained_anchor_status": candidate.retained_anchor_status,
                "last_input_time_ms": candidate.last_input_time_ms,
                "eligible": candidate.eligible,
                "rejection_reasons": candidate.rejection_reasons,
                "score": candidate.score,
                "app_witnesses": candidate.app_witnesses,
                "evidence_refs": decision_evidence_refs,
            }
            for candidate in run.candidates.all()
        ],
        "rule_evaluations": [
            {
                "rule_name": rule.rule_name,
                "scope": rule.scope,
                "candidate_branch_id": rule.candidate_branch_id,
                "other_candidate_branch_id": rule.other_candidate_branch_id,
                "inputs": rule.inputs,
                "result": rule.result,
                "decisive": rule.decisive,
                "selected_branch_id": rule.selected_branch_id,
                "rejected_branch_id": rule.rejected_branch_id,
                "sequence": rule.sequence,
                "evidence_refs": decision_evidence_refs,
            }
            for rule in run.rule_evaluations.all()
        ],
    }
    payload["severity"] = convergence_payload_severity(payload)
    return payload


def state_delta_payload(delta: StateDelta) -> dict:
    payload = {
        "epoch": delta.epoch,
        "change_kind": delta.change_kind,
        "membership_change_source": delta.membership_change_source,
        "actor_member_ref": delta.actor_member_ref,
        "actor_pubkey_hex": delta.actor_pubkey_hex,
        "subject_member_ref": delta.subject_member_ref,
        "subject_pubkey_hex": delta.subject_pubkey_hex,
        "origin_commit_id": delta.origin_commit_id,
        "fields": delta.fields,
        "component_ids": delta.component_ids,
        "value": delta.value,
        "audit_data_mode": delta.audit_data_mode,
        "wall_time_ms": delta.wall_time_ms,
        "sensitivity": sensitivity_payload(
            state_delta_sensitive_field_paths(delta),
            audit_data_modes=[delta.audit_data_mode] if delta.audit_data_mode else [],
        ),
        "evidence_ref": evidence_ref_payload(delta.audit_event),
    }
    payload["severity"] = state_delta_payload_severity(payload)
    return payload


def epoch_transition_payload(transition: EpochStateTransition) -> dict:
    payload = {
        "engine_id": transition.engine_id,
        "account_ref": transition.account_ref,
        "previous_state": transition.previous_state,
        "new_state": transition.new_state,
        "epoch": transition.epoch,
        "reason": transition.reason,
        "pending_ref": transition.pending_ref,
        "pending_kind": transition.pending_kind,
        "wall_time_ms": transition.wall_time_ms,
        "evidence_ref": evidence_ref_payload(transition.audit_event),
    }
    payload["severity"] = epoch_transition_payload_severity(payload)
    return payload


def evidence_row_payload(event: AuditEvent) -> dict:
    payload = {
        "evidence_ref": evidence_ref_payload(event),
        "parse_status": event.parse_status,
        "validation_error": event.validation_error,
        "seq": event.seq,
        "schema_version": event.schema_version,
        "recorder_session_id": event.recorder_session_id,
        "audit_data_mode": event.audit_data_mode,
        "account_ref": event.account_ref,
        "engine_id": event.engine_id,
        "group_ref": event.group_ref,
        "event_type": event.event_type,
        "message_id": event.msg_id,
        "outbound_msg_id": event.outbound_msg_id,
        "wall_time_ms": event.wall_time_ms,
        "summary": event_row(event)["summary"],
        "sensitivity": sensitivity_payload(
            evidence_row_sensitive_field_paths(event),
            audit_data_modes=[event.audit_data_mode] if event.audit_data_mode else [],
        ),
        "source_file": {
            "id": event.audit_file_id,
            "source_name": event.audit_file.source_name,
            "validation_status": event.audit_file.validation_status,
            "file_sha256": event.audit_file.file_sha256,
        },
    }
    payload["severity"] = evidence_row_payload_severity(payload)
    return payload


def audit_data_mode_change_payload(event: AuditEvent) -> dict:
    kind = event.raw_kind if isinstance(event.raw_kind, dict) else {}
    payload = {
        "engine_id": event.engine_id,
        "account_ref": event.account_ref,
        "recorder_session_id": event.recorder_session_id,
        "wall_time_ms": event.wall_time_ms,
        "previous_mode": str(kind.get("previous_mode") or ""),
        "new_mode": str(kind.get("new_mode") or event.outcome or ""),
        "reason": str(kind.get("reason") or event.reason or ""),
        "recorder_restarted": kind.get("recorder_restarted")
        if isinstance(kind.get("recorder_restarted"), bool)
        else None,
        "audit_data_mode": event.audit_data_mode,
        "sensitivity": sensitivity_payload(
            audit_data_mode_change_sensitive_field_paths(event),
            audit_data_modes=[event.audit_data_mode] if event.audit_data_mode else [],
        ),
        "evidence_ref": evidence_ref_payload(event),
    }
    payload["severity"] = audit_data_mode_change_payload_severity(payload)
    return payload


def bounded_positive_int(value: str | None, *, default: int, maximum: int) -> int:
    try:
        parsed = int(value) if value is not None else default
    except (TypeError, ValueError):
        parsed = default
    return min(max(parsed, 1), maximum)


@login_required
def audit_file_detail(request: HttpRequest, pk: int):
    audit_file = get_object_or_404(
        AuditFile.objects.defer("raw_text").annotate(
            raw_text_preview=Substr("raw_text", 1, RAW_TEXT_PREVIEW_CHARS),
            raw_text_length=Length("raw_text"),
        ),
        pk=pk,
    )
    event_queryset = audit_file.events.order_by("line_number", "id")
    event_page = Paginator(event_queryset, AUDIT_FILE_EVENT_PAGE_SIZE).get_page(
        request.GET.get("page")
    )
    return render(
        request,
        "forensics/audit_file_detail.html",
        {
            "audit_file": audit_file,
            "event_page": event_page,
            "event_rows": [event_row(event) for event in event_page],
            "groups": groups_for_audit_file(audit_file),
            "raw_text_preview": audit_file.raw_text_preview or "",
            "raw_text_preview_chars": RAW_TEXT_PREVIEW_CHARS,
            "raw_text_is_truncated": (audit_file.raw_text_length or 0) > RAW_TEXT_PREVIEW_CHARS,
            "raw_text_char_count": audit_file.raw_text_length or 0,
        },
    )


@login_required
def audit_file_raw_text(request: HttpRequest, pk: int):
    audit_file = get_object_or_404(
        AuditFile.objects.only("id", "source_name", "raw_text"),
        pk=pk,
    )
    filename = raw_text_download_filename(audit_file)
    response = HttpResponse(
        audit_file.raw_text,
        content_type="application/x-ndjson; charset=utf-8",
    )
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


def raw_text_download_filename(audit_file: AuditFile) -> str:
    source_name = (audit_file.source_name or "").rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    source_stem = source_name.rsplit(".", 1)[0] if "." in source_name else source_name
    stem = slugify(source_stem or f"audit-file-{audit_file.pk}")
    return f"{stem or f'audit-file-{audit_file.pk}'}.jsonl"


@login_required
def profile(request: HttpRequest):
    """Let a signed-in user change their own password.

    Usernames are intentionally not editable here: the form only ever touches
    the password of ``request.user``, so a user can never modify another
    account or rename their own.
    """
    if request.method == "POST":
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            # Keep the current session authenticated after the hash rotates.
            update_session_auth_hash(request, user)
            messages.success(request, "Your password has been updated.")
            return redirect("profile")
    else:
        form = PasswordChangeForm(request.user)
    return render(request, "forensics/profile.html", {"form": form})


class MaxDumpSizeUploadHandler(FileUploadHandler):
    """Abort multipart file parsing once the uploaded bytes exceed the app limit.

    The byte counter is *cumulative* across every file part in the request and
    is intentionally not reset in ``new_file``. A single multipart request can
    contain many parts, each individually under ``GOGGLES_MAX_DUMP_BYTES``; a
    per-file cap would let their sum buffer in memory and exhaust the worker.
    Capping the aggregate bounds total resident upload memory at roughly one
    ``GOGGLES_MAX_DUMP_BYTES``, matching the documented single-file ceiling.
    """

    def __init__(self, request: HttpRequest | None = None):
        super().__init__(request)
        self.bytes_received = 0

    def receive_data_chunk(self, raw_data: bytes, start: int) -> bytes:
        self.bytes_received += len(raw_data)
        if self.bytes_received > settings.GOGGLES_MAX_DUMP_BYTES:
            raise RequestDataTooBig(UPLOAD_TOO_LARGE_ERROR)
        return raw_data

    def file_complete(self, file_size: int):
        return None


@csrf_exempt
@require_POST
def api_audit_log_upload(request: HttpRequest, group_slug: str | None = None):
    token = authenticate_request(request)
    if token is None:
        return JsonResponse({"error": "missing or invalid bearer token"}, status=401)

    if not settings.GOGGLES_UPLOADS_ENABLED:
        return JsonResponse(
            {"error": "audit log uploads are temporarily disabled"},
            status=503,
        )

    install_max_dump_size_upload_handler(request)

    try:
        audit_bytes, source_name, content_type = audit_bytes_from_request(request)
    except (RequestDataTooBig, TooManyFilesSent):
        # RequestDataTooBig: a part (or the cumulative upload) exceeded the size
        # cap. TooManyFilesSent: the request carried more parts than
        # DATA_UPLOAD_MAX_NUMBER_FILES. Both are rejected with the same 413 so a
        # multi-part memory-exhaustion attempt cannot bypass the ceiling.
        return JsonResponse({"error": UPLOAD_TOO_LARGE_ERROR}, status=413)
    if len(audit_bytes) > settings.GOGGLES_MAX_DUMP_BYTES:
        return JsonResponse({"error": UPLOAD_TOO_LARGE_ERROR}, status=413)

    fallback_slug, fallback_name = fallback_group_from_request(request, group_slug)
    source_metadata = source_metadata_from_request(request)
    result = ingest_audit_log_bytes(
        dump_bytes=audit_bytes,
        fallback_group_slug=fallback_slug,
        fallback_group_name=fallback_name,
        upload_token=token,
        source_ip=client_ip(request),
        user_agent=request.headers.get("User-Agent", ""),
        source_name=source_name,
        **source_metadata,
        content_type=content_type or request.content_type or "",
    )

    token.mark_used()
    audit_file = result.audit_file
    groups = groups_for_audit_file(audit_file)
    group_slugs = [group.slug for group in groups]
    response_status = 201 if result.created else 200
    if audit_file.validation_status == AuditFile.STATUS_INVALID:
        response_status = 400

    body = {
        "id": audit_file.id,
        "created": result.created,
        "group": group_slugs[0] if len(group_slugs) == 1 else None,
        "groups": group_slugs,
        "artifact_type": "audit_log",
        "source": source_response(audit_file),
        "account_refs": audit_file.account_refs,
        "group_refs": audit_file.group_refs,
        "schema_versions": audit_file.schema_versions,
        "audit_data_modes": audit_file.audit_data_modes,
        "validation_status": audit_file.validation_status,
        "event_count": audit_file.valid_event_count,
        "invalid_event_count": audit_file.invalid_event_count,
        "duplicate_event_count": audit_file.duplicate_event_count,
        "engine_ids": audit_file.engine_ids,
    }
    if audit_file.validation_status == AuditFile.STATUS_INVALID:
        body["error"] = audit_file.validation_error
    return JsonResponse(body, status=response_status)


def authenticate_request(request: HttpRequest) -> UploadToken | None:
    authorization = request.headers.get("Authorization", "")
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer" or not value:
        return None
    return UploadToken.authenticate(value.strip())


def install_max_dump_size_upload_handler(request: HttpRequest) -> None:
    if (request.content_type or "").startswith("multipart/"):
        request.upload_handlers.insert(0, MaxDumpSizeUploadHandler(request))


def audit_bytes_from_request(request: HttpRequest) -> tuple[bytes, str, str]:
    if request.FILES:
        upload = (
            request.FILES.get("audit_log")
            or request.FILES.get("dump")
            or next(iter(request.FILES.values()))
        )
        return read_upload_bytes(upload), upload.name, getattr(upload, "content_type", "")
    if request.body:
        return request.body, "", request.content_type or ""
    return b"", "", ""


def read_upload_bytes(upload) -> bytes:
    max_dump_bytes = settings.GOGGLES_MAX_DUMP_BYTES
    upload_size = getattr(upload, "size", None)
    if upload_size is not None and upload_size > max_dump_bytes:
        raise RequestDataTooBig(UPLOAD_TOO_LARGE_ERROR)

    chunks = []
    total_bytes = 0
    for chunk in upload.chunks():
        total_bytes += len(chunk)
        if total_bytes > max_dump_bytes:
            raise RequestDataTooBig(UPLOAD_TOO_LARGE_ERROR)
        chunks.append(chunk)
    return b"".join(chunks)


def source_metadata_from_request(request: HttpRequest) -> dict[str, str]:
    # Account identity (account_label, account_pubkey_hex) now arrives in the
    # JSONL body via the source_context object and is backfilled onto the
    # AuditFile at ingest -- it is no longer sent as an X-Goggles-* header.
    # Likewise device_id/device_name/upload_trigger/account_npub, when present,
    # ride along in source_context. Only the device label, platform, and app
    # version are still carried as upload headers (alongside Authorization).
    return {
        "source_device_label": request.POST.get("device_label")
        or request.headers.get("X-Goggles-Device-Label", ""),
        "source_platform": request.POST.get("platform")
        or request.headers.get("X-Goggles-Platform", ""),
        "source_app_version": request.POST.get("app_version")
        or request.headers.get("X-Goggles-App-Version", ""),
    }


def source_response(audit_file: AuditFile) -> dict[str, str]:
    response = {
        "account_label": audit_file.source_account_label,
        "device_label": audit_file.source_device_label,
        "platform": audit_file.source_platform,
        "app_version": audit_file.source_app_version,
    }
    optional = {
        "device_id": audit_file.source_device_id,
        "device_name": audit_file.source_device_name,
        "upload_trigger": audit_file.source_upload_trigger,
        "account_pubkey_hex": audit_file.source_account_pubkey_hex,
        "account_npub": audit_file.source_account_npub,
    }
    response.update({key: value for key, value in optional.items() if value})
    return response


def fallback_group_from_request(
    request: HttpRequest,
    group_slug: str | None,
) -> tuple[str | None, str]:
    candidate = (
        group_slug
        or request.POST.get("group")
        or request.GET.get("group")
        or request.headers.get("X-Goggles-Group")
    )
    if not candidate:
        return None, ""
    slug = slugify(candidate)[:160] or "incoming"
    return slug, group_name(candidate)


def group_name(candidate: str) -> str:
    return candidate.replace("-", " ").strip().title() or "Incoming"


def groups_for_audit_file(audit_file: AuditFile):
    # Use the explicit file -> group membership rather than inferring links from
    # stored AuditEvent rows: a duplicate-heavy upload may store zero events for
    # a group whose membership is still recorded on the file
    # (marmot-protocol/goggles#37).
    return list(audit_file.groups.distinct().order_by("slug"))


def client_ip(request: HttpRequest) -> str | None:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Trust only the rightmost hop, appended by our reverse proxy. The
        # leftmost entries are client-controlled and trivially spoofable.
        candidate = forwarded_for.rsplit(",", 1)[-1].strip()
    else:
        candidate = (request.META.get("REMOTE_ADDR") or "").strip()
    if not candidate:
        return None
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return candidate
