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
from django.db.models import Count, Max, Min, Q
from django.db.models.functions import Length, Substr
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.defaultfilters import slugify
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .analysis import (
    FORK_EVENT_TYPES,
    PEELER_EVENT_TYPES,
    agent_state_export_for_group,
    audit_files_for_group,
    color_index,
    engine_initials,
    event_row,
    file_rows_for_group,
    fork_and_convergence_events,
    group_list_rows,
    human_action_groups_for_group,
    message_traces_for_group,
    missing_observations_for_group,
    peeler_and_rejection_events,
    timeline_payload_for_group,
    valid_events_for_group,
)
from .ingest import ingest_audit_log_bytes
from .models import AuditEvent, AuditFile, AuditGroup, UploadToken

UPLOAD_TOO_LARGE_ERROR = "audit log exceeds maximum upload size"
AUDIT_FILE_EVENT_PAGE_SIZE = 100
RAW_TEXT_PREVIEW_CHARS = 32 * 1024
GROUP_TIMELINE_EVENT_PAGE_SIZE = 2_000
GROUP_TIMELINE_EVENT_MAX_PAGE_SIZE = 5_000
GROUP_ENGINE_PREVIEW_LIMIT = 12
GROUP_DETAIL_TAB_TEMPLATES = {
    "actions": "forensics/partials/group_actions.html",
    "messages": "forensics/partials/group_messages.html",
    "integrity": "forensics/partials/group_integrity.html",
    "files": "forensics/partials/group_files.html",
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
    return AuditEvent.objects.filter(
        group=group,
        audit_file__validation_status=AuditFile.STATUS_VALID,
        parse_status=AuditEvent.STATUS_VALID,
    )


def group_detail_shell_context(group: AuditGroup) -> dict:
    valid_events = valid_group_event_queryset(group)
    event_stats = valid_events.aggregate(
        event_count=Count("id"),
        engine_count=Count("engine_id", filter=~Q(engine_id=""), distinct=True),
        group_count=Count("group_ref", filter=~Q(group_ref=""), distinct=True),
        message_count=Count("msg_id", filter=~Q(msg_id=""), distinct=True),
        action_count=Count("id", filter=~Q(human_action_action="")),
    )
    file_count = AuditFile.objects.filter(events__group=group).distinct().count()
    invalid_event_count = AuditEvent.objects.filter(
        group=group, parse_status=AuditEvent.STATUS_INVALID
    ).count()
    integrity_count = valid_events.filter(
        event_type__in=FORK_EVENT_TYPES + PEELER_EVENT_TYPES
    ).count()
    epoch_count = group_epoch_count(valid_events)
    engine_preview = group_engine_preview(valid_events)
    engine_count = event_stats["engine_count"] or 0
    return {
        "summary": {
            "file_count": file_count,
            "event_count": event_stats["event_count"],
            "invalid_event_count": invalid_event_count,
            "engine_count": engine_count,
            "group_count": event_stats["group_count"],
            "message_count": event_stats["message_count"],
        },
        "timeline_summary": {
            "engines": engine_preview,
            "engine_overflow_count": max(engine_count - len(engine_preview), 0),
            "epoch_count": epoch_count,
            "integrity": group_global_integrity_summary(group, valid_events),
        },
        "tab_counts": {
            "timeline": epoch_count,
            "actions": event_stats["action_count"],
            "messages": event_stats["message_count"],
            "integrity": integrity_count,
            "files": file_count,
        },
    }


def group_epoch_count(valid_events) -> int:
    epochs = set()
    for row in valid_events.values_list(
        "epoch",
        "source_epoch",
        "to_epoch",
        "pending_epoch",
        "current_tip_epoch",
        "selected_tip_epoch",
    ):
        epochs.update(value for value in row if value is not None)
    return len(epochs)


def group_engine_preview(valid_events) -> list[dict]:
    rows = (
        valid_events.exclude(engine_id="")
        .values("engine_id")
        .annotate(
            event_count=Count("id"),
            first_event_ms=Min("wall_time_ms"),
            last_event_ms=Max("wall_time_ms"),
            account_ref=Min("account_ref"),
        )
        .order_by("first_event_ms", "engine_id")[:GROUP_ENGINE_PREVIEW_LIMIT]
    )
    engines = []
    for idx, row in enumerate(rows):
        engine_id = row["engine_id"]
        engines.append(
            {
                "engine_id": engine_id,
                "account_ref": row["account_ref"] or "",
                "label": "",
                "color_index": color_index(engine_id),
                "first_event_ms": row["first_event_ms"],
                "last_event_ms": row["last_event_ms"],
                "event_count": row["event_count"],
                "idx": idx,
                "short": engine_id[:8],
                "initials": engine_initials("", engine_id),
            }
        )
    return engines


def group_global_integrity_summary(group: AuditGroup, valid_events=None) -> dict:
    if valid_events is None:
        valid_events = valid_group_event_queryset(group)
    counts = valid_events.aggregate(
        fork_resolution_count=Count("id", filter=Q(event_type="fork_resolution")),
        rollback_count=Count("id", filter=Q(event_type="epoch_rolled_back")),
    )
    fork_count = counts["fork_resolution_count"] or 0
    rollback_count = counts["rollback_count"] or 0
    return {
        "divergent_message_count": group.divergent_message_count,
        # The timeline endpoint is windowed; listing every divergent msg_id would
        # require rebuilding all message traces and reintroduce the unbounded
        # payload path. Keep the cheap whole-group count global and leave the
        # full IDs to the messages tab / export paths.
        "divergent_msg_ids": [],
        "fork_resolution_count": fork_count,
        "rollback_count": rollback_count,
        "has_fork_activity": bool(fork_count or rollback_count),
    }


@login_required
def group_timeline(request: HttpRequest, slug: str):
    group = get_object_or_404(AuditGroup, slug=slug)
    page_size = bounded_positive_int(
        request.GET.get("page_size"),
        default=GROUP_TIMELINE_EVENT_PAGE_SIZE,
        maximum=GROUP_TIMELINE_EVENT_MAX_PAGE_SIZE,
    )
    page = Paginator(valid_events_for_group(group), page_size).get_page(request.GET.get("page"))
    events = list(page.object_list)
    payload = timeline_payload_for_group(group, events, [])
    payload["integrity"] = group_global_integrity_summary(group)
    payload["pagination"] = {
        "page": page.number,
        "page_size": page_size,
        "page_count": page.paginator.num_pages,
        "event_count": page.paginator.count,
        "has_next": page.has_next(),
        "has_previous": page.has_previous(),
    }
    return JsonResponse(payload, json_dumps_params={"separators": (",", ":")})


def bounded_positive_int(value: str | None, *, default: int, maximum: int) -> int:
    try:
        parsed = int(value) if value is not None else default
    except (TypeError, ValueError):
        parsed = default
    return min(max(parsed, 1), maximum)


@login_required
def group_tab(request: HttpRequest, slug: str, tab: str):
    template_name = GROUP_DETAIL_TAB_TEMPLATES.get(tab)
    if template_name is None:
        raise Http404("unknown group detail tab")
    group = get_object_or_404(AuditGroup, slug=slug)
    return render(request, template_name, group_tab_context(group, tab))


def group_tab_context(group: AuditGroup, tab: str) -> dict:
    if tab == "files":
        audit_files = list(audit_files_for_group(group))
        return {"group": group, "audit_files": file_rows_for_group(audit_files, group)}

    events = list(valid_events_for_group(group))
    if tab == "actions":
        return {"group": group, "human_action_groups": human_action_groups_for_group(events)}
    if tab == "messages":
        traces = message_traces_for_group(group, events=events)
        return {
            "group": group,
            "message_traces": traces,
            "missing_observations": missing_observations_for_group(group, traces=traces),
        }
    if tab == "integrity":
        return {
            "group": group,
            "fork_events": fork_and_convergence_events(group, events=events),
            "peeler_events": peeler_and_rejection_events(group, events=events),
        }
    raise Http404("unknown group detail tab")


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
    response = JsonResponse(
        agent_state_export_for_group(group, events, audit_files),
        json_dumps_params=json_dumps_params,
    )
    response["Content-Disposition"] = f'attachment; filename="{group.slug}-agent-state.json"'
    return response


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
    return {
        "source_account_label": request.POST.get("account_label")
        or request.headers.get("X-Goggles-Account-Label", ""),
        "source_device_label": request.POST.get("device_label")
        or request.headers.get("X-Goggles-Device-Label", ""),
        "source_platform": request.POST.get("platform")
        or request.headers.get("X-Goggles-Platform", ""),
        "source_app_version": request.POST.get("app_version")
        or request.headers.get("X-Goggles-App-Version", ""),
    }


def source_response(audit_file: AuditFile) -> dict[str, str]:
    return {
        "account_label": audit_file.source_account_label,
        "device_label": audit_file.source_device_label,
        "platform": audit_file.source_platform,
        "app_version": audit_file.source_app_version,
    }


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
