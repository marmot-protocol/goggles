from __future__ import annotations

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.core.exceptions import RequestDataTooBig
from django.core.files.uploadhandler import FileUploadHandler
from django.db.models import Count, Q
from django.http import HttpRequest, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.template.defaultfilters import slugify
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .analysis import (
    agent_state_export_for_group,
    audit_files_for_group,
    event_row,
    file_rows_for_group,
    fork_and_convergence_events,
    group_list_rows,
    group_summary,
    human_action_groups_for_group,
    message_traces_for_group,
    missing_observations_for_group,
    peeler_and_rejection_events,
    timeline_payload_for_group,
    valid_events_for_group,
)
from .ingest import ingest_audit_log_bytes
from .models import AuditFile, AuditGroup, UploadToken

UPLOAD_TOO_LARGE_ERROR = "audit log exceeds maximum upload size"


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
        AuditFile.objects.select_related("upload_token", "uploaded_by")
        .annotate(group_count=Count("events__group", distinct=True))
        .order_by("-created_at", "-id")[:100]
    )
    stats = AuditFile.objects.aggregate(
        total=Count("id"),
        valid=Count("id", filter=Q(validation_status=AuditFile.STATUS_VALID)),
        invalid=Count("id", filter=Q(validation_status=AuditFile.STATUS_INVALID)),
    )
    latest_upload = AuditFile.objects.order_by("-created_at", "-id").first()
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
    audit_files = list(audit_files_for_group(group))
    events = list(valid_events_for_group(group))
    traces = message_traces_for_group(group, events=events)
    return render(
        request,
        "forensics/group_detail.html",
        {
            "group": group,
            "summary": group_summary(group, audit_files, events=events),
            "audit_files": file_rows_for_group(audit_files, group),
            "human_action_groups": human_action_groups_for_group(events),
            "message_traces": traces,
            "missing_observations": missing_observations_for_group(group, traces=traces),
            "fork_events": fork_and_convergence_events(group, events=events),
            "peeler_events": peeler_and_rejection_events(group, events=events),
            "timeline_payload": timeline_payload_for_group(group, events, audit_files),
        },
    )


@login_required
def group_agent_export(request: HttpRequest, slug: str):
    group = get_object_or_404(AuditGroup, slug=slug)
    audit_files = list(audit_files_for_group(group))
    events = list(valid_events_for_group(group))
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
        AuditFile.objects.prefetch_related("events__group"),
        pk=pk,
    )
    return render(
        request,
        "forensics/audit_file_detail.html",
        {
            "audit_file": audit_file,
            "event_rows": [event_row(event) for event in audit_file.events.all()],
            "groups": groups_for_audit_file(audit_file),
        },
    )


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
    """Abort multipart file parsing once a single uploaded file exceeds the app limit."""

    def __init__(self, request: HttpRequest | None = None):
        super().__init__(request)
        self.bytes_received = 0

    def new_file(self, *args, **kwargs):
        super().new_file(*args, **kwargs)
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
    except RequestDataTooBig:
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
    return list(
        AuditGroup.objects.filter(audit_events__audit_file=audit_file).distinct().order_by("slug")
    )


def client_ip(request: HttpRequest) -> str | None:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.META.get("REMOTE_ADDR")
