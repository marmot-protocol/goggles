from django.contrib import admin
from django.urls import reverse
from django.utils.html import format_html
from django.utils.http import urlencode

from .models import AnalysisRun, AuditEvent, AuditFile, AuditGroup, UploadToken


@admin.register(AuditGroup)
class AuditGroupAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "group_ref", "created_at", "updated_at")
    search_fields = ("name", "slug", "group_ref", "notes")
    prepopulated_fields = {"slug": ("name",)}


@admin.register(UploadToken)
class UploadTokenAdmin(admin.ModelAdmin):
    list_display = ("name", "token_prefix", "is_active", "created_at", "last_used_at")
    list_filter = ("is_active",)
    search_fields = ("name", "token_prefix")
    readonly_fields = ("token_prefix", "token_hash", "created_at", "last_used_at")


@admin.register(AuditFile)
class AuditFileAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "source_name",
        "source_device_label",
        "validation_status",
        "valid_event_count",
        "invalid_event_count",
        "duplicate_event_count",
        "created_at",
    )
    list_filter = ("validation_status",)
    search_fields = (
        "source_name",
        "source_account_label",
        "source_device_label",
        "source_platform",
        "file_sha256",
        "account_refs",
        "engine_ids",
        "group_refs",
    )
    readonly_fields = ("file_sha256", "byte_size", "created_at", "events_link")

    @admin.display(description="Events")
    def events_link(self, obj):
        """Link out to the filtered AuditEvent changelist instead of inlining.

        A single audit file can hold hundreds of thousands of events, so we
        never render them as an inline formset (no pagination, unbounded query
        and HTML). Operators reach the events through the paginated
        ``AuditEventAdmin`` changelist, pre-filtered to this file.
        """
        if obj is None or obj.pk is None:
            return "\u2014"
        url = reverse("admin:forensics_auditevent_changelist")
        query = urlencode({"audit_file__id__exact": obj.pk})
        count = obj.events.count()
        return format_html(
            '<a href="{}?{}">View {} event{}</a>',
            url,
            query,
            count,
            "" if count == 1 else "s",
        )


@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    list_display = (
        "line_number",
        "event_type",
        "parse_status",
        "account_ref",
        "engine_id",
        "msg_id",
        "wall_time_ms",
    )
    list_filter = (
        "parse_status",
        "event_type",
        "outcome",
        "outcome_kind",
        "new_state",
        "audit_file",
    )
    search_fields = (
        "account_ref",
        "engine_id",
        "group_ref",
        "msg_id",
        "payload_digest",
        "candidate_digest",
        "incumbent_digest",
        "raw_line",
    )


@admin.register(AnalysisRun)
class AnalysisRunAdmin(admin.ModelAdmin):
    list_display = ("group", "created_at")
    readonly_fields = ("created_at",)
