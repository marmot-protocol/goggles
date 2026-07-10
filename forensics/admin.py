from django.contrib import admin
from django.urls import reverse
from django.utils.html import format_html
from django.utils.http import urlencode

from .models import (
    AnalysisRun,
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
    PersonalAccessToken,
    RecipientExpectation,
    StateDelta,
    UploadToken,
)

# Hard cap on how much of an audit file's raw JSONL the change page renders.
# A single upload can be tens of megabytes (hundreds of thousands of lines),
# so the full ``raw_text`` is never emitted into the admin form; operators see
# a bounded preview here and reach the complete evidence through the events
# changelist / the stored file.
RAW_TEXT_PREVIEW_CHARS = 2000


@admin.register(AuditGroup)
class AuditGroupAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "group_ref", "created_at", "updated_at")
    search_fields = ("name", "slug", "group_ref", "notes")
    prepopulated_fields = {"slug": ("name",)}


@admin.register(UploadToken)
class UploadTokenAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "token_prefix",
        "is_active",
        "created_at",
        "expires_at",
        "last_used_at",
    )
    list_filter = ("is_active",)
    search_fields = ("name", "token_prefix")
    readonly_fields = ("token_prefix", "token_hash", "created_at", "last_used_at")


@admin.register(PersonalAccessToken)
class PersonalAccessTokenAdmin(admin.ModelAdmin):
    list_display = (
        "name",
        "user",
        "token_prefix",
        "is_active",
        "created_at",
        "expires_at",
        "last_used_at",
    )
    list_filter = ("is_active",)
    search_fields = ("name", "token_prefix", "user__username")
    autocomplete_fields = ("user",)
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
    search_fields = ("file_sha256__exact",)
    show_full_result_count = False
    # ``raw_text`` is excluded from the change form: it holds the entire
    # uploaded JSONL (potentially tens of MB), and Django's default model form
    # would render it into one editable textarea, making the page unbounded by
    # file size (goggles#34). Operators see a bounded ``raw_text_preview``
    # instead and reach the full content through the events changelist.
    exclude = ("raw_text",)
    readonly_fields = (
        "file_sha256",
        "byte_size",
        "created_at",
        "raw_text_preview",
        "events_link",
    )

    def get_queryset(self, request):
        # Admin changelists/autocomplete render metadata only. Keep the complete
        # upload body out of those page-sized query results; the change-page
        # preview intentionally resolves the one deferred body it displays.
        return super().get_queryset(request).defer("raw_text", "user_agent")

    @admin.display(description="Raw text (preview)")
    def raw_text_preview(self, obj):
        """Bounded, read-only preview of the uploaded JSONL.

        The full ``raw_text`` is never rendered on the change page (a single
        upload can be tens of megabytes / hundreds of thousands of lines). We
        show at most ``RAW_TEXT_PREVIEW_CHARS`` characters plus the total size,
        so the page stays usable no matter how large the file is.
        """
        if obj is None or obj.pk is None:
            return "\u2014"
        raw = obj.raw_text or ""
        total_chars = len(raw)
        preview = raw[:RAW_TEXT_PREVIEW_CHARS]
        if total_chars > RAW_TEXT_PREVIEW_CHARS:
            notice = format_html(
                "<p><em>Showing first {} of {} characters "
                "({} bytes). Full content is preserved in storage; "
                "use the events list for line-level detail.</em></p>",
                RAW_TEXT_PREVIEW_CHARS,
                total_chars,
                obj.byte_size,
            )
        else:
            notice = format_html("<p><em>{} characters.</em></p>", total_chars)
        return format_html(
            '{}<pre style="max-height: 24em; overflow: auto; white-space: pre-wrap;">{}</pre>',
            notice,
            preview,
        )

    @admin.display(description="Events")
    def events_link(self, obj):
        """Link out to the filtered AuditEvent changelist instead of inlining.

        A single audit file can hold hundreds of thousands of events, so we
        never render them as an inline formset (no pagination, unbounded query
        and HTML). Operators reach the events through the paginated
        ``AuditEventAdmin`` changelist, pre-filtered to this file. The label is
        static so the change page issues no per-event COUNT query.
        """
        if obj is None or obj.pk is None:
            return "\u2014"
        url = reverse("admin:forensics_auditevent_changelist")
        query = urlencode({"audit_file__id__exact": obj.pk})
        return format_html('<a href="{}?{}">View events</a>', url, query)


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
    list_filter = ("parse_status",)
    search_fields = (
        "account_ref__exact",
        "engine_id__exact",
        "group_ref__exact",
        "msg_id__exact",
        "payload_digest__exact",
        "candidate_digest__exact",
    )
    autocomplete_fields = ("audit_file", "group")
    show_full_result_count = False

    def get_queryset(self, request):
        return (
            super()
            .get_queryset(request)
            .defer(
                "raw_line",
                "raw_event",
                "raw_kind",
                "raw_context",
            )
        )

    def lookup_allowed(self, lookup, value, request):
        if lookup == "audit_file__id__exact":
            return True
        return super().lookup_allowed(lookup, value, request)


@admin.register(AnalysisRun)
class AnalysisRunAdmin(admin.ModelAdmin):
    list_display = ("id", "title", "group", "created_by", "created_at")
    search_fields = ("title", "notes", "group__group_ref")
    autocomplete_fields = ("group", "created_by")
    readonly_fields = ("created_at",)

    def get_queryset(self, request):
        return super().get_queryset(request).defer("report_json")


@admin.register(DeliveryArtifact)
class DeliveryArtifactAdmin(admin.ModelAdmin):
    list_display = ("artifact_id", "artifact_kind", "group", "first_seen_ms", "last_seen_ms")
    search_fields = ("artifact_id__exact",)
    autocomplete_fields = ("group",)
    show_full_result_count = False


@admin.register(DeliveryObservation)
class DeliveryObservationAdmin(admin.ModelAdmin):
    list_display = ("artifact", "engine_id", "latest_state", "first_seen_ms", "last_seen_ms")
    search_fields = ("engine_id__exact", "artifact__artifact_id__exact")
    autocomplete_fields = ("artifact",)
    show_full_result_count = False


@admin.register(RecipientExpectation)
class RecipientExpectationAdmin(admin.ModelAdmin):
    list_display = ("artifact", "recipient_scope", "membership_epoch", "expected_count")
    search_fields = ("artifact__artifact_id__exact",)
    autocomplete_fields = ("artifact", "evidence_event")
    show_full_result_count = False


@admin.register(NetworkObservation)
class NetworkObservationAdmin(admin.ModelAdmin):
    list_display = ("phase", "direction", "message_id", "engine_id", "wall_time_ms")
    search_fields = (
        "message_id__exact",
        "engine_id__exact",
        "nostr_event_id__exact",
        "welcome_nostr_event_id__exact",
        "welcome_rumor_event_id__exact",
        "welcome_key_package_tag__exact",
    )
    autocomplete_fields = ("group", "artifact", "audit_event")
    show_full_result_count = False


@admin.register(ConvergenceRun)
class ConvergenceRunAdmin(admin.ModelAdmin):
    list_display = ("run_id", "group", "engine_id", "phase", "started_at_ms", "ended_at_ms")
    search_fields = ("run_id__exact", "engine_id__exact", "selected_branch_id__exact")
    autocomplete_fields = ("group",)
    show_full_result_count = False


@admin.register(ConvergenceCandidate)
class ConvergenceCandidateAdmin(admin.ModelAdmin):
    list_display = ("run", "branch_id", "fork_epoch", "tip_epoch", "eligible")
    search_fields = ("branch_id__exact",)
    autocomplete_fields = ("run",)
    show_full_result_count = False


@admin.register(ConvergenceRuleEvaluation)
class ConvergenceRuleEvaluationAdmin(admin.ModelAdmin):
    list_display = ("run", "sequence", "rule_name", "decisive", "selected_branch_id")
    search_fields = ("rule_name", "selected_branch_id__exact")
    autocomplete_fields = ("run",)
    show_full_result_count = False


@admin.register(StateDelta)
class StateDeltaAdmin(admin.ModelAdmin):
    list_display = ("change_kind", "membership_change_source", "group", "epoch", "wall_time_ms")
    search_fields = ("origin_commit_id__exact",)
    autocomplete_fields = ("group", "audit_event")
    show_full_result_count = False


@admin.register(EpochStateTransition)
class EpochStateTransitionAdmin(admin.ModelAdmin):
    list_display = ("new_state", "group", "engine_id", "epoch", "wall_time_ms")
    search_fields = ("engine_id__exact",)
    autocomplete_fields = ("group", "audit_event")
    show_full_result_count = False
