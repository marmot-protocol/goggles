from django.urls import path

from . import views

urlpatterns = [
    path("healthz/", views.healthz, name="healthz"),
    path("", views.group_list, name="group-list"),
    path("profile/", views.profile, name="profile"),
    path("uploads/", views.upload_log_list, name="upload-log-list"),
    path(
        "investigations/accounts/<str:account_ref>/",
        views.account_investigation,
        name="account-investigation",
    ),
    path(
        "investigations/engines/<str:engine_id>/",
        views.engine_investigation,
        name="engine-investigation",
    ),
    path(
        "groups/<slug:slug>/agent-state.json",
        views.group_agent_export,
        name="group-agent-export",
    ),
    path(
        "groups/<slug:slug>/saved-reports/",
        views.create_saved_report,
        name="create-saved-report",
    ),
    path(
        "reports/<int:pk>/",
        views.saved_report_detail,
        name="saved-report-detail",
    ),
    path(
        "reports/<int:pk>/report.json",
        views.saved_report_json,
        name="saved-report-json",
    ),
    path("groups/<slug:slug>/tabs/<slug:tab>/", views.group_tab, name="group-tab"),
    path("groups/<slug:slug>/", views.group_detail, name="group-detail"),
    path("audit-files/<int:pk>/", views.audit_file_detail, name="audit-file-detail"),
    path(
        "audit-files/<int:pk>/raw/",
        views.audit_file_raw_text,
        name="audit-file-raw-text",
    ),
    path("api/v1/audit-logs/", views.api_audit_log_upload, name="api-audit-log-upload"),
    path(
        "api/v1/groups/<slug:group_slug>/audit-logs/",
        views.api_audit_log_upload,
        name="api-group-audit-log-upload",
    ),
    path("api/v1/groups/", views.api_group_list, name="api-group-list"),
    path("api/v1/groups/<slug:slug>/", views.api_group_detail, name="api-group-detail"),
    path(
        "api/v1/groups/<slug:slug>/delivery/",
        views.api_group_delivery,
        name="api-group-delivery",
    ),
    path(
        "api/v1/groups/<slug:slug>/delivery/<path:artifact_id>/",
        views.api_group_delivery_artifact,
        name="api-group-delivery-artifact",
    ),
    path(
        "api/v1/messages/<path:message_id>/",
        views.api_message_detail,
        name="api-message-detail",
    ),
    path(
        "api/v1/groups/<slug:slug>/network/",
        views.api_group_network,
        name="api-group-network",
    ),
    path(
        "api/v1/groups/<slug:slug>/convergence-runs/",
        views.api_group_convergence_runs,
        name="api-group-convergence-runs",
    ),
    path(
        "api/v1/groups/<slug:slug>/convergence-runs/<path:run_id>/",
        views.api_group_convergence_run,
        name="api-group-convergence-run",
    ),
    path(
        "api/v1/groups/<slug:slug>/state-deltas/",
        views.api_group_state,
        name="api-group-state",
    ),
    path(
        "api/v1/groups/<slug:slug>/engines/",
        views.api_group_engines,
        name="api-group-engines",
    ),
    path(
        "api/v1/groups/<slug:slug>/actions/",
        views.api_group_actions,
        name="api-group-actions",
    ),
    path(
        "api/v1/groups/<slug:slug>/projections/",
        views.api_group_projections,
        name="api-group-projections",
    ),
    path(
        "api/v1/groups/<slug:slug>/evidence/",
        views.api_group_evidence,
        name="api-group-evidence",
    ),
    path(
        "api/v1/events/<int:event_id>/evidence/",
        views.api_event_evidence,
        name="api-event-evidence",
    ),
    path(
        "api/v1/accounts/<str:account_ref>/groups/",
        views.api_account_groups,
        name="api-account-groups",
    ),
    path(
        "api/v1/engines/<str:engine_id>/groups/",
        views.api_engine_groups,
        name="api-engine-groups",
    ),
]
