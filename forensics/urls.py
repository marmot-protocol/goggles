from django.urls import path

from . import views

urlpatterns = [
    path("healthz/", views.healthz, name="healthz"),
    path("", views.group_list, name="group-list"),
    path("profile/", views.profile, name="profile"),
    path("uploads/", views.upload_log_list, name="upload-log-list"),
    path(
        "groups/<slug:slug>/agent-state.json",
        views.group_agent_export,
        name="group-agent-export",
    ),
    path("groups/<slug:slug>/", views.group_detail, name="group-detail"),
    path("audit-files/<int:pk>/", views.audit_file_detail, name="audit-file-detail"),
    path("api/v1/audit-logs/", views.api_audit_log_upload, name="api-audit-log-upload"),
    path(
        "api/v1/groups/<slug:group_slug>/audit-logs/",
        views.api_audit_log_upload,
        name="api-group-audit-log-upload",
    ),
]
