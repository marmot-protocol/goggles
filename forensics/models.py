from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import models
from django.utils import timezone


class AuditGroup(models.Model):
    name = models.CharField(max_length=200)
    slug = models.SlugField(max_length=160, unique=True)
    group_ref = models.CharField(max_length=512, blank=True, db_index=True)
    divergent_message_count = models.PositiveIntegerField(default=0)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at", "-created_at"]

    def __str__(self) -> str:
        return self.name


class UploadToken(models.Model):
    TOKEN_PREFIX = "goggles"

    name = models.CharField(max_length=120)
    token_prefix = models.CharField(max_length=16, unique=True)
    token_hash = models.CharField(max_length=128)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Optional expiry. Null means the token never expires.",
    )
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["name", "token_prefix"]

    def __str__(self) -> str:
        state = "active" if self.is_active else "disabled"
        return f"{self.name} ({self.token_prefix}, {state})"

    @classmethod
    def issue(cls, name: str, expires_at: datetime | None = None) -> tuple[str, UploadToken]:
        prefix = secrets.token_hex(4)
        secret = secrets.token_urlsafe(32)
        raw_token = f"{cls.TOKEN_PREFIX}_{prefix}_{secret}"
        token = cls.objects.create(
            name=name,
            token_prefix=prefix,
            token_hash=cls.hash_secret(secret),
            expires_at=expires_at,
        )
        return raw_token, token

    @classmethod
    def hash_secret(cls, secret: str) -> str:
        # Keyed on GOGGLES_TOKEN_HASH_KEY (a dedicated, independently
        # rotatable secret) rather than SECRET_KEY, so rotating the Django
        # signing key does not invalidate every issued upload token. The
        # setting falls back to SECRET_KEY when unset, preserving existing
        # hashes for deployments that have not provisioned a dedicated key.
        key = settings.GOGGLES_TOKEN_HASH_KEY.encode("utf-8")
        return hmac.new(key, secret.encode("utf-8"), hashlib.sha256).hexdigest()

    def is_expired(self, *, at: datetime | None = None) -> bool:
        if self.expires_at is None:
            return False
        return (at or timezone.now()) >= self.expires_at

    @classmethod
    def authenticate(cls, raw_token: str | None) -> UploadToken | None:
        if not raw_token:
            return None
        parts = raw_token.split("_", 2)
        if len(parts) != 3 or parts[0] != cls.TOKEN_PREFIX:
            return None
        _, prefix, secret = parts
        try:
            token = cls.objects.get(token_prefix=prefix, is_active=True)
        except cls.DoesNotExist:
            return None
        if not hmac.compare_digest(token.token_hash, cls.hash_secret(secret)):
            return None
        if token.is_expired():
            return None
        return token

    def mark_used(self) -> None:
        self.last_used_at = timezone.now()
        self.save(update_fields=["last_used_at"])


class AuditFile(models.Model):
    STATUS_VALID = "valid"
    STATUS_INVALID = "invalid"
    STATUS_CHOICES = [(STATUS_VALID, "Valid"), (STATUS_INVALID, "Invalid")]

    upload_token = models.ForeignKey(
        UploadToken,
        related_name="audit_files",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    uploaded_by = models.ForeignKey(
        get_user_model(),
        related_name="audit_log_uploads",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )

    source_name = models.CharField(max_length=255, blank=True)
    source_account_label = models.CharField(max_length=255, blank=True)
    source_device_label = models.CharField(max_length=255, blank=True)
    source_platform = models.CharField(max_length=120, blank=True)
    source_app_version = models.CharField(max_length=120, blank=True)
    content_type = models.CharField(max_length=120, blank=True)
    file_sha256 = models.CharField(max_length=64)
    byte_size = models.PositiveBigIntegerField()
    raw_text = models.TextField()

    validation_status = models.CharField(
        max_length=16,
        choices=STATUS_CHOICES,
        default=STATUS_VALID,
    )
    validation_error = models.TextField(blank=True)
    total_line_count = models.PositiveIntegerField(default=0)
    valid_event_count = models.PositiveIntegerField(default=0)
    invalid_event_count = models.PositiveIntegerField(default=0)
    duplicate_event_count = models.PositiveIntegerField(default=0)

    first_line_number = models.PositiveIntegerField(null=True, blank=True)
    last_line_number = models.PositiveIntegerField(null=True, blank=True)
    first_seq = models.PositiveBigIntegerField(null=True, blank=True)
    last_seq = models.PositiveBigIntegerField(null=True, blank=True)
    first_wall_time_ms = models.PositiveBigIntegerField(null=True, blank=True)
    last_wall_time_ms = models.PositiveBigIntegerField(null=True, blank=True)
    account_refs = models.JSONField(default=list, blank=True)
    engine_ids = models.JSONField(default=list, blank=True)
    group_refs = models.JSONField(default=list, blank=True)
    schema_versions = models.JSONField(default=list, blank=True)

    source_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["file_sha256"],
                name="unique_audit_file_sha256",
            )
        ]
        indexes = [
            models.Index(fields=["validation_status"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self) -> str:
        return f"audit file {self.id} ({self.validation_status})"


class AuditEvent(models.Model):
    STATUS_VALID = "valid"
    STATUS_INVALID = "invalid"
    STATUS_CHOICES = [(STATUS_VALID, "Valid"), (STATUS_INVALID, "Invalid")]

    group = models.ForeignKey(
        AuditGroup,
        related_name="audit_events",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    audit_file = models.ForeignKey(AuditFile, related_name="events", on_delete=models.CASCADE)
    line_number = models.PositiveIntegerField()
    line_hash = models.CharField(max_length=64)
    raw_line = models.TextField()
    raw_event = models.JSONField(null=True, blank=True)
    raw_kind = models.JSONField(default=dict, blank=True)
    raw_context = models.JSONField(default=dict, blank=True)

    parse_status = models.CharField(
        max_length=16,
        choices=STATUS_CHOICES,
        default=STATUS_VALID,
    )
    validation_error = models.TextField(blank=True)

    schema_version = models.CharField(max_length=80, blank=True)
    seq = models.PositiveBigIntegerField(null=True, blank=True)
    wall_time_ms = models.PositiveBigIntegerField(null=True, blank=True)
    account_ref = models.CharField(max_length=64, blank=True)
    engine_id = models.CharField(max_length=64, blank=True)
    group_ref = models.TextField(blank=True)
    event_type = models.CharField(max_length=80, blank=True)
    context_operation_id = models.CharField(max_length=160, blank=True)
    context_human_action = models.JSONField(default=dict, blank=True)
    context_transport = models.JSONField(default=dict, blank=True)
    context_engine = models.JSONField(default=dict, blank=True)
    context_group = models.JSONField(default=dict, blank=True)

    human_action_action = models.CharField(max_length=120, blank=True)
    human_action_origin = models.CharField(max_length=80, blank=True)
    human_action_phase = models.CharField(max_length=80, blank=True)
    human_action_fields = models.JSONField(default=list, blank=True)
    human_action_component_ids = models.JSONField(default=list, blank=True)
    human_action_target_count = models.PositiveIntegerField(null=True, blank=True)
    human_action_message_ids = models.JSONField(default=list, blank=True)

    msg_id = models.TextField(blank=True)
    outbound_msg_id = models.TextField(blank=True)
    outbound_welcome_msg_ids = models.JSONField(default=list, blank=True)
    target_kind = models.CharField(max_length=120, blank=True)
    relay_urls = models.JSONField(default=list, blank=True)
    accepted_relay_urls = models.JSONField(default=list, blank=True)
    failed_relays = models.JSONField(default=list, blank=True)
    required_acks = models.PositiveIntegerField(null=True, blank=True)
    met_required_acks = models.BooleanField(null=True, blank=True)

    epoch = models.PositiveBigIntegerField(null=True, blank=True)
    source_epoch = models.PositiveBigIntegerField(null=True, blank=True)
    from_epoch = models.PositiveBigIntegerField(null=True, blank=True)
    to_epoch = models.PositiveBigIntegerField(null=True, blank=True)
    pending_epoch = models.PositiveBigIntegerField(null=True, blank=True)
    restored_epoch = models.PositiveBigIntegerField(null=True, blank=True)
    current_tip_epoch = models.PositiveBigIntegerField(null=True, blank=True)
    selected_fork_epoch = models.PositiveBigIntegerField(null=True, blank=True)
    selected_tip_epoch = models.PositiveBigIntegerField(null=True, blank=True)

    payload_len = models.PositiveBigIntegerField(null=True, blank=True)
    payload_digest = models.CharField(max_length=128, blank=True)
    candidate_digest = models.CharField(max_length=128, blank=True)
    incumbent_digest = models.CharField(max_length=128, blank=True)

    envelope_kind = models.CharField(max_length=120, blank=True)
    outcome = models.CharField(max_length=120, blank=True)
    outcome_kind = models.CharField(max_length=120, blank=True)
    stale_reason = models.CharField(max_length=160, blank=True)
    decision = models.CharField(max_length=120, blank=True)
    reason = models.CharField(max_length=240, blank=True)
    winner = models.CharField(max_length=120, blank=True)
    new_state = models.CharField(max_length=120, blank=True)
    pending_kind = models.CharField(max_length=120, blank=True)
    intent_kind = models.CharField(max_length=120, blank=True)
    result_kind = models.CharField(max_length=120, blank=True)
    proposal_kind = models.CharField(max_length=120, blank=True)
    snapshot_name = models.CharField(max_length=256, blank=True)
    selected_branch_id = models.CharField(max_length=256, blank=True)
    detail = models.TextField(blank=True)
    fallback_snapshot_used = models.BooleanField(null=True, blank=True)
    invalidated_msg_id = models.TextField(blank=True)
    max_rewind_commits = models.PositiveBigIntegerField(null=True, blank=True)
    candidate_count = models.PositiveIntegerField(null=True, blank=True)
    eligible_count = models.PositiveIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["wall_time_ms", "engine_id", "line_number", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["audit_file", "line_number"],
                name="unique_audit_event_line_per_file",
            )
        ]
        indexes = [
            models.Index(fields=["line_hash", "engine_id"], name="forensics_a_line_hash_eng_idx"),
            models.Index(fields=["account_ref", "engine_id"]),
            models.Index(fields=["engine_id", "wall_time_ms"]),
            models.Index(fields=["group_ref", "wall_time_ms"]),
            models.Index(fields=["msg_id"]),
            models.Index(fields=["event_type"]),
            models.Index(fields=["human_action_action"]),
            models.Index(fields=["context_operation_id"]),
            models.Index(fields=["source_epoch"]),
            models.Index(fields=["payload_digest"]),
            models.Index(fields=["candidate_digest"]),
            models.Index(fields=["parse_status"]),
        ]

    def __str__(self) -> str:
        label = self.event_type or self.parse_status
        return f"{self.engine_id} line {self.line_number} {label}"


class AnalysisRun(models.Model):
    group = models.ForeignKey(AuditGroup, related_name="analysis_runs", on_delete=models.CASCADE)
    report_json = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.group} analysis at {self.created_at:%Y-%m-%d %H:%M:%S}"
