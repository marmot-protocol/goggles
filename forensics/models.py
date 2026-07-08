from __future__ import annotations

from datetime import datetime

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import models
from django.utils import timezone

from . import token_crypto


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
        raw_token, lookup_prefix, secret = token_crypto.generate_raw_token(cls.TOKEN_PREFIX)
        token = cls.objects.create(
            name=name,
            token_prefix=lookup_prefix,
            token_hash=token_crypto.hash_secret(secret),
            expires_at=expires_at,
        )
        return raw_token, token

    @classmethod
    def hash_secret(cls, secret: str, *, key: str | None = None) -> str:
        return token_crypto.hash_secret(secret, key=key)

    def is_expired(self, *, at: datetime | None = None) -> bool:
        return token_crypto.is_expired(self, at=at)

    @classmethod
    def authenticate(cls, raw_token: str | None) -> UploadToken | None:
        return token_crypto.authenticate(cls, raw_token, cls.TOKEN_PREFIX)

    def mark_used(self) -> None:
        self.last_used_at = timezone.now()
        self.save(update_fields=["last_used_at"])


class PersonalAccessToken(models.Model):
    """A user-owned, read-only API credential, self-service from the profile page.

    Distinct from :class:`UploadToken`: that authorizes a device to *upload*; this
    authorizes a person to *read/export*. The two never overlap — separate tables
    and separate raw-token type prefixes, enforced at ``authenticate``.
    """

    TOKEN_PREFIX = "gpat"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="access_tokens",
    )
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
        ordering = ["user", "name", "token_prefix"]

    def __str__(self) -> str:
        state = "active" if self.is_active else "disabled"
        return f"{self.name} ({self.token_prefix}, {state})"

    @classmethod
    def issue(
        cls, name: str, *, user, expires_at: datetime | None = None
    ) -> tuple[str, PersonalAccessToken]:
        raw_token, lookup_prefix, secret = token_crypto.generate_raw_token(cls.TOKEN_PREFIX)
        token = cls.objects.create(
            user=user,
            name=name,
            token_prefix=lookup_prefix,
            token_hash=token_crypto.hash_secret(secret),
            expires_at=expires_at,
        )
        return raw_token, token

    def is_expired(self, *, at: datetime | None = None) -> bool:
        return token_crypto.is_expired(self, at=at)

    @classmethod
    def authenticate(cls, raw_token: str | None) -> PersonalAccessToken | None:
        token = token_crypto.authenticate(cls, raw_token, cls.TOKEN_PREFIX)
        # A token is only as live as its owner: deactivating a user immediately
        # revokes their tokens. This check is model-specific (UploadToken has no
        # owner), so it lives here rather than in the shared helper.
        if token is not None and not token.user.is_active:
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
    source_device_id = models.CharField(max_length=255, blank=True)
    source_device_name = models.CharField(max_length=255, blank=True)
    source_platform = models.CharField(max_length=120, blank=True)
    source_app_version = models.CharField(max_length=120, blank=True)
    source_upload_trigger = models.CharField(max_length=160, blank=True)
    source_account_pubkey_hex = models.CharField(max_length=64, blank=True)
    source_account_npub = models.CharField(max_length=120, blank=True)
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
    audit_data_modes = models.JSONField(default=list, blank=True)

    source_ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    groups = models.ManyToManyField(
        AuditGroup,
        related_name="audit_files_linked",
        blank=True,
    )

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
    recorder_session_id = models.CharField(max_length=160, blank=True)
    audit_data_mode = models.CharField(max_length=80, blank=True)
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
    context_convergence = models.JSONField(default=dict, blank=True)
    context_source = models.JSONField(default=dict, blank=True)

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
            # Keep engine_id second so existing_duplicate_events() can satisfy
            # its projected dedup key from the index after filtering line_hash.
            models.Index(fields=["line_hash", "engine_id"], name="forensics_a_line_hash_eng_idx"),
            models.Index(fields=["account_ref", "engine_id"]),
            models.Index(fields=["audit_data_mode"]),
            models.Index(fields=["recorder_session_id"]),
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
    created_by = models.ForeignKey(
        get_user_model(),
        related_name="saved_investigations",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    title = models.CharField(max_length=160, blank=True)
    notes = models.TextField(blank=True)
    report_json = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        label = self.title or "saved investigation"
        return f"{self.group} {label} at {self.created_at:%Y-%m-%d %H:%M:%S}"


class DeliveryArtifact(models.Model):
    group = models.ForeignKey(
        AuditGroup, related_name="delivery_artifacts", on_delete=models.CASCADE
    )
    artifact_id = models.TextField()
    artifact_kind = models.CharField(max_length=80, blank=True)
    first_seen_ms = models.PositiveBigIntegerField(null=True, blank=True)
    last_seen_ms = models.PositiveBigIntegerField(null=True, blank=True)
    audit_data_modes = models.JSONField(default=list, blank=True)
    author = models.JSONField(default=dict, blank=True)
    decoded_payload = models.JSONField(default=dict, blank=True)
    decoded_app_event = models.JSONField(default=dict, blank=True)
    evidence_events = models.ManyToManyField(AuditEvent, related_name="delivery_artifact_evidence")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["first_seen_ms", "artifact_id"]
        constraints = [
            models.UniqueConstraint(
                fields=["group", "artifact_id"],
                name="unique_delivery_artifact_per_group",
            )
        ]
        indexes = [
            models.Index(fields=["group", "artifact_kind"]),
            models.Index(fields=["artifact_id"]),
            models.Index(fields=["first_seen_ms"]),
        ]

    def __str__(self) -> str:
        return f"{self.group_id}:{self.artifact_id[:16]}"


class DeliveryObservation(models.Model):
    artifact = models.ForeignKey(
        DeliveryArtifact,
        related_name="engine_observations",
        on_delete=models.CASCADE,
    )
    engine_id = models.CharField(max_length=64)
    account_ref = models.CharField(max_length=64, blank=True)
    first_seen_ms = models.PositiveBigIntegerField(null=True, blank=True)
    last_seen_ms = models.PositiveBigIntegerField(null=True, blank=True)
    states = models.JSONField(default=list, blank=True)
    latest_state = models.CharField(max_length=120, blank=True)
    missing_inferred = models.BooleanField(default=False)
    evidence_events = models.ManyToManyField(
        AuditEvent, related_name="delivery_observation_evidence"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["artifact_id", "engine_id"]
        constraints = [
            models.UniqueConstraint(
                fields=["artifact", "engine_id"],
                name="unique_delivery_observation_per_engine",
            )
        ]
        indexes = [
            models.Index(fields=["engine_id", "latest_state"]),
            models.Index(fields=["first_seen_ms"]),
        ]

    def __str__(self) -> str:
        return f"{self.artifact_id}:{self.engine_id[:8]}:{self.latest_state}"


class RecipientExpectation(models.Model):
    artifact = models.ForeignKey(
        DeliveryArtifact,
        related_name="recipient_expectations",
        on_delete=models.CASCADE,
    )
    artifact_kind = models.CharField(max_length=80, blank=True)
    recipient_scope = models.CharField(max_length=80)
    membership_epoch = models.PositiveBigIntegerField(null=True, blank=True)
    basis_commit_id = models.TextField(blank=True)
    expected_member_refs = models.JSONField(default=list, blank=True)
    expected_pubkeys_hex = models.JSONField(default=list, blank=True)
    expected_count = models.PositiveBigIntegerField(null=True, blank=True)
    evidence_event = models.ForeignKey(
        AuditEvent,
        related_name="recipient_expectations",
        on_delete=models.CASCADE,
    )

    class Meta:
        ordering = ["artifact_id", "id"]
        indexes = [
            models.Index(fields=["recipient_scope"]),
            models.Index(fields=["membership_epoch"]),
        ]


class NetworkObservation(models.Model):
    group = models.ForeignKey(
        AuditGroup, related_name="network_observations", on_delete=models.CASCADE
    )
    artifact = models.ForeignKey(
        DeliveryArtifact,
        related_name="network_observations",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    audit_event = models.ForeignKey(
        AuditEvent,
        related_name="network_observations",
        on_delete=models.CASCADE,
    )
    direction = models.CharField(max_length=40)
    phase = models.CharField(max_length=80)
    message_id = models.TextField(blank=True)
    artifact_kind = models.CharField(max_length=80, blank=True)
    engine_id = models.CharField(max_length=64, blank=True)
    account_ref = models.CharField(max_length=64, blank=True)
    wall_time_ms = models.PositiveBigIntegerField(null=True, blank=True)
    transport_source = models.CharField(max_length=80, blank=True)
    delivery_plane = models.CharField(max_length=80, blank=True)
    relay_url = models.TextField(blank=True)
    subscription_id = models.CharField(max_length=255, blank=True)
    wire_id = models.TextField(blank=True)
    wire_kind = models.CharField(max_length=80, blank=True)
    wire_pubkey_hex = models.CharField(max_length=64, blank=True)
    transport_group_id = models.TextField(blank=True)
    nostr_event_id = models.CharField(max_length=64, blank=True)
    nostr_kind = models.PositiveBigIntegerField(null=True, blank=True)
    nostr_pubkey_hex = models.CharField(max_length=64, blank=True)
    gift_wrap_event_id = models.CharField(max_length=64, blank=True)
    welcome_nostr_event_id = models.CharField(max_length=64, blank=True)
    welcome_rumor_event_id = models.CharField(max_length=64, blank=True)
    welcome_key_package_tag = models.TextField(blank=True)
    publish_result_id = models.CharField(max_length=255, blank=True)
    payload_len = models.PositiveBigIntegerField(null=True, blank=True)
    payload_digest = models.CharField(max_length=128, blank=True)
    outcome = models.CharField(max_length=120, blank=True)
    accepted_relay_urls = models.JSONField(default=list, blank=True)
    failed_relays = models.JSONField(default=list, blank=True)
    required_acks = models.PositiveIntegerField(null=True, blank=True)
    met_required_acks = models.BooleanField(null=True, blank=True)

    class Meta:
        ordering = ["wall_time_ms", "engine_id", "id"]
        indexes = [
            models.Index(fields=["group", "phase"]),
            models.Index(fields=["message_id"]),
            models.Index(fields=["engine_id", "wall_time_ms"]),
            models.Index(fields=["nostr_event_id"]),
            models.Index(fields=["relay_url"]),
        ]


class ConvergenceRun(models.Model):
    group = models.ForeignKey(AuditGroup, related_name="convergence_runs", on_delete=models.CASCADE)
    run_id = models.CharField(max_length=160)
    engine_id = models.CharField(max_length=64)
    account_ref = models.CharField(max_length=64, blank=True)
    inferred = models.BooleanField(default=False)
    phase = models.CharField(max_length=80, blank=True)
    started_at_ms = models.PositiveBigIntegerField(null=True, blank=True)
    ended_at_ms = models.PositiveBigIntegerField(null=True, blank=True)
    current_tip_epoch = models.PositiveBigIntegerField(null=True, blank=True)
    selected_branch_id = models.CharField(max_length=256, blank=True)
    selected_fork_epoch = models.PositiveBigIntegerField(null=True, blank=True)
    selected_tip_epoch = models.PositiveBigIntegerField(null=True, blank=True)
    max_rewind_commits = models.PositiveBigIntegerField(null=True, blank=True)
    losing_branch_ids = models.JSONField(default=list, blank=True)
    error_kinds = models.JSONField(default=list, blank=True)
    evidence_events = models.ManyToManyField(AuditEvent, related_name="convergence_run_evidence")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["started_at_ms", "engine_id", "run_id"]
        constraints = [
            models.UniqueConstraint(
                fields=["group", "engine_id", "run_id"],
                name="unique_convergence_run_per_engine",
            )
        ]
        indexes = [
            models.Index(fields=["group", "phase"]),
            models.Index(fields=["engine_id", "started_at_ms"]),
        ]


class ConvergenceCandidate(models.Model):
    run = models.ForeignKey(ConvergenceRun, related_name="candidates", on_delete=models.CASCADE)
    branch_id = models.CharField(max_length=256)
    fork_epoch = models.PositiveBigIntegerField(null=True, blank=True)
    tip_epoch = models.PositiveBigIntegerField(null=True, blank=True)
    commit_ids = models.JSONField(default=list, blank=True)
    commit_count = models.PositiveBigIntegerField(null=True, blank=True)
    state_digest = models.CharField(max_length=64, blank=True)
    tip_digest = models.CharField(max_length=64, blank=True)
    tip_priority = models.CharField(max_length=80, blank=True)
    tip_committer_ref = models.CharField(max_length=32, blank=True)
    tip_committer_pubkey_hex = models.CharField(max_length=64, blank=True)
    retained_anchor_status = models.CharField(max_length=120, blank=True)
    last_input_time_ms = models.PositiveBigIntegerField(null=True, blank=True)
    eligible = models.BooleanField(null=True, blank=True)
    rejection_reasons = models.JSONField(default=list, blank=True)
    score = models.JSONField(default=dict, blank=True)
    app_witnesses = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ["run_id", "fork_epoch", "tip_epoch", "branch_id"]
        constraints = [
            models.UniqueConstraint(
                fields=["run", "branch_id"],
                name="unique_convergence_candidate_per_run",
            )
        ]


class ConvergenceRuleEvaluation(models.Model):
    run = models.ForeignKey(
        ConvergenceRun,
        related_name="rule_evaluations",
        on_delete=models.CASCADE,
    )
    rule_name = models.CharField(max_length=160)
    scope = models.CharField(max_length=80, blank=True)
    candidate_branch_id = models.CharField(max_length=256, blank=True)
    other_candidate_branch_id = models.CharField(max_length=256, blank=True)
    inputs = models.JSONField(default=dict, blank=True)
    result = models.JSONField(default=dict, blank=True)
    decisive = models.BooleanField(default=False)
    selected_branch_id = models.CharField(max_length=256, blank=True)
    rejected_branch_id = models.CharField(max_length=256, blank=True)
    sequence = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["run_id", "sequence", "id"]
        indexes = [
            models.Index(fields=["rule_name"]),
            models.Index(fields=["decisive"]),
        ]


class StateDelta(models.Model):
    group = models.ForeignKey(AuditGroup, related_name="state_deltas", on_delete=models.CASCADE)
    audit_event = models.ForeignKey(
        AuditEvent, related_name="state_deltas", on_delete=models.CASCADE
    )
    epoch = models.PositiveBigIntegerField(null=True, blank=True)
    change_kind = models.CharField(max_length=120)
    membership_change_source = models.CharField(max_length=80, blank=True)
    actor_member_ref = models.CharField(max_length=32, blank=True)
    actor_pubkey_hex = models.CharField(max_length=64, blank=True)
    subject_member_ref = models.CharField(max_length=32, blank=True)
    subject_pubkey_hex = models.CharField(max_length=64, blank=True)
    origin_commit_id = models.TextField(blank=True)
    fields = models.JSONField(default=list, blank=True)
    component_ids = models.JSONField(default=list, blank=True)
    value = models.JSONField(default=dict, blank=True)
    audit_data_mode = models.CharField(max_length=80, blank=True)
    wall_time_ms = models.PositiveBigIntegerField(null=True, blank=True)

    class Meta:
        ordering = ["epoch", "wall_time_ms", "id"]
        indexes = [
            models.Index(fields=["group", "epoch"]),
            models.Index(fields=["change_kind"]),
            models.Index(fields=["origin_commit_id"]),
        ]


class EpochStateTransition(models.Model):
    group = models.ForeignKey(
        AuditGroup,
        related_name="epoch_state_transitions",
        on_delete=models.CASCADE,
    )
    audit_event = models.ForeignKey(
        AuditEvent,
        related_name="epoch_state_transitions",
        on_delete=models.CASCADE,
    )
    engine_id = models.CharField(max_length=64)
    account_ref = models.CharField(max_length=64, blank=True)
    previous_state = models.CharField(max_length=120, blank=True)
    new_state = models.CharField(max_length=120)
    epoch = models.PositiveBigIntegerField(null=True, blank=True)
    reason = models.CharField(max_length=240, blank=True)
    pending_ref = models.PositiveBigIntegerField(null=True, blank=True)
    pending_kind = models.CharField(max_length=120, blank=True)
    wall_time_ms = models.PositiveBigIntegerField(null=True, blank=True)

    class Meta:
        ordering = ["wall_time_ms", "engine_id", "id"]
        indexes = [
            models.Index(fields=["group", "epoch"]),
            models.Index(fields=["engine_id", "wall_time_ms"]),
            models.Index(fields=["new_state"]),
        ]
