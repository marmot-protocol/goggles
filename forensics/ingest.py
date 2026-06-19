from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from django.db import IntegrityError, transaction
from django.db.backends.base.operations import BaseDatabaseOperations
from django.template.defaultfilters import slugify
from django.utils import timezone

from .models import AuditEvent, AuditFile, AuditGroup, UploadToken

AUDIT_SCHEMA_VERSION = "marmot-forensics-audit/v1"
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# Upper bound for millisecond epoch timestamps (``wall_time_ms``). A value can
# fit the ``bigint`` column (~9.2e18) and still be nonsense as a millis-since-
# epoch instant. Downstream consumers materialize it: the server builds a
# ``datetime`` (year must be <= 9999, i.e. ms < ~2.534e14) and the timeline JS
# builds a ``Date`` (abs ms <= 8.64e15). A garbage value past either ceiling
# would crash a shared page (the groups landing 500) or a per-group timeline
# (blank render). Bound ingest at the year-2100 mark -- comfortably inside both
# ceilings and far beyond any plausible real audit-log timestamp -- and
# quarantine anything past it like other schema violations.
MAX_WALL_TIME_MS = 4_102_444_800_000  # 2100-01-01T00:00:00Z

# Maximum bracket/brace nesting depth we will hand to ``json.loads``. The audit
# schema is shallow (event -> kind/context -> at most a small nested object or
# list), so a few hundred levels is far more headroom than any legitimate line
# needs while staying well below Python's recursion limit. Deeply-nested input
# (e.g. ``[[[[...]]]]`` thousands of levels deep) makes ``json.loads`` recurse
# until it raises ``RecursionError`` -- which is *not* a ``JSONDecodeError`` --
# and would otherwise escape the parser as an uncaught 500, losing the raw
# upload instead of quarantining it. We reject such lines up front with a clear
# validation error so they are quarantined like any other malformed JSON.
MAX_JSON_NESTING_DEPTH = 200


def max_json_nesting_depth(raw: str) -> int:
    """Return the maximum bracket/brace nesting depth of a JSON text.

    Scans the raw characters, ignoring brackets that appear inside string
    literals (so a ``[`` inside a ``"..."`` value does not inflate the count).
    This is a cheap O(n) pre-check used to reject pathologically deep input
    *before* ``json.loads`` ever recurses into it, making the guard
    deterministic regardless of the interpreter's recursion limit.
    """
    depth = 0
    max_depth = 0
    in_string = False
    escaped = False
    for ch in raw:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > max_depth:
                max_depth = depth
        elif ch in "]}":
            if depth > 0:
                depth -= 1
    return max_depth


def loads_audit_json(raw: str) -> Any:
    """Parse one JSONL line, rejecting pathologically deep nesting.

    Behaves like ``json.loads`` for ordinary input but raises ``ValueError``
    (the base class of ``json.JSONDecodeError``) when the input nests deeper
    than :data:`MAX_JSON_NESTING_DEPTH`, so callers that already handle
    malformed JSON via ``except ValueError`` / ``except json.JSONDecodeError``
    treat over-nested input the same way instead of letting a ``RecursionError``
    escape.
    """
    if max_json_nesting_depth(raw) > MAX_JSON_NESTING_DEPTH:
        raise ValueError(f"nesting exceeds maximum depth of {MAX_JSON_NESTING_DEPTH}")
    return json.loads(raw)


@dataclass(frozen=True)
class IngestionResult:
    audit_file: AuditFile
    created: bool


@dataclass
class ParsedLine:
    line_number: int
    raw_line: str
    line_hash: str
    data: dict[str, Any] | None
    normalized: dict[str, Any]
    errors: list[str]


def iter_jsonl_record_lines(raw_text: str) -> Iterator[str]:
    """Yield JSONL records split only on the LF record delimiter.

    ``str.splitlines()`` treats Unicode separators such as U+2028 and U+2029 as
    line breaks, but JSONL records are delimited by ``\n``. Keep those
    characters inside JSON strings while still tolerating CRLF uploads.
    """
    for raw_line in raw_text.split("\n"):
        if raw_line.endswith("\r"):
            raw_line = raw_line[:-1]
        yield raw_line


def first_group_ref_from_audit_log_bytes(dump_bytes: bytes) -> str | None:
    try:
        raw_text = dump_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None

    for raw_line in iter_jsonl_record_lines(raw_text):
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            loaded = loads_audit_json(raw_line)
        except (ValueError, RecursionError):
            continue
        if not isinstance(loaded, dict):
            continue
        group_ref = loaded.get("group_ref")
        if is_hex(group_ref, even=True):
            return group_ref
    return None


def ingest_audit_log_bytes(
    *,
    dump_bytes: bytes,
    fallback_group_slug: str | None = None,
    fallback_group_name: str = "",
    upload_token: UploadToken | None = None,
    uploaded_by=None,
    source_ip: str | None = None,
    user_agent: str = "",
    source_name: str = "",
    source_account_label: str = "",
    source_device_label: str = "",
    source_platform: str = "",
    source_app_version: str = "",
    content_type: str = "",
) -> IngestionResult:
    try:
        raw_text = dump_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raw_text = dump_bytes.decode("utf-8", errors="replace")
        return save_invalid_upload(
            fallback_group_slug=fallback_group_slug,
            fallback_group_name=fallback_group_name,
            upload_token=upload_token,
            uploaded_by=uploaded_by,
            source_ip=source_ip,
            user_agent=user_agent,
            source_name=source_name,
            source_account_label=source_account_label,
            source_device_label=source_device_label,
            source_platform=source_platform,
            source_app_version=source_app_version,
            content_type=content_type,
            dump_bytes=dump_bytes,
            raw_text=raw_text,
            error=f"Audit log must be UTF-8 JSONL: {exc}.",
        )

    file_sha256 = hashlib.sha256(dump_bytes).hexdigest()
    existing = AuditFile.objects.filter(file_sha256=file_sha256).first()
    if existing is not None:
        return IngestionResult(audit_file=existing, created=False)

    parsed_lines = parse_jsonl(raw_text)
    metadata = file_metadata(parsed_lines)
    validation_errors = [
        f"line {line.line_number}: {'; '.join(line.errors)}" for line in parsed_lines if line.errors
    ]
    if not parsed_lines:
        validation_errors = ["audit log has no non-empty JSONL lines"]
    else:
        validation_errors.extend(file_validation_errors(parsed_lines))

    validation_status = AuditFile.STATUS_INVALID if validation_errors else AuditFile.STATUS_VALID
    validation_error = "\n".join(validation_errors)

    try:
        with transaction.atomic():
            audit_file = AuditFile.objects.create(
                upload_token=upload_token,
                uploaded_by=uploaded_by,
                source_name=source_name[:255],
                source_account_label=source_account_label[:255],
                source_device_label=source_device_label[:255],
                source_platform=source_platform[:120],
                source_app_version=source_app_version[:120],
                content_type=content_type[:120],
                file_sha256=file_sha256,
                byte_size=len(dump_bytes),
                raw_text=raw_text,
                validation_status=validation_status,
                validation_error=validation_error,
                source_ip=source_ip,
                user_agent=user_agent[:5000],
                **metadata,
            )
            duplicate_count, group_ids = create_events(
                audit_file,
                parsed_lines,
                fallback_group_slug=fallback_group_slug,
                fallback_group_name=fallback_group_name,
            )
            if duplicate_count:
                audit_file.duplicate_event_count = duplicate_count
                audit_file.save(update_fields=["duplicate_event_count"])
            for group_id in group_ids:
                AuditGroup.objects.filter(id=group_id).update(updated_at=timezone.now())
            return IngestionResult(audit_file=audit_file, created=True)
    except IntegrityError:
        audit_file = AuditFile.objects.get(file_sha256=file_sha256)
        return IngestionResult(audit_file=audit_file, created=False)


def save_invalid_upload(
    *,
    fallback_group_slug: str | None,
    fallback_group_name: str,
    upload_token: UploadToken | None,
    uploaded_by,
    source_ip: str | None,
    user_agent: str,
    source_name: str,
    source_account_label: str,
    source_device_label: str,
    source_platform: str,
    source_app_version: str,
    content_type: str,
    dump_bytes: bytes,
    raw_text: str,
    error: str,
) -> IngestionResult:
    file_sha256 = hashlib.sha256(dump_bytes).hexdigest()
    existing = AuditFile.objects.filter(file_sha256=file_sha256).first()
    if existing is not None:
        return IngestionResult(audit_file=existing, created=False)
    fallback_group = group_for_slug(fallback_group_slug, fallback_group_name)
    with transaction.atomic():
        audit_file = AuditFile.objects.create(
            upload_token=upload_token,
            uploaded_by=uploaded_by,
            source_name=source_name[:255],
            source_account_label=source_account_label[:255],
            source_device_label=source_device_label[:255],
            source_platform=source_platform[:120],
            source_app_version=source_app_version[:120],
            content_type=content_type[:120],
            file_sha256=file_sha256,
            byte_size=len(dump_bytes),
            raw_text=raw_text,
            validation_status=AuditFile.STATUS_INVALID,
            validation_error=error,
            total_line_count=1,
            invalid_event_count=1,
            source_ip=source_ip,
            user_agent=user_agent[:5000],
        )
        AuditEvent.objects.create(
            group=fallback_group,
            audit_file=audit_file,
            line_number=1,
            line_hash=hashlib.sha256(raw_text.encode("utf-8", errors="replace")).hexdigest(),
            raw_line=raw_text,
            parse_status=AuditEvent.STATUS_INVALID,
            validation_error=error,
        )
        if fallback_group is not None:
            AuditGroup.objects.filter(id=fallback_group.id).update(updated_at=timezone.now())
    return IngestionResult(audit_file=audit_file, created=True)


def parse_jsonl(raw_text: str) -> list[ParsedLine]:
    parsed_lines = []
    for line_number, raw_line in enumerate(iter_jsonl_record_lines(raw_text), start=1):
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        data = None
        errors = []
        try:
            loaded = loads_audit_json(raw_line)
            if not isinstance(loaded, dict):
                errors.append("line must be a JSON object")
            else:
                data = loaded
        except json.JSONDecodeError as exc:
            errors.append(f"invalid JSON: {exc.msg}")
        except (ValueError, RecursionError) as exc:
            # ValueError covers the depth-limit guard in loads_audit_json();
            # RecursionError is a belt-and-suspenders catch in case the
            # interpreter's recursion limit is hit before the depth guard.
            # Neither is a JSONDecodeError, so without this they would escape
            # parse_jsonl() as an uncaught 500 and lose the raw upload.
            errors.append(f"invalid JSON: {exc}")

        normalized: dict[str, Any] = {}
        if data is not None:
            normalized, validation_errors = normalize_event(data)
            errors.extend(validation_errors)

        parsed_lines.append(
            ParsedLine(
                line_number=line_number,
                raw_line=raw_line,
                line_hash=hashlib.sha256(raw_line.encode("utf-8")).hexdigest(),
                data=data,
                normalized=normalized,
                errors=errors,
            )
        )
    return parsed_lines


def normalize_event(data: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    normalized: dict[str, Any] = {
        "schema_version": bounded_str_or_empty(
            data.get("schema_version"),
            "schema_version",
            errors,
        ),
        "seq": value_if_int(data.get("seq")),
        "wall_time_ms": value_if_int(data.get("wall_time_ms")),
        "account_ref": (
            value_if_str(data.get("account_ref")) if data.get("account_ref") is not None else ""
        ),
        "engine_id": value_if_str(data.get("engine_id")),
        "group_ref": (
            value_if_str(data.get("group_ref")) if data.get("group_ref") is not None else ""
        ),
    }

    if normalized["schema_version"] != AUDIT_SCHEMA_VERSION:
        errors.append(
            "unsupported schema_version "
            f"{data.get('schema_version')!r}; expected {AUDIT_SCHEMA_VERSION}"
        )
    if normalized["seq"] is None:
        errors.append("seq must be a non-negative integer")
    elif int_exceeds_model_limit("seq", normalized["seq"], errors):
        normalized["seq"] = None
    if normalized["wall_time_ms"] is None:
        errors.append("wall_time_ms must be a non-negative integer")
    elif int_exceeds_model_limit("wall_time_ms", normalized["wall_time_ms"], errors):
        normalized["wall_time_ms"] = None
    elif normalized["wall_time_ms"] > MAX_WALL_TIME_MS:
        errors.append(
            f"wall_time_ms must be a non-negative integer within range (at most {MAX_WALL_TIME_MS})"
        )
        normalized["wall_time_ms"] = None
    if normalized["account_ref"] and not is_hex(normalized["account_ref"], exact_len=32):
        errors.append("account_ref must be 32 hex characters when present")
    if not is_hex(normalized["engine_id"], exact_len=32):
        errors.append("engine_id must be 32 hex characters")
    if normalized["group_ref"] and not valid_group_ref(normalized["group_ref"]):
        errors.append(
            "group_ref must be even-length hex and at most "
            f"{group_ref_max_length()} characters when present"
        )

    normalize_context(data.get("context"), normalized, errors)

    kind = data.get("kind")
    if not isinstance(kind, dict):
        errors.append("kind must be an object")
        return normalized, errors

    event_type = value_if_str(kind.get("type"))
    normalized["raw_kind"] = kind
    if not event_type:
        errors.append("kind.type must be a non-empty string")
        return normalized, errors
    if string_exceeds_model_limit("event_type", event_type, errors):
        return normalized, errors
    normalized["event_type"] = event_type

    variant_errors = normalize_kind(event_type, kind, normalized)
    errors.extend(variant_errors)
    if not normalized.get("human_action_action"):
        errors.append(
            "new audit rows must include kind.type 'human_action' or context.human_action.action"
        )
    return normalized, errors


def normalize_kind(event_type: str, kind: dict[str, Any], normalized: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    match event_type:
        case "ingest_entry":
            copy_msg_id(kind, normalized, errors)
            copy_str(kind, normalized, errors, "envelope_kind")
            copy_int(kind, normalized, errors, "payload_len")
            copy_digest(kind, normalized, errors, "payload_digest")
        case "ingest_outcome":
            copy_msg_id(kind, normalized, errors)
            copy_str(kind, normalized, errors, "outcome_kind")
            copy_optional_str(kind, normalized, errors, "stale_reason")
            copy_optional_int(kind, normalized, errors, "epoch")
        case "send_entry":
            copy_str(kind, normalized, errors, "intent_kind")
        case "send_outcome":
            copy_str(kind, normalized, errors, "intent_kind")
            copy_str(kind, normalized, errors, "result_kind")
            copy_optional_msg_id(kind, normalized, errors, "outbound_msg_id")
            welcome_ids = kind.get("outbound_welcome_msg_ids", [])
            if not isinstance(welcome_ids, list) or any(
                not is_hex(item, even=True) for item in welcome_ids
            ):
                errors.append("outbound_welcome_msg_ids must be a list of hex strings")
            else:
                normalized["outbound_welcome_msg_ids"] = welcome_ids
        case "human_action":
            copy_human_action_fields(kind, normalized, errors)
        case "publish_attempt":
            copy_publish_fields(kind, normalized, errors)
            copy_optional_str_list(kind, normalized, errors, "relay_urls")
        case "publish_outcome":
            copy_publish_fields(kind, normalized, errors)
            copy_optional_str_list(kind, normalized, errors, "accepted_relay_urls")
            failed_relays = kind.get("failed_relays")
            if failed_relays is not None:
                if not isinstance(failed_relays, list):
                    errors.append("failed_relays must be a list when present")
                else:
                    normalized["failed_relays"] = failed_relays
            met_required_acks = kind.get("met_required_acks")
            if met_required_acks is not None:
                if not isinstance(met_required_acks, bool):
                    errors.append("met_required_acks must be a boolean when present")
                else:
                    normalized["met_required_acks"] = met_required_acks
        case "publish_failure":
            copy_publish_fields(kind, normalized, errors)
            copy_optional_str(kind, normalized, errors, "reason")
            copy_optional_str(kind, normalized, errors, "detail")
            copy_optional_str_list(kind, normalized, errors, "relay_urls")
        case "epoch_confirmed":
            copy_int(kind, normalized, errors, "from_epoch")
            copy_int(kind, normalized, errors, "to_epoch")
            copy_str(kind, normalized, errors, "pending_kind")
        case "epoch_rolled_back":
            copy_int(kind, normalized, errors, "pending_epoch")
            copy_int(kind, normalized, errors, "restored_epoch")
            copy_str(kind, normalized, errors, "pending_kind")
        case "snapshot_created":
            copy_str(kind, normalized, errors, "snapshot_name")
            copy_int(kind, normalized, errors, "source_epoch")
            copy_str(kind, normalized, errors, "reason")
        case "fork_resolution":
            copy_int(kind, normalized, errors, "source_epoch")
            copy_digest(kind, normalized, errors, "candidate_digest")
            copy_optional_digest(kind, normalized, errors, "incumbent_digest")
            copy_str(kind, normalized, errors, "winner")
            if normalized.get("winner") not in {"candidate", "incumbent", "missing_snapshot"}:
                errors.append("winner must be candidate, incumbent, or missing_snapshot")
            copy_optional_msg_id(kind, normalized, errors, "invalidated_msg_id")
        case "convergence_decision":
            copy_int(kind, normalized, errors, "current_tip_epoch")
            copy_int(kind, normalized, errors, "candidate_count")
            copy_int(kind, normalized, errors, "eligible_count")
            copy_int(kind, normalized, errors, "max_rewind_commits")
            copy_optional_str(kind, normalized, errors, "selected_branch_id")
            copy_optional_int(kind, normalized, errors, "selected_fork_epoch")
            copy_optional_int(kind, normalized, errors, "selected_tip_epoch")
        case "peeler_outcome":
            copy_msg_id(kind, normalized, errors)
            copy_str(kind, normalized, errors, "outcome")
            if normalized.get("outcome") not in {
                "success",
                "decrypt_failed",
                "stale_epoch",
                "malformed",
                "other",
            }:
                errors.append("outcome must be a known peeler outcome")
            fallback = kind.get("fallback_snapshot_used")
            if not isinstance(fallback, bool):
                errors.append("fallback_snapshot_used must be a boolean")
            else:
                normalized["fallback_snapshot_used"] = fallback
            copy_optional_str(kind, normalized, errors, "detail")
        case "auto_commit_decision":
            copy_str(kind, normalized, errors, "proposal_kind")
            copy_str(kind, normalized, errors, "decision")
            copy_optional_str(kind, normalized, errors, "reason")
        case "message_state_changed":
            copy_msg_id(kind, normalized, errors)
            copy_str(kind, normalized, errors, "new_state")
            copy_str(kind, normalized, errors, "reason")
        case "rejection":
            copy_msg_id(kind, normalized, errors)
            copy_str(kind, normalized, errors, "reason")
        case _:
            pass
    return errors


def normalize_context(
    context: Any,
    normalized: dict[str, Any],
    errors: list[str],
) -> None:
    if context is None:
        return
    if not isinstance(context, dict):
        errors.append("context must be an object when present")
        return

    normalized["raw_context"] = context
    operation_id = context.get("operation_id")
    if operation_id is not None:
        copy_context_str(context, normalized, errors, "operation_id", "context_operation_id")
    human_action = context.get("human_action")
    if human_action is not None:
        if not isinstance(human_action, dict):
            errors.append("context.human_action must be an object when present")
        else:
            normalized["context_human_action"] = human_action
            copy_human_action_fields(human_action, normalized, errors)
    for field in ("transport", "engine", "group"):
        if field in context and context[field] is not None:
            normalized[f"context_{field}"] = context[field]


def create_events(
    audit_file: AuditFile,
    parsed_lines: list[ParsedLine],
    *,
    fallback_group_slug: str | None,
    fallback_group_name: str,
) -> tuple[int, set[int]]:
    duplicate_count = 0
    group_ids: set[int] = set()
    groups_by_key = groups_for_parsed_lines(
        parsed_lines,
        fallback_group_slug=fallback_group_slug,
        fallback_group_name=fallback_group_name,
    )
    existing_duplicates = existing_duplicate_events(
        parsed_lines,
        ignore_invalid_files=audit_file.validation_status == AuditFile.STATUS_VALID,
    )
    events = []
    for parsed in parsed_lines:
        group_key = group_key_for_parsed_line(
            parsed,
            fallback_group_slug=fallback_group_slug,
        )
        group = groups_by_key.get(group_key)
        if group is not None:
            group_ids.add(group.id)
        if duplicate_event_exists(parsed, existing_duplicates=existing_duplicates):
            duplicate_count += 1
            continue
        values = event_values(audit_file, parsed, group)
        events.append(AuditEvent(**values))
        remember_duplicate_event(parsed, existing_duplicates)
    AuditEvent.objects.bulk_create(events)
    return duplicate_count, group_ids


def groups_for_parsed_lines(
    parsed_lines: list[ParsedLine],
    *,
    fallback_group_slug: str | None,
    fallback_group_name: str,
) -> dict[tuple[str, str] | None, AuditGroup]:
    groups = {}
    for parsed in parsed_lines:
        group_key = group_key_for_parsed_line(
            parsed,
            fallback_group_slug=fallback_group_slug,
        )
        if group_key is None or group_key in groups:
            continue
        groups[group_key] = group_for_key(group_key, fallback_group_name=fallback_group_name)
    return groups


def group_key_for_parsed_line(
    parsed: ParsedLine,
    *,
    fallback_group_slug: str | None,
) -> tuple[str, str] | None:
    group_ref = parsed.normalized.get("group_ref") or ""
    if valid_group_ref(group_ref):
        return ("ref", group_ref)
    if fallback_group_slug:
        return ("slug", fallback_group_slug)
    return None


def group_for_key(group_key: tuple[str, str], *, fallback_group_name: str) -> AuditGroup:
    key_type, value = group_key
    if key_type == "ref":
        return group_for_ref(value)
    return group_for_slug(value, fallback_group_name)


def existing_duplicate_events(
    parsed_lines: list[ParsedLine],
    *,
    ignore_invalid_files: bool,
) -> dict[str, set[str]]:
    line_hashes = {parsed.line_hash for parsed in parsed_lines}
    if not line_hashes:
        return {}
    queryset = AuditEvent.objects.filter(line_hash__in=line_hashes)
    if ignore_invalid_files:
        queryset = queryset.filter(audit_file__validation_status=AuditFile.STATUS_VALID)
    duplicates: dict[str, set[str]] = {}
    for line_hash, engine_id in queryset.values_list("line_hash", "engine_id"):
        duplicates.setdefault(line_hash, set()).add(engine_id)
    return duplicates


def duplicate_event_exists(
    parsed: ParsedLine,
    *,
    existing_duplicates: dict[str, set[str]],
) -> bool:
    existing_engines = existing_duplicates.get(parsed.line_hash)
    if not existing_engines:
        return False
    engine_id = parsed.normalized.get("engine_id")
    if engine_id:
        return engine_id in existing_engines
    return True


def remember_duplicate_event(
    parsed: ParsedLine,
    existing_duplicates: dict[str, set[str]],
) -> None:
    existing_duplicates.setdefault(parsed.line_hash, set()).add(
        parsed.normalized.get("engine_id") or ""
    )


def group_for_ref(group_ref: str) -> AuditGroup:
    existing = AuditGroup.objects.filter(group_ref=group_ref).first()
    if existing is not None:
        return existing
    slug = group_slug_for_ref(group_ref)
    group, created = AuditGroup.objects.get_or_create(
        slug=slug,
        defaults={
            "name": f"Group {group_ref[:12]}",
            "group_ref": group_ref,
        },
    )
    if group_ref and not group.group_ref:
        group.group_ref = group_ref
        group.save(update_fields=["group_ref"])
    elif created:
        group.save(update_fields=["updated_at"])
    return group


def group_slug_for_ref(group_ref: str) -> str:
    slug = slugify(group_ref) or "incoming"
    max_slug_length = AuditGroup._meta.get_field("slug").max_length
    if len(slug) <= max_slug_length:
        return slug
    digest = hashlib.sha256(group_ref.encode("utf-8")).hexdigest()[:32]
    prefix_length = max_slug_length - len(digest) - 1
    return f"{slug[:prefix_length]}-{digest}"


def group_for_slug(slug: str | None, name: str = "") -> AuditGroup | None:
    if not slug:
        return None
    group, _created = AuditGroup.objects.get_or_create(
        slug=slug,
        defaults={"name": name or group_name_from_slug(slug), "group_ref": ""},
    )
    return group


def group_name_from_slug(slug: str) -> str:
    return slug.replace("-", " ").strip().title() or "Incoming"


def event_values(
    audit_file: AuditFile,
    parsed: ParsedLine,
    group: AuditGroup | None,
) -> dict[str, Any]:
    values = {
        "group": group,
        "audit_file": audit_file,
        "line_number": parsed.line_number,
        "line_hash": parsed.line_hash,
        "raw_line": parsed.raw_line,
        "raw_event": parsed.data,
        "parse_status": AuditEvent.STATUS_INVALID if parsed.errors else AuditEvent.STATUS_VALID,
        "validation_error": "; ".join(parsed.errors),
    }
    if parsed.data is not None:
        values.update(
            {
                "raw_kind": parsed.normalized.get("raw_kind") or {},
                "raw_context": parsed.normalized.get("raw_context") or {},
                "schema_version": parsed.normalized.get("schema_version") or "",
                "seq": parsed.normalized.get("seq"),
                "wall_time_ms": parsed.normalized.get("wall_time_ms"),
                "account_ref": parsed.normalized.get("account_ref") or "",
                "engine_id": parsed.normalized.get("engine_id") or "",
                "group_ref": parsed.normalized.get("group_ref") or "",
                "event_type": parsed.normalized.get("event_type") or "",
            }
        )
        for field in normalized_fields():
            if field in parsed.normalized:
                values[field] = parsed.normalized[field]
    return values


def file_metadata(parsed_lines: list[ParsedLine]) -> dict[str, Any]:
    valid_lines = [line for line in parsed_lines if not line.errors]
    all_line_numbers = [line.line_number for line in parsed_lines]
    seqs = [
        line.normalized.get("seq") for line in valid_lines if line.normalized.get("seq") is not None
    ]
    wall_times = [
        line.normalized.get("wall_time_ms")
        for line in valid_lines
        if line.normalized.get("wall_time_ms") is not None
    ]
    engine_ids = sorted(
        {
            line.normalized.get("engine_id")
            for line in valid_lines
            if line.normalized.get("engine_id")
        }
    )
    account_refs = sorted(
        {
            line.normalized.get("account_ref")
            for line in valid_lines
            if line.normalized.get("account_ref")
        }
    )
    group_refs = sorted(
        {
            line.normalized.get("group_ref")
            for line in valid_lines
            if line.normalized.get("group_ref")
        }
    )
    schema_versions = sorted(
        {
            line.normalized.get("schema_version")
            for line in parsed_lines
            if line.normalized.get("schema_version")
        }
    )
    return {
        "total_line_count": len(parsed_lines),
        "valid_event_count": len(valid_lines),
        "invalid_event_count": len(parsed_lines) - len(valid_lines),
        "first_line_number": min(all_line_numbers) if all_line_numbers else None,
        "last_line_number": max(all_line_numbers) if all_line_numbers else None,
        "first_seq": min(seqs) if seqs else None,
        "last_seq": max(seqs) if seqs else None,
        "first_wall_time_ms": min(wall_times) if wall_times else None,
        "last_wall_time_ms": max(wall_times) if wall_times else None,
        "account_refs": account_refs,
        "engine_ids": engine_ids,
        "group_refs": group_refs,
        "schema_versions": schema_versions,
    }


def file_validation_errors(parsed_lines: list[ParsedLine]) -> list[str]:
    errors = []
    engine_ids = sorted(
        {
            line.normalized.get("engine_id")
            for line in parsed_lines
            if is_hex(line.normalized.get("engine_id"), exact_len=32)
        }
    )
    if len(engine_ids) > 1:
        errors.append(
            "audit log contains multiple engine_ids; expected one engine per file: "
            + ", ".join(engine_ids)
        )
    account_refs = sorted(
        {
            line.normalized.get("account_ref")
            for line in parsed_lines
            if is_hex(line.normalized.get("account_ref"), exact_len=32)
        }
    )
    if len(account_refs) > 1:
        errors.append(
            "audit log contains multiple account_refs; expected one account per file: "
            + ", ".join(account_refs)
        )
    return errors


def normalized_fields() -> tuple[str, ...]:
    return (
        "msg_id",
        "outbound_msg_id",
        "outbound_welcome_msg_ids",
        "target_kind",
        "relay_urls",
        "accepted_relay_urls",
        "failed_relays",
        "required_acks",
        "met_required_acks",
        "context_operation_id",
        "context_human_action",
        "context_transport",
        "context_engine",
        "context_group",
        "human_action_action",
        "human_action_origin",
        "human_action_phase",
        "human_action_fields",
        "human_action_component_ids",
        "human_action_target_count",
        "human_action_message_ids",
        "epoch",
        "source_epoch",
        "from_epoch",
        "to_epoch",
        "pending_epoch",
        "restored_epoch",
        "current_tip_epoch",
        "selected_fork_epoch",
        "selected_tip_epoch",
        "payload_len",
        "payload_digest",
        "candidate_digest",
        "incumbent_digest",
        "envelope_kind",
        "outcome",
        "outcome_kind",
        "stale_reason",
        "decision",
        "reason",
        "winner",
        "new_state",
        "pending_kind",
        "intent_kind",
        "result_kind",
        "proposal_kind",
        "snapshot_name",
        "selected_branch_id",
        "detail",
        "fallback_snapshot_used",
        "invalidated_msg_id",
        "max_rewind_commits",
        "candidate_count",
        "eligible_count",
    )


def copy_human_action_fields(
    source: dict[str, Any],
    normalized: dict[str, Any],
    errors: list[str],
) -> None:
    copy_human_action_str(source, normalized, errors, "action", "human_action_action")
    copy_human_action_str(source, normalized, errors, "origin", "human_action_origin")
    copy_human_action_str(source, normalized, errors, "phase", "human_action_phase")
    copy_optional_str_list(source, normalized, errors, "fields", "human_action_fields")
    copy_optional_int_list(
        source,
        normalized,
        errors,
        "component_ids",
        "human_action_component_ids",
    )
    copy_optional_int(source, normalized, errors, "target_count", "human_action_target_count")
    copy_optional_msg_id_list(
        source,
        normalized,
        errors,
        "message_ids",
        "human_action_message_ids",
    )
    copy_optional_int(source, normalized, errors, "from_epoch")
    copy_optional_int(source, normalized, errors, "to_epoch")


def copy_publish_fields(
    kind: dict[str, Any],
    normalized: dict[str, Any],
    errors: list[str],
) -> None:
    copy_optional_msg_id(kind, normalized, errors, "msg_id")
    copy_optional_str(kind, normalized, errors, "target_kind")
    copy_optional_int(kind, normalized, errors, "required_acks")
    relay_url = kind.get("relay_url")
    if relay_url is not None:
        if not isinstance(relay_url, str):
            errors.append("relay_url must be a string when present")
        elif "relay_urls" not in kind:
            normalized["relay_urls"] = [relay_url]


def copy_context_str(
    source: dict[str, Any],
    normalized: dict[str, Any],
    errors: list[str],
    source_field: str,
    dest_field: str,
) -> None:
    value = source.get(source_field)
    if not isinstance(value, str):
        errors.append(f"context.{source_field} must be a string when present")
        return
    if string_exceeds_model_limit(dest_field, value, errors):
        return
    normalized[dest_field] = value


def copy_human_action_str(
    source: dict[str, Any],
    normalized: dict[str, Any],
    errors: list[str],
    source_field: str,
    dest_field: str,
) -> None:
    value = source.get(source_field)
    if value is None:
        return
    if not isinstance(value, str):
        errors.append(f"human_action.{source_field} must be a string when present")
        return
    if string_exceeds_model_limit(dest_field, value, errors):
        return
    normalized[dest_field] = value


def copy_optional_str_list(
    source: dict[str, Any],
    normalized: dict[str, Any],
    errors: list[str],
    source_field: str,
    dest_field: str | None = None,
) -> None:
    value = source.get(source_field)
    if value is None:
        return
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        errors.append(f"{source_field} must be a list of strings when present")
        return
    normalized[dest_field or source_field] = value


def copy_optional_int_list(
    source: dict[str, Any],
    normalized: dict[str, Any],
    errors: list[str],
    source_field: str,
    dest_field: str,
) -> None:
    value = source.get(source_field)
    if value is None:
        return
    if not isinstance(value, list) or any(value_if_int(item) is None for item in value):
        errors.append(f"human_action.{source_field} must be a list of non-negative integers")
        return
    normalized[dest_field] = value


def copy_optional_msg_id_list(
    source: dict[str, Any],
    normalized: dict[str, Any],
    errors: list[str],
    source_field: str,
    dest_field: str,
) -> None:
    value = source.get(source_field)
    if value is None:
        return
    if not isinstance(value, list) or any(not is_hex(item, even=True) for item in value):
        errors.append(f"human_action.{source_field} must be a list of hex strings")
        return
    normalized[dest_field] = value


def copy_msg_id(kind: dict[str, Any], normalized: dict[str, Any], errors: list[str]) -> None:
    copy_msg_field(kind, normalized, errors, "msg_id", required=True)


def copy_optional_msg_id(
    kind: dict[str, Any],
    normalized: dict[str, Any],
    errors: list[str],
    field: str,
) -> None:
    copy_msg_field(kind, normalized, errors, field, required=False)


def copy_msg_field(
    kind: dict[str, Any],
    normalized: dict[str, Any],
    errors: list[str],
    field: str,
    *,
    required: bool,
) -> None:
    value = kind.get(field)
    if value is None:
        if required:
            errors.append(f"{field} is required")
        return
    if not is_hex(value, even=True):
        errors.append(f"{field} must be even-length hex")
        return
    normalized[field] = value


def copy_digest(
    kind: dict[str, Any],
    normalized: dict[str, Any],
    errors: list[str],
    field: str,
) -> None:
    value = kind.get(field)
    if not is_hex(value, exact_len=64):
        errors.append(f"{field} must be 64 hex characters")
        return
    normalized[field] = value


def copy_optional_digest(
    kind: dict[str, Any],
    normalized: dict[str, Any],
    errors: list[str],
    field: str,
) -> None:
    value = kind.get(field)
    if value is None:
        return
    if not is_hex(value, exact_len=64):
        errors.append(f"{field} must be 64 hex characters")
        return
    normalized[field] = value


def copy_str(
    kind: dict[str, Any],
    normalized: dict[str, Any],
    errors: list[str],
    field: str,
) -> None:
    raw_value = kind.get(field)
    value = value_if_str(raw_value)
    if not value:
        errors.append(f"{field} must be a non-empty string")
        return
    if string_exceeds_model_limit(field, value, errors):
        return
    normalized[field] = value


def copy_optional_str(
    kind: dict[str, Any],
    normalized: dict[str, Any],
    errors: list[str],
    field: str,
) -> None:
    value = kind.get(field)
    if value is None:
        return
    if not isinstance(value, str):
        errors.append(f"{field} must be a string when present")
        return
    if string_exceeds_model_limit(field, value, errors):
        return
    normalized[field] = value


def copy_int(
    kind: dict[str, Any],
    normalized: dict[str, Any],
    errors: list[str],
    field: str,
) -> None:
    value = value_if_int(kind.get(field))
    if value is None:
        errors.append(f"{field} must be a non-negative integer")
        return
    if int_exceeds_model_limit(field, value, errors):
        return
    normalized[field] = value


def copy_optional_int(
    kind: dict[str, Any],
    normalized: dict[str, Any],
    errors: list[str],
    field: str,
    dest_field: str | None = None,
) -> None:
    if kind.get(field) is None:
        return
    value = value_if_int(kind.get(field))
    if value is None:
        errors.append(f"{field} must be a non-negative integer when present")
        return
    if int_exceeds_model_limit(field, value, errors, model_field=dest_field or field):
        return
    normalized[dest_field or field] = value


def value_if_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def bounded_str_or_empty(value: Any, field: str, errors: list[str]) -> str:
    if not isinstance(value, str):
        return ""
    if string_exceeds_model_limit(field, value, errors):
        return ""
    return value


def string_exceeds_model_limit(field: str, value: str, errors: list[str]) -> bool:
    max_length = AuditEvent._meta.get_field(field).max_length
    if max_length is not None and len(value) > max_length:
        errors.append(f"{field} must be at most {max_length} characters")
        return True
    return False


def model_int_field_max(field: str) -> int | None:
    """Logical max for an ``AuditEvent`` integer column.

    Keyed off the field's internal type via the *base* backend ranges rather
    than ``connection.ops.integer_field_range``: the latter is backend
    dependent (SQLite reports the bigint range for every integer field), but
    the column width is fixed by the schema, so the validation must enforce the
    same range Postgres enforces regardless of which database the suite runs
    against. This keeps the guard correct on the SQLite dev DB and in parity
    with production Postgres.
    """
    internal_type = AuditEvent._meta.get_field(field).get_internal_type()
    field_range = BaseDatabaseOperations.integer_field_ranges.get(internal_type)
    if field_range is None:
        return None
    return field_range[1]


def int_exceeds_model_limit(
    field: str,
    value: int,
    errors: list[str],
    *,
    model_field: str | None = None,
) -> bool:
    max_value = model_int_field_max(model_field or field)
    if max_value is not None and value > max_value:
        errors.append(f"{field} must be a non-negative integer within range")
        return True
    return False


def value_if_int(value: Any) -> int | None:
    return value if type(value) is int and value >= 0 else None


def is_hex(value: Any, *, exact_len: int | None = None, even: bool = False) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if exact_len is not None and len(value) != exact_len:
        return False
    if even and len(value) % 2:
        return False
    return HEX_RE.fullmatch(value) is not None


def valid_group_ref(value: Any) -> bool:
    return is_hex(value, even=True) and len(value) <= group_ref_max_length()


def group_ref_max_length() -> int:
    return AuditGroup._meta.get_field("group_ref").max_length
