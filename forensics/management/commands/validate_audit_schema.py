import json
from collections.abc import Iterable
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError, CommandParser
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

DEFAULT_SCHEMA_PATH = settings.BASE_DIR / "docs" / "schemas" / "audit-log-event.v2.schema.json"


class Command(BaseCommand):
    help = "Validate JSONL audit events against a committed JSON Schema."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("paths", nargs="+", help="JSONL audit log path(s) to validate.")
        parser.add_argument(
            "--schema",
            default=str(DEFAULT_SCHEMA_PATH),
            help="JSON Schema path. Defaults to the committed V2 audit event schema.",
        )

    def handle(self, *args, **options):
        schema_path = Path(options["schema"])
        validator = schema_validator(schema_path)
        event_count = 0
        error_count = 0
        for raw_path in options["paths"]:
            path = Path(raw_path)
            if not path.exists():
                raise CommandError(f"Audit log path does not exist: {path}")
            for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if not line.strip():
                    continue
                event_count += 1
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    error_count += 1
                    self.stderr.write(f"{path}:{line_number}: invalid JSON: {exc.msg}")
                    continue
                errors = sorted(validator.iter_errors(event), key=lambda error: error.path)
                for error in errors:
                    for pointer, message in safe_validation_errors(error):
                        error_count += 1
                        self.stderr.write(f"{path}:{line_number}:{pointer}: {message}")

        if error_count:
            raise CommandError(
                "Schema validation failed with "
                f"{error_count} error(s) across {event_count} event(s)."
            )
        self.stdout.write(
            self.style.SUCCESS(
                "Schema validation passed for "
                f"{event_count} event(s) across {len(options['paths'])} file(s)."
            )
        )


def schema_validator(schema_path: Path) -> Draft202012Validator:
    if not schema_path.exists():
        raise CommandError(f"Schema path does not exist: {schema_path}")
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CommandError(f"Schema is not valid JSON: {schema_path}: {exc.msg}") from exc
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise CommandError(f"Schema is invalid: {exc.message}") from exc
    return Draft202012Validator(schema)


def safe_validation_errors(error: ValidationError) -> list[tuple[str, str]]:
    messages: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for child_error in _safe_validation_errors(error):
        pointer = ".".join(str(part) for part in child_error.absolute_path) or "$"
        message = _safe_validation_message(child_error)
        key = (pointer, message)
        if key not in seen:
            messages.append(key)
            seen.add(key)
    return messages


def _safe_validation_errors(error: ValidationError) -> Iterable[ValidationError]:
    if error.validator in {"anyOf", "oneOf"}:
        matching_context = _matching_union_context(error)
        if matching_context:
            for child_error in matching_context:
                yield from _safe_validation_errors(child_error)
        else:
            yield error
        return
    yield error


def _matching_union_context(error: ValidationError) -> list[ValidationError]:
    if not error.context or not isinstance(error.instance, dict):
        return []
    event_type = error.instance.get("type")
    if not isinstance(event_type, str):
        return []

    branch_indexes: set[int] = set()
    const_mismatch_indexes: set[int] = set()
    for child_error in error.context:
        branch_index = _union_branch_index(child_error)
        if branch_index is None:
            continue
        branch_indexes.add(branch_index)
        if (
            child_error.validator == "const"
            and tuple(child_error.path) == ("type",)
            and child_error.validator_value != event_type
        ):
            const_mismatch_indexes.add(branch_index)

    matching_indexes = branch_indexes - const_mismatch_indexes
    if len(matching_indexes) != 1:
        return []
    matching_index = next(iter(matching_indexes))
    return [
        child_error
        for child_error in error.context
        if _union_branch_index(child_error) == matching_index
    ]


def _union_branch_index(error: ValidationError) -> int | None:
    if not error.schema_path:
        return None
    branch_index = error.schema_path[0]
    if isinstance(branch_index, int):
        return branch_index
    return None


def _safe_validation_message(error: ValidationError) -> str:
    match error.validator:
        case "required":
            missing = _missing_required_properties(error)
            if missing:
                return f"missing required property: {', '.join(missing)}"
            return "missing required property"
        case "additionalProperties":
            unexpected = _unexpected_properties(error)
            if unexpected:
                return f"unexpected property: {', '.join(unexpected)}"
            return "has unexpected properties"
        case "const":
            return "does not match the required constant"
        case "enum":
            return "is not one of the allowed values"
        case "type":
            expected = error.validator_value
            if isinstance(expected, list):
                expected_type = " or ".join(str(item) for item in expected)
            else:
                expected_type = str(expected)
            return f"must be {expected_type}"
        case "pattern":
            return "does not match the required format"
        case "minimum":
            return f"must be greater than or equal to {error.validator_value}"
        case "maximum":
            return f"must be less than or equal to {error.validator_value}"
        case "minLength":
            return f"must be at least {error.validator_value} character(s)"
        case "not":
            return "contains data disallowed for this audit data mode"
        case "anyOf" | "oneOf":
            return "does not match any allowed schema"
        case _:
            return f"failed schema rule: {error.validator}"


def _missing_required_properties(error: ValidationError) -> list[str]:
    if not isinstance(error.instance, dict):
        return []
    if not isinstance(error.validator_value, list):
        return []
    return sorted(str(name) for name in error.validator_value if name not in error.instance)


def _unexpected_properties(error: ValidationError) -> list[str]:
    if not isinstance(error.instance, dict) or not isinstance(error.schema, dict):
        return []
    properties = error.schema.get("properties", {})
    if not isinstance(properties, dict):
        return []
    return sorted(str(name) for name in error.instance if name not in properties)
