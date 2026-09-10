"""The single acceptance contract for incoming audit evidence.

Never render jsonschema errors: their messages and paths can contain input data.
"""

import json
from functools import cache

from django.conf import settings
from jsonschema import Draft202012Validator

SCHEMA_VERSION = "marmot-forensics-audit/v4"
SCHEMA_PATH = settings.BASE_DIR / "docs/schemas/audit-log-event.v4.schema.json"


@cache
def audit_validator():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


@cache
def event_validators():
    # The authoritative union has a unique kind.type const per branch. Select
    # that branch before validation instead of evaluating every unrelated kind
    # for each record in a large upload. All definitions and root constraints
    # still come verbatim from MDK's schema.
    schema = audit_validator().schema
    return {
        variant["properties"]["type"]["const"]: Draft202012Validator(
            schema | {"properties": schema["properties"] | {"kind": variant}}
        )
        for variant in schema["$defs"]["auditEventKind"]["oneOf"]
    }


def schema_error_code(event):
    if not isinstance(event, dict):
        return "invalid_json_object"
    if event.get("schema_version") != SCHEMA_VERSION:
        return "unsupported_schema"
    kind = event.get("kind")
    kind_type = kind.get("type") if isinstance(kind, dict) else None
    validator = event_validators().get(kind_type) if isinstance(kind_type, str) else None
    if validator is None or not validator.is_valid(event):
        return "invalid_v4_schema"
    return None
