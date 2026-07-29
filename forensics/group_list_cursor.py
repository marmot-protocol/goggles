"""Opaque keyset cursor helpers for the group index API."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from django.core import signing
from django.core.signing import BadSignature
from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime

CURSOR_SALT = "goggles-groups-v1-cursor"


class InvalidGroupListCursor(ValueError):
    pass


@dataclass(frozen=True)
class GroupListCursor:
    watermark: datetime
    updated_at: datetime
    slug: str
    updated_since: datetime | None

    def keyset_filter(self) -> Q:
        return Q(updated_at__lt=self.updated_at) | Q(
            updated_at=self.updated_at,
            slug__gt=self.slug,
        )


def encode_group_list_cursor(
    *,
    watermark: datetime,
    updated_at: datetime,
    slug: str,
    updated_since: datetime | None,
) -> str:
    payload = {
        "w": watermark.isoformat(),
        "u": updated_at.isoformat(),
        "s": slug,
        "a": updated_since.isoformat() if updated_since is not None else None,
    }
    return signing.dumps(payload, salt=CURSOR_SALT, compress=True)


def decode_group_list_cursor(raw_cursor: str) -> GroupListCursor:
    if not raw_cursor:
        raise InvalidGroupListCursor("cursor is required")
    try:
        payload = signing.loads(raw_cursor, salt=CURSOR_SALT)
        if not isinstance(payload, dict):
            raise InvalidGroupListCursor("cursor payload is invalid")
        watermark = _parse_cursor_timestamp(payload.get("w"))
        updated_at = _parse_cursor_timestamp(payload.get("u"))
        slug = payload.get("s")
        updated_since = _parse_optional_cursor_timestamp(payload.get("a"))
        if not isinstance(slug, str) or not slug:
            raise InvalidGroupListCursor("cursor slug is invalid")
        return GroupListCursor(
            watermark=watermark,
            updated_at=updated_at,
            slug=slug,
            updated_since=updated_since,
        )
    except InvalidGroupListCursor:
        raise
    except (BadSignature, TypeError, ValueError) as exc:
        raise InvalidGroupListCursor("cursor is invalid") from exc


def _parse_cursor_timestamp(value) -> datetime:
    if not isinstance(value, str) or not value:
        raise InvalidGroupListCursor("cursor timestamp is invalid")
    parsed = parse_datetime(value)
    if parsed is None:
        raise InvalidGroupListCursor("cursor timestamp is invalid")
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone.get_current_timezone())
    return parsed


def _parse_optional_cursor_timestamp(value) -> datetime | None:
    if value is None:
        return None
    return _parse_cursor_timestamp(value)
