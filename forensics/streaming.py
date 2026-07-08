"""A domain-blind NDJSON streamer for bulk exports.

Emits one JSON object per line: a ``manifest`` line, then every row of each
:class:`ExportSection` tagged with its ``record_type``, then a terminal ``eof``
line carrying per-section counts. Rows are pulled through ``QuerySet.iterator()``
so peak memory is one chunk regardless of dataset size.

This module knows nothing about the forensic domain — the caller injects the
querysets and their payload factories — so it stays a pure, reusable seam that
tests can drive with fakes.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass

from django.core.serializers.json import DjangoJSONEncoder
from django.db.models import QuerySet

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ExportSection:
    """One typed stream of records: a queryset and how to serialize each row."""

    record_type: str
    rows: QuerySet
    to_payload: Callable[[object], dict]


def _line(obj: dict) -> str:
    # DjangoJSONEncoder matches the project's JsonResponse idiom and keeps the
    # serializer total over datetimes/Decimals — important because the broad
    # except below would otherwise turn a stray un-encodable value into a silent
    # truncated export. No sort_keys: keys keep insertion order, so the "t"
    # discriminator leads every line (part of the wire contract).
    return json.dumps(obj, cls=DjangoJSONEncoder, separators=(",", ":")) + "\n"


def stream_ndjson(
    manifest: dict,
    sections: Iterable[ExportSection],
    *,
    chunk_size: int = 2000,
) -> Iterator[str]:
    """Yield the export as NDJSON lines: manifest, records, then eof (or error).

    Fail-closed: once the HTTP status is committed the body cannot signal failure
    out of band, so a mid-stream error yields a terminal ``{"t":"error"}`` line
    and **no** ``eof``. Consumers treat "last line is not eof" as incomplete.
    ``chunk_size`` is forwarded to ``.iterator()`` (required for querysets that
    carry ``prefetch_related``).
    """
    try:
        yield _line({"t": "manifest", **manifest})
        counts: dict[str, int] = {}
        for section in sections:
            count = 0
            for row in section.rows.iterator(chunk_size=chunk_size):
                yield _line({"t": section.record_type, **section.to_payload(row)})
                count += 1
            counts[section.record_type] = count
        yield _line({"t": "eof", "complete": True, "counts": counts})
    except Exception:  # noqa: BLE001 — fail closed: report in-band, never half-claim success
        logger.exception("group export stream failed")
        yield _line({"t": "error", "complete": False})
