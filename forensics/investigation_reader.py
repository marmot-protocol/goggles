"""Bounded, on-demand v4 evidence reading. No ingestion or database writes."""

import hashlib
import http.client
import ipaddress
import json
import re
import time
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

# This independent reader policy is not Goggles' database retention setting.
READER_CUTOFF_NS = 30 * 86400 * 10**9
MAX_LINE_BYTES = 2 * 1024 * 1024
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_SOURCE_FILES = 256
MAX_EVIDENCE_BYTES = 64 * 1024 * 1024
MAX_RECORDS = MAX_SOURCE_BYTES // 256
MAX_QUERIES = 2_000
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_EXPRESSION_BYTES = 4_500
PAGE_SIZE = 1_000
BUCKETS = 64


class IncompleteEvidence(Exception):
    """Fixed reason only; never include raw forensic values in diagnostics."""


def strict_json(raw):
    from forensics.ingest import loads_audit_json

    return loads_audit_json(raw.decode("utf-8") if isinstance(raw, bytes) else raw)


def parse_body(body):
    try:
        if not isinstance(body, bytes) or len(body) > MAX_LINE_BYTES:
            raise ValueError
        from forensics.audit_schema import schema_error_code

        event = strict_json(body)
        if schema_error_code(event):
            raise ValueError
        return event
    except (UnicodeError, ValueError, RecursionError, TypeError) as error:
        raise IncompleteEvidence("invalid_v4_body") from error


def session(event):
    return (event["engine_id"], event.get("account_ref", ""), event.get("recorder_session_id", ""))


def identity(event):
    return (*session(event), event["seq"])


def bucket(group, engine="", account=""):
    key = ["group", group] if group else ["context", engine, account]
    digest = hashlib.sha256(
        json.dumps(key, separators=(",", ":"), ensure_ascii=False).encode()
    ).digest()
    return f"b{int.from_bytes(digest[:8], 'big') % BUCKETS:02x}"


class Evidence:
    def __init__(self):
        self.records = {}
        self.events = {}
        self.occurrences = Counter()
        self.body_bytes = 0

    def add(self, body, event=None):
        if event is None:
            event = parse_body(body)
        digest = hashlib.sha256(body).hexdigest()
        self.occurrences[digest] += 1
        if digest in self.records:
            return
        if len(self.records) >= MAX_RECORDS or self.body_bytes + len(body) > MAX_EVIDENCE_BYTES:
            raise IncompleteEvidence("evidence_budget_exceeded")
        self.records[digest] = body
        self.events[digest] = event
        self.body_bytes += len(body)

    def selected(self, group):
        group_rows = {d for d, e in self.events.items() if e.get("group_ref") == group}
        sessions = {session(self.events[d]) for d in group_rows}
        context_incomplete = any(not all(item) for item in sessions)
        complete_sessions = {item for item in sessions if all(item)}
        selected = {
            d: self.records[d]
            for d, e in self.events.items()
            if d in group_rows or (not e.get("group_ref") and session(e) in complete_sessions)
        }
        return selected, context_incomplete

    def summary(self, group, *, source, receipt_cutoff_omitted=False):
        selected, context_incomplete = self.selected(group)
        from forensics.analysis import message_traces_from_events
        from forensics.ingest import normalize_event
        from forensics.models import AuditEvent

        models = []
        kinds = Counter()
        for digest in sorted(selected):
            event = self.events[digest]
            if event.get("group_ref") != group:
                continue
            normalized, errors = normalize_event(event)
            if errors:
                raise IncompleteEvidence("normalization_rejected")
            models.append(AuditEvent(**normalized))
            kinds[event["kind"]["type"]] += 1
        traces = message_traces_from_events(models, {row.engine_id for row in models})
        source_times = [self.events[d]["wall_time_ms"] for d in selected]
        identities = defaultdict(set)
        for digest in selected:
            identities[identity(self.events[digest])].add(digest)
        conflicts = sum(len(digests) > 1 for digests in identities.values())
        return {
            "source": source,
            "scope": "provided_files_only" if source == "jsonl" else "queried_receipt_window",
            "selected_distinct_bodies": len(selected),
            "group_records": len(models),
            "supporting_groupless_context": len(selected) - len(models),
            "duplicate_occurrences": sum(self.occurrences[d] - 1 for d in selected),
            "conflicting_identities": conflicts,
            "kind_counts": dict(sorted(kinds.items())),
            "message_trace_count": len(traces),
            "source_event_time_bounds_ms": [min(source_times), max(source_times)]
            if source_times
            else None,
            "context_incomplete": context_incomplete,
            "receipt_cutoff_omitted": receipt_cutoff_omitted if source == "loki" else None,
            "bounded_retrieval_completed": True,
            "complete_for_requested_scope": source == "jsonl" and not context_incomplete,
            "limits": ["No receipt coverage can be inferred from JSONL files."]
            if source == "jsonl"
            else ["No atomic Loki snapshot or late-arrival watermark is established."],
        }


def read_jsonl(paths):
    if len(paths) > MAX_SOURCE_FILES:
        raise IncompleteEvidence("source_file_budget_exceeded")
    evidence = Evidence()
    total = 0
    for path in paths:
        with Path(path).open("rb") as stream:
            while True:
                line = stream.readline(MAX_LINE_BYTES + 2)
                if not line:
                    break
                total += len(line)
                if total > MAX_SOURCE_BYTES:
                    raise IncompleteEvidence("source_budget_exceeded")
                if len(line) > MAX_LINE_BYTES + 2 or not line.endswith(b"\n"):
                    raise IncompleteEvidence("incomplete_jsonl_line")
                body = line[:-1].removesuffix(b"\r")
                if body:
                    evidence.add(body)
    return evidence


class LocalLokiTransport:
    """Explicit loopback endpoint for this first local-only command."""

    def __init__(self, url):
        parsed = urllib.parse.urlsplit(url)
        if (
            parsed.scheme != "http"
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("unsupported_loki_endpoint")
        try:
            if parsed.port is None:
                raise ValueError
            if not ipaddress.ip_address(parsed.hostname).is_loopback:
                raise ValueError
        except (TypeError, ValueError) as error:
            raise ValueError("loopback_loki_required") from error
        self.base = url.rstrip("/")

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                raise IncompleteEvidence("loki_redirect_refused")

        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def __call__(self, expression, start, end, limit, timeout):
        query = urllib.parse.urlencode(
            {
                "query": expression,
                "start": start,
                "end": end,
                "direction": "forward",
                "limit": limit,
            }
        )
        request = urllib.request.Request(self.base + "/loki/api/v1/query_range?" + query)
        try:
            with self.http.open(request, timeout=timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except (OSError, http.client.HTTPException) as error:
            raise IncompleteEvidence("loki_request_failed") from error
        if len(raw) > MAX_RESPONSE_BYTES:
            raise IncompleteEvidence("response_budget_exceeded")
        try:
            return strict_json(raw)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise IncompleteEvidence("invalid_loki_response") from error


class LokiReader:
    def __init__(
        self,
        transport,
        service_name,
        environment_name,
        *,
        now_ns=None,
        page_size=PAGE_SIZE,
        max_seconds=180,
    ):
        if not 1 <= page_size <= 50_000:
            raise ValueError("unsupported_page_size")
        self.transport = transport
        if not service_name or len(service_name) > 128:
            raise ValueError("invalid_service_name")
        if not environment_name or len(environment_name) > 128:
            raise ValueError("invalid_environment_name")
        self.service_name = service_name
        self.environment_name = environment_name
        self.now_ns = time.time_ns() if now_ns is None else now_ns
        self.page_size = page_size
        self.deadline = time.monotonic() + max_seconds
        self.queries = 0
        self.evidence = Evidence()

    def query(self, expression, start, end):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0 or self.queries >= MAX_QUERIES:
            raise IncompleteEvidence("query_budget_exceeded")
        if len(expression.encode()) > MAX_EXPRESSION_BYTES:
            raise IncompleteEvidence("context_expression_budget_exceeded")
        self.queries += 1
        result = self.transport(expression, start, end, self.page_size, min(remaining, 180))
        try:
            if result["status"] != "success" or result["data"]["resultType"] != "streams":
                raise ValueError
            rows = []
            for stream in result["data"]["result"]:
                for value in stream["values"]:
                    timestamp, body = int(value[0]), value[1].encode("utf-8")
                    if not start <= timestamp < end:
                        raise ValueError
                    metadata = dict(stream["stream"])
                    if len(value) > 2:
                        metadata.update(value[2])
                    digest = hashlib.sha256(body).hexdigest()
                    if metadata.get("audit_sha256") != digest:
                        raise ValueError
                    rows.append((timestamp, digest, body))
        except (KeyError, IndexError, TypeError, ValueError, AttributeError, UnicodeError) as error:
            raise IncompleteEvidence("invalid_loki_response") from error
        if len(rows) > self.page_size:
            raise IncompleteEvidence("query_page_overflow")
        return sorted(rows)

    def tied(self, expression, timestamp, prefix=""):
        suffix = f' | audit_sha256=~"{prefix}[0-9a-f]*"' if prefix else ""
        rows = self.query(expression + suffix, timestamp, timestamp + 1)
        if len(rows) < self.page_size:
            return rows
        if len(prefix) >= 64:
            raise IncompleteEvidence("unresolvable_timestamp_tie")
        result = []
        for char in "0123456789abcdef":
            result.extend(self.tied(expression, timestamp, prefix + char))
        return result

    def retrieve(self, expression, start, end, accept):
        cursor = start
        while cursor < end:
            rows = self.query(expression, cursor, end)
            if not rows:
                break
            if len(rows) < self.page_size:
                chosen = rows
            else:
                boundary = rows[-1][0]
                chosen = [row for row in rows if row[0] < boundary]
                chosen.extend(self.tied(expression, boundary))
            for _, _, body in chosen:
                event = parse_body(body)
                if not accept(event):
                    raise IncompleteEvidence("loki_label_mismatch")
                self.evidence.add(body, event)
            if len(rows) < self.page_size:
                break
            cursor = rows[-1][0] + 1

    def investigate(self, group, start_ns, end_ns):
        if not re.fullmatch(r"[0-9a-fA-F]+", group):
            raise ValueError("group_ref_must_be_hex")
        if end_ns <= start_ns:
            raise ValueError("inverted_receipt_window")
        cutoff = self.now_ns - READER_CUTOFF_NS
        omitted = start_ns < cutoff
        start_ns = max(start_ns, cutoff)
        if start_ns >= end_ns:
            result = self.evidence.summary(group, source="loki", receipt_cutoff_omitted=True)
            result["queried_receipt_window_ns"] = None
            result["query_count"] = self.queries
            return result
        selector = (
            "{service_name="
            + json.dumps(self.service_name)
            + ",deployment_environment_name="
            + json.dumps(self.environment_name)
            + ",audit_bucket="
            + json.dumps(bucket(group))
            + "}"
        )
        self.retrieve(
            selector + " | audit_group=" + json.dumps(group),
            start_ns,
            end_ns,
            lambda e: e.get("group_ref") == group and bucket(e["group_ref"]) == bucket(group),
        )
        sessions = {
            session(e) for e in self.evidence.events.values() if e.get("group_ref") == group
        }
        pairs = defaultdict(set)
        for engine, account, recorder in sessions:
            if all((engine, account, recorder)):
                pairs[bucket("", engine, account)].add((engine, account, recorder))
        for partition, identities in sorted(pairs.items()):
            base = (
                "{service_name="
                + json.dumps(self.service_name)
                + ",deployment_environment_name="
                + json.dumps(self.environment_name)
                + ",audit_bucket="
                + json.dumps(partition)
                + "}"
            )
            for engine, account, recorder in sorted(identities):
                expression = (
                    base
                    + ' | audit_group="" | audit_engine='
                    + json.dumps(engine)
                    + " and audit_account="
                    + json.dumps(account)
                    + " and audit_session="
                    + json.dumps(recorder)
                )
                self.retrieve(
                    expression,
                    start_ns,
                    end_ns,
                    lambda e, expected=(engine, account, recorder), expected_bucket=partition: (
                        not e.get("group_ref")
                        and session(e) == expected
                        and bucket("", e["engine_id"], e.get("account_ref", "")) == expected_bucket
                    ),
                )
        result = self.evidence.summary(group, source="loki", receipt_cutoff_omitted=omitted)
        result["queried_receipt_window_ns"] = [start_ns, end_ns]
        result["query_count"] = self.queries
        return result
