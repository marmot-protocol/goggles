"""Synthetic contracts for the offline and bounded local Loki readers."""

import hashlib
import http.client
import json
import re
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase

from forensics.investigation_reader import (
    MAX_QUERIES,
    READER_CUTOFF_NS,
    Evidence,
    IncompleteEvidence,
    LocalLokiTransport,
    LokiReader,
    bucket,
    read_jsonl,
)

ACCOUNT = "a" * 32
GROUP = "ab12"
OTHER_GROUP = "cd34"
MESSAGE = "b" * 64


def body(seq, *, group=GROUP, session="synthetic-session", kind=None, engine="synthetic-engine"):
    event = {
        "schema_version": "marmot-forensics-audit/v4",
        "seq": seq,
        "wall_time_ms": 1_700_000_000_000 + seq,
        "engine_id": engine,
        "account_ref": ACCOUNT,
        "recorder_session_id": session,
        "kind": kind or {"type": "recorder_started", "recorder": "mdk"},
    }
    if group:
        event["group_ref"] = group
    return json.dumps(event, separators=(",", ":")).encode()


class FakeLoki:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def __call__(self, expression, start, end, limit, timeout):
        self.calls.append((expression, start, end))
        assert 'deployment_environment_name="isolated-test"' in expression
        partition = re.search(r'audit_bucket="([^"]+)"', expression).group(1)
        group_filter = re.search(r'\| audit_group="([^"]*)"', expression)
        digest_filter = re.search(r'audit_sha256=~"([0-9a-f]*)\[0-9a-f\]\*"', expression)
        output = []
        for timestamp, raw in self.rows:
            event = json.loads(raw)
            digest = hashlib.sha256(raw).hexdigest()
            if (
                not start <= timestamp < end
                or bucket(
                    event.get("group_ref", ""), event["engine_id"], event.get("account_ref", "")
                )
                != partition
            ):
                continue
            if group_filter and event.get("group_ref", "") != group_filter.group(1):
                continue
            if digest_filter and not digest.startswith(digest_filter.group(1)):
                continue
            if "audit_engine=" in expression and (
                json.dumps(event["engine_id"]) not in expression
                or json.dumps(event.get("recorder_session_id", "")) not in expression
            ):
                continue
            output.append((timestamp, digest, raw))
        output.sort()
        return {
            "status": "success",
            "data": {
                "resultType": "streams",
                "result": [
                    {
                        "stream": {},
                        "values": [
                            [str(timestamp), raw.decode(), {"audit_sha256": digest}]
                            for timestamp, digest, raw in output[:limit]
                        ],
                    }
                ],
            },
        }


class InvestigationReaderTests(SimpleTestCase):
    def test_jsonl_selection_preserves_exact_bytes_context_and_conflicts(self):
        first = body(
            1,
            kind={
                "type": "message_state_changed",
                "msg_id": MESSAGE,
                "new_state": "seen",
                "reason": "synthetic",
            },
        )
        conflict = body(
            1,
            kind={
                "type": "message_state_changed",
                "msg_id": MESSAGE,
                "new_state": "sent",
                "reason": "synthetic",
            },
        )
        context = body(2, group="")
        unrelated = body(3, group="", session="other-session")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "synthetic.jsonl"
            source.write_bytes(b"\n".join([first, first, conflict, context, unrelated]) + b"\n")
            evidence = read_jsonl([source])
        selected, incomplete = evidence.selected(GROUP)
        self.assertFalse(incomplete)
        self.assertEqual(set(selected.values()), {first, conflict, context})
        result = evidence.summary(GROUP, source="jsonl")
        self.assertEqual(result["duplicate_occurrences"], 1)
        self.assertEqual(result["conflicting_identities"], 1)
        self.assertEqual(result["message_trace_count"], 1)
        self.assertEqual(result["supporting_groupless_context"], 1)
        self.assertEqual(result["scope"], "provided_files_only")

    def test_invalid_or_unterminated_jsonl_is_visibly_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "synthetic.jsonl"
            source.write_bytes(body(1))
            with self.assertRaisesRegex(IncompleteEvidence, "incomplete_jsonl_line"):
                read_jsonl([source])
            source.write_bytes(body(1) + b"\n" + b'{"schema_version":"invalid"}\n')
            with self.assertRaisesRegex(IncompleteEvidence, "invalid_v4_body"):
                read_jsonl([source])

    def test_crlf_and_blank_lines_use_the_original_json_body(self):
        raw = body(1)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "synthetic.jsonl"
            source.write_bytes(raw + b"\r\n\r\n" + raw + b"\n")
            evidence = read_jsonl([source])
        self.assertEqual(set(evidence.records.values()), {raw})
        self.assertEqual(evidence.summary(GROUP, source="jsonl")["duplicate_occurrences"], 1)

    def test_historical_bucket_vectors(self):
        self.assertEqual(bucket("group"), "b0c")
        self.assertEqual(bucket("", "engine", "account"), "b39")

    def test_loki_timestamp_ties_and_matching_context(self):
        now = 2_000_000_000_000_000_000
        stamp = now - 10**9
        first, second, third = body(1), body(2), body(3)
        context = body(4, group="")
        unrelated = body(5, group="", session="other-session")
        fake = FakeLoki([(stamp, raw) for raw in (first, second, third, context, unrelated)])
        reader = LokiReader(fake, "synthetic-audit", "isolated-test", now_ns=now, page_size=2)
        result = reader.investigate(GROUP, stamp - 1, stamp + 1)
        self.assertEqual(result["group_records"], 3)
        self.assertEqual(result["supporting_groupless_context"], 1)
        self.assertEqual(result["selected_distinct_bodies"], 4)
        self.assertGreater(reader.queries, 2)
        self.assertFalse(result["complete_for_requested_scope"])

    def test_jsonl_and_loki_share_selection_and_reconstruction(self):
        now = 2_000_000_000_000_000_000
        records = [
            body(1),
            body(1),
            body(1, kind={"type": "recorder_started", "recorder": "jsonl"}),
            body(2, group=""),
            body(3, group=OTHER_GROUP),
        ]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "synthetic.jsonl"
            source.write_bytes(b"\n".join(records) + b"\n")
            direct = read_jsonl([source])
        fake = FakeLoki([(now - 10**9 + index, raw) for index, raw in enumerate(records)])
        reader = LokiReader(fake, "synthetic-audit", "isolated-test", now_ns=now)
        remote = reader.investigate(GROUP, now - 2 * 10**9, now)
        self.assertEqual(direct.selected(GROUP)[0], reader.evidence.selected(GROUP)[0])
        reference = direct.summary(GROUP, source="jsonl")
        for key in (
            "selected_distinct_bodies",
            "group_records",
            "supporting_groupless_context",
            "duplicate_occurrences",
            "conflicting_identities",
            "kind_counts",
            "message_trace_count",
        ):
            self.assertEqual(remote[key], reference[key], key)

    def test_incomplete_session_does_not_join_unknown_context_or_skip_good_context(self):
        now = 2_000_000_000_000_000_000
        partial_group = json.loads(body(3))
        partial_context = json.loads(body(4, group=""))
        del partial_group["account_ref"]
        del partial_context["account_ref"]
        records = [
            body(1),
            body(2, group=""),
            json.dumps(partial_group, separators=(",", ":")).encode(),
            json.dumps(partial_context, separators=(",", ":")).encode(),
        ]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "synthetic.jsonl"
            source.write_bytes(b"\n".join(records) + b"\n")
            direct = read_jsonl([source])
        fake = FakeLoki([(now - 10**9 + index, raw) for index, raw in enumerate(records)])
        reader = LokiReader(fake, "synthetic-audit", "isolated-test", now_ns=now)
        remote = reader.investigate(GROUP, now - 2 * 10**9, now)
        self.assertEqual(direct.selected(GROUP)[0], reader.evidence.selected(GROUP)[0])
        self.assertEqual(remote["supporting_groupless_context"], 1)
        self.assertTrue(remote["context_incomplete"])
        self.assertFalse(remote["complete_for_requested_scope"])

    def test_expired_receipt_window_does_not_query(self):
        now = 2_000_000_000_000_000_000
        fake = FakeLoki([])
        reader = LokiReader(fake, "synthetic-audit", "isolated-test", now_ns=now)
        result = reader.investigate(GROUP, now - READER_CUTOFF_NS - 10, now - READER_CUTOFF_NS - 1)
        self.assertEqual(fake.calls, [])
        self.assertTrue(result["receipt_cutoff_omitted"])
        self.assertIsNone(result["queried_receipt_window_ns"])

    def test_crossing_receipt_cutoff_is_marked_incomplete(self):
        now = 2_000_000_000_000_000_000
        cutoff = now - READER_CUTOFF_NS
        fake = FakeLoki([(cutoff + 1, body(1))])
        reader = LokiReader(fake, "synthetic-audit", "isolated-test", now_ns=now)
        result = reader.investigate(GROUP, cutoff - 1, cutoff + 2)
        self.assertTrue(result["receipt_cutoff_omitted"])
        self.assertEqual(result["queried_receipt_window_ns"], [cutoff, cutoff + 2])
        self.assertEqual(result["source_event_time_bounds_ms"], [1_700_000_000_001] * 2)
        self.assertFalse(result["complete_for_requested_scope"])

    def test_unresolvable_tie_never_claims_success(self):
        now = 2_000_000_000_000_000_000
        stamp = now - 10**9
        fake = FakeLoki([(stamp, body(1)), (stamp, body(1))])
        reader = LokiReader(fake, "synthetic-audit", "isolated-test", now_ns=now, page_size=2)
        with self.assertRaises(IncompleteEvidence):
            reader.investigate(GROUP, stamp - 1, stamp + 1)

    def test_dense_tie_stops_expanding_when_evidence_budget_is_exhausted(self):
        now = 2_000_000_000_000_000_000
        stamp = now - 10**9
        rows = [(stamp, body(seq)) for seq in range(1, 41)]
        complete = LokiReader(
            FakeLoki(rows), "synthetic-audit", "isolated-test", now_ns=now, page_size=2
        )
        self.assertEqual(complete.investigate(GROUP, stamp - 1, stamp + 1)["group_records"], 40)

        limited = LokiReader(
            FakeLoki(rows), "synthetic-audit", "isolated-test", now_ns=now, page_size=2
        )
        with patch("forensics.investigation_reader.MAX_EVIDENCE_BYTES", 2 * len(body(1))):
            with self.assertRaisesRegex(IncompleteEvidence, "evidence_budget_exceeded"):
                limited.investigate(GROUP, stamp - 1, stamp + 1)
        self.assertLess(limited.queries, complete.queries)
        self.assertLessEqual(len(limited.evidence.records), 2)

    def test_query_budget_and_malformed_result_fail_closed(self):
        now = 2_000_000_000_000_000_000
        stamp = now - 10**9
        reader = LokiReader(FakeLoki([]), "synthetic-audit", "isolated-test", now_ns=now)
        reader.queries = MAX_QUERIES
        with self.assertRaisesRegex(IncompleteEvidence, "query_budget_exceeded"):
            reader.investigate(GROUP, stamp - 1, stamp + 1)

        reader = LokiReader(
            lambda *_: {"status": "success", "data": {}}, "synthetic-audit", "isolated-test"
        )
        with self.assertRaisesRegex(IncompleteEvidence, "invalid_loki_response"):
            reader.investigate(GROUP, stamp - 1, stamp + 1)

    def test_loki_label_body_mismatch_fails_closed(self):
        now = 2_000_000_000_000_000_000
        stamp = now - 10**9
        raw = body(1, group=OTHER_GROUP)
        digest = hashlib.sha256(raw).hexdigest()

        def wrong_label(*_):
            return {
                "status": "success",
                "data": {
                    "resultType": "streams",
                    "result": [
                        {
                            "stream": {},
                            "values": [[str(stamp), raw.decode(), {"audit_sha256": digest}]],
                        }
                    ],
                },
            }

        reader = LokiReader(wrong_label, "synthetic-audit", "isolated-test", now_ns=now)
        with self.assertRaisesRegex(IncompleteEvidence, "loki_label_mismatch"):
            reader.investigate(GROUP, stamp - 1, stamp + 1)

    def test_context_without_complete_session_reports_gap(self):
        evidence = Evidence()
        event = json.loads(body(1))
        del event["recorder_session_id"]
        evidence.add(json.dumps(event, separators=(",", ":")).encode())
        result = evidence.summary(GROUP, source="jsonl")
        self.assertTrue(result["context_incomplete"])
        self.assertFalse(result["complete_for_requested_scope"])

    def test_endpoint_requires_explicit_loopback(self):
        with self.assertRaises(ValueError):
            LocalLokiTransport("https://example.invalid")
        with self.assertRaises(ValueError):
            LocalLokiTransport("http://127.0.0.1:3100/path")

    def test_malformed_http_response_is_bounded_failure(self):
        transport = LocalLokiTransport("http://127.0.0.1:3100")

        class BadResponse:
            def open(self, *_args, **_kwargs):
                raise http.client.BadStatusLine("synthetic")

        transport.http = BadResponse()
        with self.assertRaisesRegex(IncompleteEvidence, "loki_request_failed"):
            transport('{service_name="test"}', 1, 2, 1, 1)
