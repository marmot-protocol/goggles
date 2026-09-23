"""Private, bounded, atomic output for a local investigation result."""

import json
import os
import stat
import tempfile
import tomllib
from collections import defaultdict
from pathlib import Path

from forensics.analysis import event_message_ids
from forensics.audit_schema import SCHEMA_VERSION
from forensics.investigation_reader import IncompleteEvidence, identity, session

BUNDLE_VERSION = "goggles-investigation-bundle/v1"
MAX_BUNDLE_BYTES = 128 * 1024 * 1024
ORDERING = (
    "Within each engine/account/recorder session: sequence, then body SHA-256; "
    "no global causal order."
)


def tool_version():
    try:
        with (Path(__file__).resolve().parents[1] / "pyproject.toml").open("rb") as stream:
            return tomllib.load(stream)["project"]["version"]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as error:
        raise IncompleteEvidence("tool_version_unavailable") from error


def validate_bundle_target(path):
    target = Path(path)
    if not target.is_absolute():
        raise IncompleteEvidence("bundle_path_must_be_absolute")
    try:
        parent = os.lstat(target.parent)
        if (
            not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.getuid()
            or parent.st_mode & 0o077
        ):
            raise IncompleteEvidence("bundle_parent_not_private")
        os.lstat(target)
    except FileNotFoundError:
        if not target.parent.exists():
            raise IncompleteEvidence("bundle_parent_unavailable") from None
    except OSError as error:
        raise IncompleteEvidence("bundle_target_unavailable") from error
    else:
        raise IncompleteEvidence("bundle_target_exists")
    return target


def _scope(summary, *, supplied_file_count):
    if summary["source"] == "jsonl":
        if supplied_file_count is None:
            raise IncompleteEvidence("missing_bundle_scope")
        return {"type": "provided_files_only", "supplied_file_count": supplied_file_count}
    if summary["source"] == "loki":
        required = (
            "requested_receipt_window_ns",
            "queried_receipt_window_ns",
            "reader_cutoff_ns",
            "receipt_cutoff_omitted",
            "query_count",
        )
        if any(key not in summary for key in required):
            raise IncompleteEvidence("missing_bundle_scope")
        return {
            "type": "queried_receipt_window",
            "requested_receipt_window_ns": summary["requested_receipt_window_ns"],
            "effective_receipt_window_ns": summary["queried_receipt_window_ns"],
            "reader_cutoff_ns": summary["reader_cutoff_ns"],
            "receipt_cutoff_omitted": summary["receipt_cutoff_omitted"],
            "query_count": summary["query_count"],
        }
    raise IncompleteEvidence("unsupported_bundle_source")


def write_bundle(
    path,
    evidence,
    group,
    summary,
    *,
    acquisition_started_ns,
    acquisition_completed_ns,
    supplied_file_count=None,
):
    """Publish a complete bundle once, without replacing an existing path."""
    target = validate_bundle_target(path)
    selected, _, model_refs, traces, _ = evidence.reconstruct(group)
    ordered_refs = sorted(
        selected,
        key=lambda digest: (
            session(evidence.events[digest]),
            evidence.events[digest]["seq"],
            digest,
        ),
    )
    identities = defaultdict(list)
    for digest in ordered_refs:
        identities[identity(evidence.events[digest])].append(digest)
    trace_refs = defaultdict(set)
    for digest, model in model_refs:
        for msg_id in event_message_ids(model):
            trace_refs[msg_id].add(digest)
    header = {
        "schema_version": BUNDLE_VERSION,
        "tool": {"name": "goggles-investigation-reader", "package_version": tool_version()},
        "source_format_version": SCHEMA_VERSION,
        "group_ref": group,
        "acquisition_time_bounds_ns": [acquisition_started_ns, acquisition_completed_ns],
        "scope": _scope(summary, supplied_file_count=supplied_file_count),
        "ordering": ORDERING,
        "summary": summary,
    }

    temporary = None
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=".goggles-investigation-", suffix=".tmp", dir=target.parent
        )
        try:
            os.fchmod(descriptor, 0o600)
            stream = os.fdopen(descriptor, "wb")
        except Exception:
            os.close(descriptor)
            raise
        with stream:
            written = 0

            def emit(value):
                nonlocal written
                encoded = value.encode("utf-8")
                written += len(encoded)
                if written > MAX_BUNDLE_BYTES:
                    raise IncompleteEvidence("bundle_budget_exceeded")
                stream.write(encoded)

            def dump(value):
                return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=True)

            emit(dump(header)[:-1])
            emit(',"evidence":[')
            for index, digest in enumerate(ordered_refs):
                if index:
                    emit(",")
                emit(
                    dump(
                        {
                            "sha256": digest,
                            "body": selected[digest].decode("utf-8"),
                            "occurrences": evidence.occurrences[digest],
                        }
                    )
                )
            emit('],"conflicts":[')
            first = True
            for key, refs in sorted(identities.items()):
                if len(refs) < 2:
                    continue
                if not first:
                    emit(",")
                first = False
                emit(
                    dump(
                        {
                            "identity": {
                                "engine_id": key[0],
                                "account_ref": key[1],
                                "recorder_session_id": key[2],
                                "seq": key[3],
                            },
                            "evidence_refs": refs,
                        }
                    )
                )
            emit('],"message_traces":[')
            for index, trace in enumerate(traces):
                if index:
                    emit(",")
                emit(dump(trace | {"evidence_refs": sorted(trace_refs[trace["msg_id"]])}))
            emit("]}")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, target)
    except FileExistsError as error:
        raise IncompleteEvidence("bundle_target_exists") from error
    except OSError as error:
        raise IncompleteEvidence("bundle_write_failed") from error
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
