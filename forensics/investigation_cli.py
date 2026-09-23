"""Local, explicit-input forensic reader; never starts a server or ingests records."""

import argparse
import json
import re
from pathlib import Path

from forensics.investigation_reader import (
    IncompleteEvidence,
    LocalLokiTransport,
    LokiReader,
    read_jsonl,
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", required=True, help="Opaque hexadecimal group reference")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--jsonl", nargs="+", metavar="PATH", help="Explicit local v4 JSONL files")
    source.add_argument("--loki-url", help="Explicit loopback Loki URL")
    parser.add_argument("--service-name", help="Exact Loki service_name label")
    parser.add_argument("--environment-name", help="Exact Loki deployment_environment_name label")
    parser.add_argument("--receipt-start-ns", type=int)
    parser.add_argument("--receipt-end-ns", type=int)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[0-9a-fA-F]+", args.group):
        parser.error("--group must be a hexadecimal group reference")
    if args.loki_url and (
        not args.service_name
        or not args.environment_name
        or args.receipt_start_ns is None
        or args.receipt_end_ns is None
    ):
        parser.error("Loki requires both labels and an explicit receipt window")
    if args.jsonl and any(
        value is not None
        for value in (
            args.service_name,
            args.environment_name,
            args.receipt_start_ns,
            args.receipt_end_ns,
        )
    ):
        parser.error("receipt query options apply only to Loki")

    # The shared normalizer and message-trace rules use Django models without
    # querying a database. No ingestion command, migration or pruning runs here.
    import django
    from django.conf import settings

    if not settings.configured:
        settings.configure(
            BASE_DIR=Path(__file__).resolve().parents[1],
            INSTALLED_APPS=["django.contrib.auth", "django.contrib.contenttypes", "forensics"],
            DATABASES={"default": {"ENGINE": "django.db.backends.dummy"}},
            SECRET_KEY="local-analysis-only",
            USE_TZ=True,
        )

    django.setup()
    try:
        if args.jsonl:
            result = read_jsonl(args.jsonl).summary(args.group, source="jsonl")
        else:
            reader = LokiReader(
                LocalLokiTransport(args.loki_url), args.service_name, args.environment_name
            )
            result = reader.investigate(args.group, args.receipt_start_ns, args.receipt_end_ns)
        print(json.dumps(result, sort_keys=True))
        return 0
    except IncompleteEvidence as error:
        reason = str(error)
    except OSError:
        reason = "source_read_failed"
    except ValueError:
        reason = "invalid_input"
    print(json.dumps({"bounded_retrieval_completed": False, "reason": reason}))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
