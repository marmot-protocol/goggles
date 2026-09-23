# Local audit investigation reader

This is a bounded, on-demand reader for existing v4 audit evidence. It does not
upload, ingest, modify, or delete evidence. No endpoint is configured by default.
Run it only with explicit local input:

```sh
uv run python -m forensics.investigation_cli \
  --jsonl /absolute/private/path/segment.jsonl --group ab12
```

For an isolated **loopback** Loki instance already populated with the fixed
64-bucket audit mapping, set `RECEIPT_START_NS` and `RECEIPT_END_NS` to the
intended trusted receipt-time window in Unix nanoseconds. Give the exact
service and environment labels used by that store:

```sh
uv run python -m forensics.investigation_cli \
  --loki-url http://127.0.0.1:3100 --service-name marmot-audit-month-derived \
  --environment-name isolated-feasibility \
  --receipt-start-ns "$RECEIPT_START_NS" --receipt-end-ns "$RECEIPT_END_NS" \
  --group ab12
```

The command prints aggregate JSON only. Exit code 2 and a fixed reason mean
retrieval did not complete within the schema, file, response, query, or time
budget. It does not print raw bodies or identifiers from a failed record.

To publish one private investigation artifact, add an explicit absolute
`--bundle-path` under an existing directory that you own and that grants no
group or other access (for example, mode `0700`):

```sh
mkdir -m 700 /absolute/private/path/bundles
uv run python -m forensics.investigation_cli \
  --jsonl /absolute/private/path/segment.jsonl --group ab12 \
  --bundle-path /absolute/private/path/bundles/investigation.json
```

The output is one `goggles-investigation-bundle/v1` JSON file created with mode
`0600`. It contains the exact original UTF-8 JSON body text for each selected
distinct record, its SHA-256 reference and occurrence count, identities with
conflicting body references, and Goggles' existing message traces with their
contributing evidence references. Re-encoding a decoded `body` string as
UTF-8 reproduces the original JSON body bytes. Records are ordered within each
engine/account/recorder session by sequence and then body digest. That ordering
does not assert a global causal order. The bundle also records the source
format and tool versions, acquisition time bounds, the supplied file count or
requested and effective Loki receipt window, the reader cutoff, and the same
coverage limitations as the aggregate summary. It does not include input file
paths or the Loki URL, and the command does not print either path.

The target must not already exist, including as a symlink. Retrieval,
validation, budget exhaustion, and write errors leave no final bundle. The
bundle is sensitive local evidence: handle it only in a bounded private
workspace and delete it manually when the investigation ends. This local file
has no automatic expiry. Automatic 30-day deletion for any future server
storage is a separate design and deployment gate. The bundle is not an
incident-replay export and does not add the nine legacy projections.

Both inputs validate each original UTF-8 JSON body against this repository's
current v4 schema, deduplicate identical **bytes**, preserve different bodies
with the same `(engine, account, recorder session, sequence)` identity as a
reported conflict, and select group records plus group-less records from their
exact complete `(engine, account, recorder session)` tuples. A group record
without that tuple remains selected, but its group-less context is marked
incomplete. They then use Goggles' existing normalizer and message-trace
analysis without database reads. JSONL LF or CRLF endings delimit records and
are not part of the original JSON body; blank lines are ignored. A missing
final newline is reported as an incomplete file.

Loki queries use server receipt timestamps and an independent 30-day reader
cutoff. The original source `wall_time_ms` remains in the body and is reported
separately.
The cutoff is a reader policy, not an access-control or physical-deletion
guarantee. The command resolves timestamp ties, rejects unresolved ties and
query-limit exhaustion, and explicitly reports expired windows or missing
session identities. `bounded_retrieval_completed` means these local retrieval
checks ended successfully. `complete_for_requested_scope` is always false for
Loki: this does not establish an atomic Loki snapshot, a late-arrival
watermark, historical absence, or full source coverage. A JSONL run covers
only the files named on the command line and has no receipt-time coverage
claim.

The retrieval, bucket mapping, byte deduplication, and context selection were
extracted from the local Goggles feasibility snapshot
`0a74fc32c54e389f4885af80f9acf0a4fca24471` (`scripts/feasibility/lab.py`,
`bucket.py`, `investigate.py`, `retained_reader.py`, and `unique.py`). This
snapshot is a local Git object, not a published dependency. Loki mode requires
an already populated store using the bucket and metadata mapping independently
specified by [MDK's isolated receiver contract](https://github.com/marmot-protocol/mdk/pull/1997).
That contract is loopback synthetic; this reader does not supply a deployed
writer or a production route. The reader and bundle test these contracts with
synthetic current-v4 records. They do
not include the private corpus, experiment results, lab containers, persistent
projections, or the later production access and retention design. The prior
projection parity experiment covered selected cases but is not claimed here.
