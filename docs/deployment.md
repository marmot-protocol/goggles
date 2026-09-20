# Goggles Deployment Notes

## V4 source metadata compatibility

The committed v4 schema is synchronized byte for byte with MDK commit
`8cf083167d1db488033e9d37acb2bf132b12df37`, including `local_member_ref`.
Deploy the updated web application to accept newer MDK source-context records.
Previously rejected bodies were not retained: they must be retried from the
client if still available. Apply migration 0017 to add a covering group-session
index and a partial index containing only source-bearing events. Index creation
can briefly block writes on a populated database; schedule it accordingly. No
purge or evidence backfill is required.

Group overview and timeline metadata now resolve from retained source events
with the same engine, account and recorder-session ID, including startup files
without events for that group. Existing accepted evidence benefits immediately,
without rewriting uploads or rebuilding projections. Missing session IDs or
deleted/unuploaded source segments remain unknown. File-level metadata remains
an exact summary of that file rather than an inferred copy from another segment.

## Audit Evidence Retention

Audit uploads and their events use one retention window, defaulting to **30 days
from server receipt** (`AuditFile.created_at`), not the event's timestamp or the
age of its group. Pruning deletes entire expired uploads and their events, ages
out body-free rejection records, and rebuilds affected groups' projections from
surviving evidence. There is no historical rollup. Saved investigation reports,
group metadata, backups and exported copies are outside this command's scope.
The 30-day window is the chosen investigation-history policy, replacing the
previous 14-day default; scheduling separately ensures that policy runs regularly.

The Compose `retention` service is the sole automatic pruning trigger. It waits
for a healthy web service (after migrations), runs an immediate catch-up
prune, then runs nightly at **03:00 UTC**, independent of web restarts. Failed
runs retry every five minutes. Each run finishes before another begins within
that service; keep one retention replica. Expired evidence can remain until the
next nightly run (normally less than 31 days total), or longer during an outage.

For existing installations, set `GOGGLES_AUDIT_RETENTION_DAYS=30` in the deployment
environment: an existing value of 14 overrides the new default. Both catch-up and
nightly runs use this same setting. Preview against the deployed database with:

```sh
docker compose exec -T web python manage.py prune_audit_data --dry-run
```

Deploy with `docker compose up -d --build` to include the new retention service.
Verify it with `docker compose ps retention` and
`docker compose logs --since 24h retention`; successful runs report aggregate
counts, including when there is nothing to prune. Monitor these logs for failures
or missing daily completion. A running container alone does not prove pruning
succeeded. This repository does not configure external alert delivery.

Despite its legacy name, `GOGGLES_PRUNE_ON_STARTUP=0` disables both catch-up and
nightly runs in `retention`. The existing name is retained so deployment disable
settings continue to work. Recreate `retention` after changing this flag; changing
the environment file or restarting `web` alone does not change a running scheduler.
Stop `retention` and confirm its pruning child has exited before a historical
purge or maintenance that must exclude pruning.

The retention container uses the web memory/swap, CPU and PID limit settings.
These limits apply per container: budget capacity for web, retention and Postgres
running together. Postgres-side query and VACUUM work uses the database container's
resources, not the retention container's limits.

Manual `prune_audit_data` calls remain explicit operations and support
`--dry-run` and `--retention-days N`.

On Postgres, pruning runs `VACUUM ANALYZE` on the file and event tables to make
deleted space reusable. This is not secure erasure or removal of backups.

## V4-only acceptance and historical data reset

The [read-only production inventory](v4-cutover-inventory-2026-09-10.md) records
the initial dry-run counts and known backup copies.

This is a staged, destructive cutover. Implementation does not authorize the
production purge. Older clients intentionally receive HTTP 400 until they emit
v4 files. Do not rename or translate legacy files to bypass the boundary.

### Schema and deployment gate

The committed `docs/schemas/audit-log-event.v4.schema.json` is a byte-for-byte
copy of MDK's finalized `crates/marmot-forensics/schema/audit-log-event.v4.schema.json`.
Its SHA-256 is `7da683d30c3ab5ae9a11c9998e61634d41cfd242c95bbf01bd98aadc54b60200`.
The source task confirmed this field set on 2026-09-10, initially on
`codex/audit-v4` based on `c1289eedaa62813da1876605d29d42e7e43ce84b`.
Before deployment, record the final MDK commit and compare both checksums again.
Do not deploy if they differ. Run `just check`, `just ci`, and
`just validate-schema fixtures/*.jsonl` on the final Goggles revision.
Also confirm MDK's actual emitted value domains against the documented Goggles
storage/display limits in [the upload contract](api-v1.md#v4-upload-rejection-diagnostics):
engine IDs and other bounded columns, integer ranges, reference widths and the
year-2100 wall-time ceiling. Exercise representative maximum-sized MDK segments.
A schema-valid value outside these limits rejects the whole file with
`storage_limit_exceeded`; that engine cannot upload that segment until its values
or Goggles' limits are corrected. Treat this compatibility check as a deployment
gate, not evidence established by the schema checksum alone.

1. Stop any running `retention` service and confirm its pruning child has exited
   **before beginning the cutover**; it can delete nightly without a web restart.
   Set `GOGGLES_PRUNE_ON_STARTUP=0` in the deployment environment and keep it at 0
   until deletion is approved. Inventory the installation, database, backups and
   exports before changing it. Record a production `purge_audit_data --dry-run` count (using
   `docker compose exec -T web python manage.py purge_audit_data --dry-run`).
   The existing command counts uploads, events, groups, reports and rejections;
   the new command additionally counts every projection table.
2. Pause uploads on **all** old workers and drain/stop them, including in-flight
   ingestion and exports. Keep exports disabled during the cutover with
   `GOGGLES_EXPORTS_ENABLED=0`. An already streaming export must be drained;
   changing the flag does not terminate it. Do not permit a rolling deployment
   to leave a v1-v3 accepting worker reachable.
3. Deploy the v4-only release and apply migrations. Migration 0015 removes the
   old source-label/pubkey columns, adds `source_hardware_model`, and removes
   sensitive metadata columns from the existing rejection table. It does not purge raw evidence or reports.
   **The retention service must stay disabled.** Confirm the flag from step 1
   is 0, then recreate both `web` and `retention` with the new Compose definition
   and environment. Confirm `retention` logs "Automatic retention pruning is
   disabled." Recreating only `web` does not update the scheduler's environment.
   The new web command runs migrations, collectstatic and gunicorn without pruning.
   Older releases may prune on web startup, and the oldest workers do not honor
   this flag: stop/drain them before recreating with the new Compose definition.
4. Re-enable uploads only on v4-only workers. Test authenticated raw NDJSON and
   multipart requests with synthetic invalid/legacy/mixed bodies; they must
   return 400 with no new `AuditFile`, `AuditEvent`, group or projection rows.
   Rejections contain only time, credential reference, declared/received byte
   counts, HTTP status, fixed reason code and optional line number. Requests
   with multiple file parts
   return 413 and store no evidence. Test a synthetic valid v4 record as well.
   Never use actual private data for these probes. Source metadata is derived
   from validated body source contexts; client filenames, source headers and
   form metadata do not populate file identity. Segments without source context
   are valid. Hardware model must be a system model, never a user-assigned name,
   hostname or serial number; its provenance is enforced by the MDK producer,
   not by guessing from arbitrary strings in Goggles.
5. Confirm the new boundary is the only reachable ingress, then pause v4 uploads
   briefly and drain in-flight requests for an exact reset. Run the **new**
   `purge_audit_data --dry-run` and retain counts, timestamp and release revision.
   Obtain explicit approval for these concrete production counts before step 6.
6. **Only after approval**, execute:
   `docker compose exec -T web python manage.py purge_audit_data --confirm-delete-audit-data`.
   This deletes audit uploads, raw events, group workspaces, derived projections,
   saved reports and upload-rejection records. Users, permissions, sessions,
   upload tokens and personal access tokens remain intact. Verify all audit
   counts are zero using another `--dry-run` while uploads are still paused.
7. Resume v4 uploads and exports. Verify a new valid v4 file and its projections.
   Replay synthetic legacy and forbidden-field uploads; assert evidence counts
   do not increase (a body-free rejection record may increase). Resume normal
   automatic retention only after the deletion approval is fulfilled: set
   `GOGGLES_PRUNE_ON_STARTUP=1` and recreate `retention` so it loads the new value.
   This immediately runs catch-up pruning and enables nightly runs. Verify its
   completion in the retention logs; changing the environment file alone does
   not re-enable an already-running disabled scheduler.

The acceptance boundary must be deployed **before** the purge. Never roll back
to a legacy-accepting application after the reset. If v4 needs rollback, disable
uploads/exports and roll forward with a corrected v4-only build. Restoring an old
backup reintroduces prohibited data and requires a separate, approved cleanup.

### Backups and exported copies: separate inventory

A database purge is not deletion of every historical copy. Inventory each
storage location by owner, location, creation range, retention and deletion
status, without copying raw contents into a ticket or report:

- Postgres volume, replicas, WAL archives, PITR retention and managed snapshots.
- Repository/deployment `backups/` SQL dumps and compressed database archives;
  filesystem/VM snapshots and backup jobs, including offsite destinations.
- Raw JSONL downloads, group NDJSON exports, agent-state JSON, saved report JSON,
  analyst workspaces and downstream CGKA pipeline inputs/archives.
- Proxy/application log stores and error-monitoring retention; review configured
  request logging without printing credential values or request bodies.

Use read-only provider listings and file metadata. Do not make a fresh copy of
historical sensitive data by default. Any required rollback backup retains the
same sensitive data and must have an explicitly recorded owner and expiry.
Purge approvals for the live DB do not authorize deletion of these other copies.

`VACUUM ANALYZE` makes deleted space reusable and updates statistics; it is not
secure erasure, and does not remove old backups, WAL or exported files. Coordinate
physical retention/erasure separately with the storage operator.

## Streaming Group Export

`GET /api/v1/groups/{slug}/export/` streams a group's full forensic aggregate as
NDJSON (see `docs/api-v1.md`). It is a long-lived, resource-intensive response, so
the gunicorn command runs threaded workers with a raised timeout:
`--workers 3 --threads 4 --timeout 300 --max-requests 500 --max-requests-jitter 50`.

Capacity model — size the database for it:

- **Connections.** Each in-flight request holds one database connection for its full
  duration. With `--workers 3 --threads 4`, up to **12** connections may be live at
  once, and an export can hold one for minutes. Provision Postgres `max_connections`
  (or pooler slots) for at least `workers × threads` plus headroom for background
  tasks. If a transaction-mode pooler (e.g. PgBouncer) fronts the database it breaks
  server-side cursors; set `GOGGLES_DISABLE_SERVER_SIDE_CURSORS=1` in that case (reads
  fall back to client-side chunked fetches, still bounded by the query `chunk_size`).
- **CPU / GIL.** Serializing rows to JSON is CPU-bound and holds the GIL, so
  concurrent exports within one worker do not run in parallel — throughput is roughly
  one export per worker at a time. Scale workers (and DB connections) if concurrent
  large exports are expected.
- **Timeout scope.** `--timeout 300` is process-wide: it also relaxes gunicorn's
  liveness guard for uploads and every other request, not just exports.
- **Kill-switch.** Set `GOGGLES_EXPORTS_ENABLED=0` and restart to shed the export
  surface without affecting uploads or the rest of the API.

The edge proxy (Caddy) streams `reverse_proxy` responses by default, so no proxy
change is required; `nginx` serves only static assets and is not in the export
request path.

## Upload capacity model

Compose runs separate pools. `web` has three workers with two threads each for
browsing, exports and health, and always disables uploads. `ingest` has two
synchronous workers on loopback port 8002. The Caddy upload matcher sends POSTs
on **both** audit upload routes to that pool; other requests still use port 8000.
Apply the route change with the application change: sending POSTs to `web` now
returns 503. A bare Dockerfile invocation remains a combined development pool
and is not the isolated production configuration.

Caddy sheds excess uploads using `unhealthy_request_count 2`; upstream overload,
connection failure and timeout on these routes return 503 with `Retry-After: 30`.
Keep this cap aligned with `GOGGLES_INGEST_WORKERS`. There is no durable server
queue and no asynchronous acceptance: 201 means evidence and projections have
committed, 200 means an already committed identical file, and 503 means retry.
Clients must retain their file and retry with jitter. A lost HTTP response can
follow a successful commit; the file hash makes that retry safe.

The sync upload worker has a 120s hard deadline (including body reading and
Python computation), with a 125s upstream response-header deadline. The threaded
read pool's 300s Gunicorn timeout is a worker heartbeat, **not** a request deadline.
Inside upload atomic writes, PostgreSQL 17 enforces a 90s transaction deadline,
30s per statement, 1s lock wait, and 15s idle transaction deadline. These are
transaction-local and do not change browsing, export or retention settings.
Recorder advisory locks and existing group NOWAIT locks reject contention before
raw evidence writes. New-group uniqueness conflicts are bounded by the lock
deadline. No global ingestion mutex serializes independent groups/recorders.

These are protection limits, not acceptance latency targets. A true same-recorder
historical rebuild can still exceed 90s and return 503; repeating an intrinsically
over-budget file will not make it smaller. Investigate repeated failures with
synthetic/authorized staging evidence before changing budgets. Do not reopen
unbounded shared upload workers to process such a file. See
[the incident investigation](upload-lock-investigation-2026-09-20.md).

Budget for the multipart `BytesIO`, its bytes read copy, decoded text, parsed
records, normalized values and projection/database work, plus worker baseline
within the upload pool; exports have a separate pool. The pre-v4 capacity exercise measured approximately
1.23 GiB RSS for a 64 MiB upload (about 19 times the body). That is historical
baseline evidence, **not a v4 peak-memory measurement**. The extra in-memory
multipart buffer and allocation transients require more headroom. The former
12-slot extrapolation was already about 14.7 GiB under the default 16 GiB
container limit; do not use that concurrency for the v4 cutover without new
measurements.

Before deployment, load-test synthetic near-limit v4 multipart and raw uploads
at the configured concurrency together with representative exports. Record peak
container RSS, latency, OOM/restart count and rejection outcomes. Keep substantial
headroom below `GOGGLES_INGEST_MEMORY_LIMIT`; reduce upload workers or the upload
ceiling if needed. The two-worker default is a conservative bound, not a
substitute for that measurement. Never regain memory headroom by spooling
unvalidated uploads to disk.

## Memory-pressure deployment

The performance hardening release does **not** require purging audit data.
Deploy it with uploads paused so no old worker continues a high-memory ingest:

Set the Compose environment source once before running the commands below. This
explicit `--env-file` is required for Compose-time resource and logging limits;
the service-level `env_file` alone only populates the container environment.

```sh
export GOGGLES_ENV_FILE="${GOGGLES_ENV_FILE:-.env}"
```

1. Set `GOGGLES_UPLOADS_ENABLED=0` in the production environment.
2. Recreate the web and ingest services so the changed environment and Compose resource
   limits take effect:
   `docker compose --env-file "$GOGGLES_ENV_FILE" up -d --build --force-recreate web ingest`.
3. Confirm the container has the expected 16 GiB memory/no-swap boundary (or
   the value set in `GOGGLES_WEB_MEMORY_LIMIT`) by resolving the actual Compose
   container rather than assuming a project-specific name:
   `web_container_id="$(docker compose --env-file "$GOGGLES_ENV_FILE" ps -q web)"; test -n "$web_container_id"; docker inspect "$web_container_id"`.
   Wait for the health check to pass.
4. While uploads remain paused, exercise an authenticated group overview,
   delivery tab, and evidence tab while watching `docker stats`.
5. Verify both POST routes use port 8002 in the current Caddy config, then set
   `GOGGLES_UPLOADS_ENABLED=1` and recreate only `ingest` with the same `--env-file`.
   The `web` service keeps uploads disabled regardless of this environment value.
6. Perform a representative upload while watching `docker stats`, then recheck
   the group overview, delivery tab, and evidence tab.

Do not use `purge_audit_data` for this deployment. The query changes avoid
hydrating stored raw bodies without changing their schema or deleting evidence.

The Compose service keeps three threaded workers by default, recycles each
after a jittered 500-request budget, and constrains the whole web container to
a configurable 16 GiB default (`GOGGLES_WEB_MEMORY_LIMIT`) with no additional
swap. CPU, PID, and Docker log rotation limits are configurable through the
adjacent `GOGGLES_WEB_*` settings. The ingest pool has its own CPU and memory
limits. Shed uploads at the edge during an incident; changing the read pool's
worker count is not an ingestion-concurrency control.

## Upload body integrity and operational diagnostics

V4 retains the transport checks introduced before this cutover: missing
Content-Length returns 411; a truncated body or malformed multipart returns 400;
oversized bodies or multiple file parts return 413. No prefix is ingested.
The default file limit is 64 MiB; Caddy's 68 MiB limit leaves room for multipart
framing. The record limit defaults to the byte limit divided by 256.

Rejection persistence is best effort and contains only the approved operational
fields listed above. A database failure records a fixed warning without exception
values or SQL. Upload request events are suppressed from GlitchTip/Sentry,
including arbitrary exception values and breadcrumbs. Gunicorn access logs contain time, method, status, response size
and duration; Caddy removes the entire request object. Apply the committed Caddy
configuration as part of deployment, validate it and reload Caddy before exposing
the new ingress. Existing proxy/container/error-monitoring logs remain part of
the separate historical-copy inventory. Do not log source headers for diagnosis.

These privacy settings intentionally limit attribution: edge refusals can be
counted by status/time but cannot be assigned to a client, group or endpoint.
Do not reconstruct those values from request logs. Django's body-free rejection
records support credential-level attribution only after a request reaches the
application. Unexpected upload exceptions outside the ingestion guard are also
suppressed from external telemetry; aggregate HTTP 500 monitoring will not
provide their stack traces. Any future endpoint diagnostics must use fixed
server-side route names and exclude request values, exception messages, frame
locals and breadcrumbs. Do not restore literal URIs or exception payloads as a
workaround.

Multipart files are buffered only in memory under the upload size limit;
unvalidated bytes never spool to temporary files. Validation occurs before
deduplication as well as before persistence. A previously
stored hash never authorizes a legacy replay. All evidence and projection writes
are atomic; a later ingestion failure rolls them back and returns a fixed error.
