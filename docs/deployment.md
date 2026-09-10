# Goggles Deployment Notes

## Audit Evidence Retention

The web container normally prunes aged audit evidence on startup (migrations, then
`prune_audit_data`, then `collectstatic` and gunicorn — see
`docker-compose.yml`). Retention defaults to 14 days and is configurable via
`GOGGLES_AUDIT_RETENTION_DAYS`; uploads (and their events) older than the window
are deleted and the affected groups' projections are rebuilt from surviving
evidence. On Postgres, a successful prune also runs `VACUUM ANALYZE` scoped to
the file and event tables so deleted `raw_text` rows actually free disk space;
no-op startups skip the VACUUM. Preview what would be pruned with
`uv run python manage.py prune_audit_data --dry-run`, or override the window for
a one-off run with `uv run python manage.py prune_audit_data --retention-days N`.

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

1. Inventory the existing installation, database, backups and exports before
   changing it. Record a production `purge_audit_data --dry-run` count (using
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
   **Normal Compose startup also runs retention pruning.** Before any restart,
   set `GOGGLES_PRUNE_ON_STARTUP=0` in the deployment environment. Keep it at 0
   until deletion is authorized. The new Compose command then runs migrations,
   collectstatic and gunicorn without pruning. Existing old workers do not honor
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
   retention startup behavior (`GOGGLES_PRUNE_ON_STARTUP=1`) only after the
   deletion approval is fulfilled.

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

The default is three workers with **two threads each**, limiting concurrent
requests to six across the container. This is lower than the previous four-thread
setting because v4 multipart uploads must stay in RAM until validation. Update
existing explicit `GOGGLES_WEB_THREADS=4` overrides too; rebuilding an image does
not replace operator environment settings. Streaming exports share these slots.

Budget for the multipart `BytesIO`, its bytes read copy, decoded text, parsed
records, normalized values and projection/database work, plus worker baseline
and concurrent exports. The pre-v4 capacity exercise measured approximately
1.23 GiB RSS for a 64 MiB upload (about 19 times the body). That is historical
baseline evidence, **not a v4 peak-memory measurement**. The extra in-memory
multipart buffer and allocation transients require more headroom. The former
12-slot extrapolation was already about 14.7 GiB under the default 16 GiB
container limit; do not use that concurrency for the v4 cutover without new
measurements.

Before deployment, load-test synthetic near-limit v4 multipart and raw uploads
at the configured concurrency together with representative exports. Record peak
container RSS, latency, OOM/restart count and rejection outcomes. Keep substantial
headroom below `GOGGLES_WEB_MEMORY_LIMIT`; reduce workers/threads or the upload
ceiling if needed. The two-thread default is a conservative reduction, not a
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
2. Recreate the web service so the changed environment and Compose resource
   limits take effect:
   `docker compose --env-file "$GOGGLES_ENV_FILE" up -d --build --force-recreate web`.
3. Confirm the container has the expected 16 GiB memory/no-swap boundary (or
   the value set in `GOGGLES_WEB_MEMORY_LIMIT`) by resolving the actual Compose
   container rather than assuming a project-specific name:
   `web_container_id="$(docker compose --env-file "$GOGGLES_ENV_FILE" ps -q web)"; test -n "$web_container_id"; docker inspect "$web_container_id"`.
   Wait for the health check to pass.
4. While uploads remain paused, exercise an authenticated group overview,
   delivery tab, and evidence tab while watching `docker stats`.
5. Set `GOGGLES_UPLOADS_ENABLED=1` and recreate the web service again with the
   same `--env-file` command from step 2.
6. Perform a representative upload while watching `docker stats`, then recheck
   the group overview, delivery tab, and evidence tab.

Do not use `purge_audit_data` for this deployment. The query changes avoid
hydrating stored raw bodies without changing their schema or deleting evidence.

The Compose service keeps three threaded workers by default, recycles each
after a jittered 500-request budget, and constrains the whole web container to
a configurable 16 GiB default (`GOGGLES_WEB_MEMORY_LIMIT`) with no additional
swap. CPU, PID, and Docker log rotation limits are configurable through the
adjacent `GOGGLES_WEB_*` settings. During an incident, set
`GOGGLES_WEB_WORKERS=1` before the recreate to prevent concurrent amplification;
restore the measured production worker count only after memory remains stable.

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

Multipart files are buffered only in memory under the upload size limit;
unvalidated bytes never spool to temporary files. Validation occurs before
deduplication as well as before persistence. A previously
stored hash never authorizes a legacy replay. All evidence and projection writes
are atomic; a later ingestion failure rolls them back and returns a fixed error.
