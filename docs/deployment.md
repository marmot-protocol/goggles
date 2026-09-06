# Goggles Deployment Notes

## Audit Evidence Retention

The web container prunes aged audit evidence on every startup (migrations, then
`prune_audit_data`, then `collectstatic` and gunicorn — see
`docker-compose.yml`). Retention defaults to 14 days and is configurable via
`GOGGLES_AUDIT_RETENTION_DAYS`; uploads (and their events) older than the window
are deleted and the affected groups' projections are rebuilt from surviving
evidence. On Postgres, a successful prune also runs `VACUUM ANALYZE` scoped to
the file and event tables so deleted `raw_text` rows actually free disk space;
no-op startups skip the VACUUM. Preview what would be pruned with
`uv run python manage.py prune_audit_data --dry-run`, or override the window for
a one-off run with `uv run python manage.py prune_audit_data --retention-days N`.

## Upload Limits and Rejected Uploads

Marmot clients refuse to upload a segment larger than 64 MiB, so the server accepts
exactly that (`GOGGLES_MAX_DUMP_BYTES`, default 64 MiB; `GOGGLES_MAX_DUMP_RECORDS`,
default 100,000 lines). The limits are layered and must stay in this order:

| Layer | Limit | Why |
| --- | --- | --- |
| Marmot client | 64 MiB per file | Anything the client would send must be accepted somewhere, or it is re-posted forever. |
| Django (`GOGGLES_MAX_DUMP_BYTES`) | 64 MiB | Decides the 413 on the `Content-Length` header before reading, and records it. |
| Caddy `request_body max_size` | 68MiB | Safety net only. Must exceed Django's limit: a body Caddy refuses leaves no server-side record. |

Every authenticated attempt the upload API refuses before ingesting is stored as
an `UploadRejection` (reason `incomplete_body`, `too_large`, `too_many_parts`, or
`length_required`; declared vs received bytes; client platform/version headers;
token; IP). They appear on the **Upload logs** page, in the admin under
*Upload rejections*, and are pruned by `prune_audit_data` on the same retention
window as evidence. A body shorter than its `Content-Length` is refused with `400`
and **not** ingested: gunicorn hands Django whatever arrived before the connection
closed, and until this check the truncated prefix was ingested, its cut-off last
line quarantined, and the client (seeing a 400) re-posted the whole file anyway.

Memory: one 64 MiB upload holds the raw bytes, the decoded text, and every parsed
line in the worker while it ingests. Measured locally (gunicorn, one worker, a
64 MiB / 71,365-line synthetic log): worker RSS peaked at **1.23 GiB**, i.e. about
19× the body. With the default `3 workers × 4 threads` the worst case of twelve
simultaneous maximum-size uploads is ~14.7 GiB, inside the 16 GiB
`GOGGLES_WEB_MEMORY_LIMIT` but with little headroom; lower `GOGGLES_WEB_THREADS`
if such uploads are ever concurrent in practice. That same run took 179 s on
SQLite (Postgres is faster); a client whose read timeout is shorter than the
ingest sees a timeout, but its re-post of the identical body is answered
`200` immediately because the file is already stored.

### Investigating rejected or missing uploads

- `docker compose logs web` carries a gunicorn access line per request:
  `time "METHOD path" status bytes durations cl=<Content-Length> platform=<X-Goggles-Platform> app=<X-Goggles-App-Version>`.
  Count non-2xx by status and platform, or look at the duration column (`%(L)s`)
  for the request-time distribution during an incident window.
- Caddy's access log (`/var/log/caddy/goggles-access.log`, JSON) is the only
  record of requests Caddy refused itself (413 over `max_size`, client aborts).
  Filter on `"status":413` and group by `request.headers.User-Agent`.
- A device whose file never gets through shows up as repeated `too_large`
  rejections from the same token/platform; a lossy or overloaded path shows up
  as `incomplete_body` rejections whose `received_bytes` vary per attempt.

## Audit Redesign Cutover

The audit-log redesign does not require dropping the whole database. Keep the
existing database so Django users, groups, permissions, sessions, and reusable
upload tokens remain intact.

Recommended cutover:

1. Take a database backup or managed snapshot.
2. Pause audit uploads by setting `GOGGLES_UPLOADS_ENABLED=0` and restarting the
   app process.
3. Deploy the new code.
4. Run migrations with `uv run python manage.py migrate`.
5. Inspect current audit-data counts:
   `uv run python manage.py purge_audit_data --dry-run`.
6. Purge only forensic audit data:
   `uv run python manage.py purge_audit_data --confirm-delete-audit-data`.
7. Resume audit uploads by setting `GOGGLES_UPLOADS_ENABLED=1` and restarting
   the app process.

The purge command deletes audit uploads, raw events, group workspaces, derived
projections, and saved reports. It preserves user accounts and upload tokens.

On large Postgres databases, run `VACUUM ANALYZE` after the purge if reclaiming
space or refreshing planner statistics matters for the deployment window.

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
