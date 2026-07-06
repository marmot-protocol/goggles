# Goggles Deployment Notes

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
  server-side cursors; set `DISABLE_SERVER_SIDE_CURSORS=1` in that case (memory stays
  bounded via the query `chunk_size`).
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
