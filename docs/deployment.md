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
