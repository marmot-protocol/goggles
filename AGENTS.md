# Agent Notes

`AGENTS.md` is the canonical instruction file for this repository. `CLAUDE.md`
should remain a symlink to this file.

## Project

Goggles is a Django app for inspecting sensitive Marmot audit-log JSONL. Treat
raw uploads, bearer tokens, engine IDs, account refs, group refs, message IDs,
payload digests, IPs, and user agents as sensitive data.

## Local Workflow

- Install dependencies with `uv sync`.
- Use `just dev` for the seeded local app at `127.0.0.1:8000`.
- Use `just reset-db` to recreate the durable local SQLite database.
- Use `just token "name"` to create a reusable upload bearer token. Add
  `--expires-in-days N` to set an optional expiry; pass `--expires-in-days` to
  `manage.py create_upload_token` directly when invoking the command outside
  `just`.
- Use `just check` for the quick local verification suite.
- Use `just ci` before publishing when you need parity with GitHub Actions.

## Upload token lifecycle

Upload bearer tokens are long-lived, reusable credentials, not one-time codes:

- A token authenticates every upload it is presented for; `mark_used()` records
  `last_used_at` but does not revoke the token.
- A token stays valid until it is deactivated (`is_active = False`, via the
  admin) or until its optional `expires_at` is reached.
- `expires_at` is null by default (no expiry). Set it at creation with
  `--expires-in-days` or edit it in the admin to bound a token's lifetime.
- Treat a leaked token as a standing credential: deactivate or delete it in the
  admin to revoke access immediately.

## Personal access token lifecycle

Personal access tokens (`PersonalAccessToken`, raw prefix `gpat_`) are the
**read-only** counterpart to upload tokens. They authenticate the group index and
streaming group export (`GET /api/v1/groups/` and
`GET /api/v1/groups/<slug>/export/`) — never uploads. They are a distinct model and
credential from `UploadToken`; the two are never interchangeable.

- A user mints and revokes their own from the profile page; the raw token is shown
  exactly once and only its hash is stored.
- For a service account (e.g. the CGKA pipeline), mint one bound to a user with
  `manage.py create_access_token "name" --user <username>` (optionally
  `--expires-in-days N`).
- A token is only as live as its owner: it stops authenticating when revoked
  (`is_active = False`), when `expires_at` passes, or when the owning user is
  deactivated.
- The shared hashing/verification/expiry mechanics live in `forensics/token_crypto.py`
  and are single-sourced across both token models.

## Guardrails

- `prune_audit_data` enforces audit evidence retention (default 14 days,
  `GOGGLES_AUDIT_RETENTION_DAYS`) by deleting aged uploads and events, then
  rebuilding the touched groups' projections. The web container runs it on every
  startup in `docker-compose.yml`, so every deploy/restart prunes. It is distinct
  from `purge_audit_data`, which wipes *all* audit data but still requires
  `--confirm-delete-audit-data`.
- Keep upload and forensic behavior grounded in the JSONL schema and existing
  ingestion tests.
- Preserve raw audit-log text and line-level evidence unless a task explicitly
  asks to change storage behavior.
- Do not log bearer tokens or raw upload bodies.
- Keep UI changes compact and operational; this is an internal investigation
  tool, not a marketing surface.
