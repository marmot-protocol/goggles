# Goggles

Internal Marmot audit-log explorer.

Goggles accepts sensitive `marmot-forensics-audit` JSONL audit logs from Dark Matter clients (current schema `marmot-forensics-audit/v2`; legacy `v1` is still accepted), preserves the exact uploaded text and raw lines, normalizes common forensic columns into PostgreSQL tables, and gives the team a login-gated dashboard for comparing what multiple account-device engines saw and decided inside each group.

The audit event schema is committed at `docs/schemas/audit-log-event.v2.schema.json`. See also `docs/api-v1.md` for the authenticated read API, `docs/deployment.md` for VM deployment notes, and `docs/audit-debugging-platform-prd.md` for the platform's product requirements.

## Local Development

The easiest local workflow uses `just` and a durable SQLite database at `var/goggles-dev.sqlite3`:

```sh
uv sync --python /opt/homebrew/bin/python3.13
just reset-db
just dev
```

Goggles supports Python 3.12 and 3.13 (`requires-python = ">=3.12,<3.14"`); point `--python` at whichever interpreter you have.

The seeded development login is:

```text
username: admin
password: pass123
```

Useful commands:

```sh
just sync                # install/update local Python dependencies (uv sync)
just dev                 # run the dev server on 127.0.0.1:8000
just seed                # create/update admin/pass123 and load sample audit data
just reset-db            # delete, recreate, migrate, and seed the dev database
just token "ios qa"      # create an upload bearer token in the dev database
just purge-audit-data    # delete audit uploads/events/groups/projections/reports (keeps users + tokens)
just migrate             # apply migrations to the dev database
just makemigrations      # create migrations from model changes
just shell               # open a Django shell against the dev database
just validate-schema P   # validate JSONL paths against the committed V2 audit schema
just django-check        # run Django's system checks
just lint                # run Ruff lint checks
just format              # format Python code with Ruff
just format-check        # fail if Python code is not Ruff-formatted
just test                # run the Django test suite against local SQLite
just test-postgres       # run tests against a disposable Postgres service
just check               # run tests, Django checks, Ruff, format check, and migration drift check
just audit-dependencies  # audit the locked dependency set with pip-audit
just ci                  # run the same push/PR checks as GitHub Actions
```

Set `GOGGLES_DEV_DB` to use a different local SQLite path, or `GOGGLES_DEV_PORT` to run the dev server on another port. The VM path should use PostgreSQL.

`just test-postgres` starts the `db-test` Docker Compose service on
`127.0.0.1:55432`, runs the Django test suite with
`DATABASE_URL=postgres://goggles:goggles@127.0.0.1:55432/goggles_test`, then
removes the test database container. Set `GOGGLES_TEST_DB_PORT` or
`GOGGLES_TEST_DATABASE_URL` if that local port is already in use.

`just ci` is the full local GitHub Actions parity gate. It runs a frozen
dependency sync, the SQLite and PostgreSQL test suites, Django checks, Ruff,
format checking, migration drift checking, and the locked dependency audit.

## Upload An Audit Log

Each line must be one JSON object in the `marmot-forensics-audit` JSONL shape. Current `marmot-forensics-audit/v2` rows must include `schema_version`, `seq`, `wall_time_ms`, `audit_data_mode` (`obfuscated_sensitive_data` or `full_data`), a non-empty `engine_id`, and a `kind` object. Legacy `marmot-forensics-audit/v1` rows are still accepted, but they must additionally carry a human action (`kind.type = "human_action"` or `context.human_action.action`); action-less v1 rows are quarantined. If the JSONL includes valid `group_ref` values, Goggles will create or reuse those groups automatically. One uploaded file can contain multiple groups, but it should normally contain one `engine_id` and one `account_ref`. The bundled `fixtures/*.jsonl` samples are all `marmot-forensics-audit/v2`.

```sh
curl -X POST http://127.0.0.1:8000/api/v1/audit-logs/ \
  -H "Authorization: Bearer $GOGGLES_UPLOAD_TOKEN" \
  -H "Content-Type: application/x-ndjson" \
  -H "X-Goggles-Device-Label: Alice iPhone" \
  -H "X-Goggles-Platform: ios" \
  -H "X-Goggles-App-Version: 2026.6.8" \
  --data-binary @fixtures/sample-audit-log-trailhead-maya.jsonl
```

Account identity comes from the JSONL body: `source_context.account_label`, the
top-level `account_ref`, and (in full-data mode) `source_context.account_pubkey_hex`.
Goggles surfaces the account label as the primary identifier with the pubkey hex
shown alongside it. The remaining upload headers (`X-Goggles-Device-Label`,
`X-Goggles-Platform`, `X-Goggles-App-Version`) are optional human labels; the
forensic joins still come from the JSONL `account_ref`, `engine_id`, and
`group_ref` fields.

The group URL is only a fallback for group-less lines or broken logs. Event-level `group_ref` values take precedence:

```sh
curl -X POST http://127.0.0.1:8000/api/v1/groups/qa-fork/audit-logs/ \
  -H "Authorization: Bearer $GOGGLES_UPLOAD_TOKEN" \
  -F "audit_log=@fixtures/sample-audit-log-trailhead-maya.jsonl;type=application/x-ndjson"
```

Query parameters also work as the same fallback:

```sh
curl -X POST "http://127.0.0.1:8000/api/v1/audit-logs/?group=qa-fork" \
  -H "Authorization: Bearer $GOGGLES_UPLOAD_TOKEN" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary @fixtures/sample-audit-log-trailhead-maya.jsonl
```

Upload another one-engine file, such as `fixtures/sample-audit-log-trailhead-theo.jsonl`, to compare multiple clients in the same group. Invalid JSONL, mixed-engine uploads, or mixed-account uploads return `400` and are still saved as quarantined audit files so damaged lines can be inspected.

## Production Deployment: goggles.ipf.dev

Goggles is designed to run on a VM with Docker Compose, Postgres, Gunicorn, a small nginx static sidecar, and Caddy terminating TLS for `goggles.ipf.dev`. The Compose file binds Django to `127.0.0.1:8000` and static assets to `127.0.0.1:8001`; Caddy is the public entrypoint.

Copy `.env.example` to `.env` and replace every secret:

```dotenv
DJANGO_DEBUG=0
DJANGO_SECRET_KEY=replace-with-output-of-python-secrets-token-urlsafe-64
GOGGLES_TOKEN_HASH_KEY=replace-with-output-of-python-secrets-token-urlsafe-64
DJANGO_ALLOWED_HOSTS=goggles.ipf.dev
DJANGO_CSRF_TRUSTED_ORIGINS=https://goggles.ipf.dev
DJANGO_SECURE_SSL_REDIRECT=0
DJANGO_SESSION_COOKIE_SECURE=1
DJANGO_CSRF_COOKIE_SECURE=1
DJANGO_SECURE_HSTS_SECONDS=31536000
DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS=0
DJANGO_SECURE_HSTS_PRELOAD=0
DATABASE_URL=postgres://goggles:replace-with-long-random-database-password@db:5432/goggles
GOGGLES_MAX_DUMP_BYTES=52428800
POSTGRES_DB=goggles
POSTGRES_USER=goggles
POSTGRES_PASSWORD=replace-with-long-random-database-password
```

Generate secret values on the VM:

```sh
python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(64))
PY
```

Use the same database password in `DATABASE_URL` and `POSTGRES_PASSWORD`. If the
database password contains URL punctuation such as `@`, `/`, or `:`, URL-encode
the password portion in `DATABASE_URL`.

> **Existing deployments — migrating to `GOGGLES_TOKEN_HASH_KEY`.** Upload
> tokens issued before `GOGGLES_TOKEN_HASH_KEY` existed were hashed under
> `DJANGO_SECRET_KEY` (the historical fallback). After you configure a fresh
> `GOGGLES_TOKEN_HASH_KEY`, Goggles still checks the current `DJANGO_SECRET_KEY`
> as a legacy hash key. The first successful upload for each active, unexpired
> legacy token rekeys that database row to `GOGGLES_TOKEN_HASH_KEY`, so clients
> do not need an immediate raw-token rotation.
>
> Migration sequence for an existing deployment:
>
> 1. Deploy this code while keeping the current `DJANGO_SECRET_KEY` unchanged.
> 2. Set a fresh, stable `GOGGLES_TOKEN_HASH_KEY` and restart the web service.
> 3. Let every expected client upload once; each successful authentication
>    migrates that token hash to the dedicated key.
> 4. Rotate `DJANGO_SECRET_KEY` only after the clients you care about have
>    authenticated under step 2. Any token that never authenticated before the
>    `DJANGO_SECRET_KEY` rotation must be reissued.
>
> This lazy migration only covers the first move away from the historical
> `DJANGO_SECRET_KEY` fallback. Rotating from one dedicated
> `GOGGLES_TOKEN_HASH_KEY` value to another still requires issuing replacement
> upload tokens before the key change, then disabling the old tokens.
>
> A brand-new deployment has no pre-existing tokens, so generate a fresh
> `GOGGLES_TOKEN_HASH_KEY` directly with the command below.

First run:

```sh
docker compose up -d --build
docker compose ps
docker compose exec web python manage.py createsuperuser
docker compose exec web python manage.py create_upload_token "ios qa"
```

The web container runs `python manage.py migrate --noinput` before Gunicorn starts, so first-run migrations are handled by startup. Re-run migrations explicitly after deploys if you want to inspect them:

```sh
docker compose exec web python manage.py migrate --noinput
```

The web container runs `collectstatic` into the Docker-managed `static-assets` volume. The `static` Compose service serves that volume on `127.0.0.1:8001`, and Caddy proxies `/static/*` to it. Django/Gunicorn handles the application and upload API.

### Caddy

Use `deploy/Caddyfile.goggles.ipf.dev` as the Caddy site snippet:

```caddyfile
goggles.ipf.dev {
    request_body {
        max_size 50MB
    }

    encode zstd gzip

    handle_path /static/* {
        reverse_proxy 127.0.0.1:8001
    }

    handle {
        reverse_proxy 127.0.0.1:8000
    }
}
```

The static sidecar avoids requiring the Caddy system user to read inside the app checkout. It serves generated CSS, JavaScript, and admin assets only.

The `request_body` limit should match `GOGGLES_MAX_DUMP_BYTES`. Stock Caddy does not include rate limiting. If the deployed Caddy build includes a rate-limit module, put it in front of the upload paths. If not, rely on private network controls, Caddy body limits, Django bearer tokens, token rotation, and host-level protections such as firewall rules or fail2ban.

Health check:

```sh
curl -fsS https://goggles.ipf.dev/healthz/
```

The health endpoint returns only `{"status":"ok"}`. It does not expose config, counts, token status, or raw data.

### Public Surface

Publicly reachable paths are intentionally narrow:

- `GET /accounts/login/`, dashboard pages, and `/admin/`, protected by Django authentication.
- `POST /api/v1/audit-logs/`, protected by `Authorization: Bearer <token>`.
- `POST /api/v1/groups/<slug>/audit-logs/`, also bearer-token protected, for fallback grouping.
- `GET /healthz/`, unauthenticated and non-sensitive.

There is no public signup and no password-reset route configured.

Upload a sample log through the public endpoint:

```sh
curl -X POST https://goggles.ipf.dev/api/v1/audit-logs/ \
  -H "Authorization: Bearer $GOGGLES_UPLOAD_TOKEN" \
  -H "Content-Type: application/x-ndjson" \
  -H "X-Goggles-Device-Label: Alice iPhone" \
  -H "X-Goggles-Platform: ios" \
  --data-binary @fixtures/sample-audit-log-trailhead-maya.jsonl
```

Invalid JSONL is saved as a quarantined upload and returns `400`.

### Operational Safety

- Web UI access uses Django users; there is no public signup.
- Uploads require bearer tokens generated with `create_upload_token`.
- Upload tokens are reusable, long-lived credentials, not one-time codes; each
  upload it authenticates only updates `last_used_at`.
- Upload token secrets are shown once and stored only as keyed hashes.
- Upload token hashes are keyed on `GOGGLES_TOKEN_HASH_KEY`, a dedicated
  secret that is **independent of `DJANGO_SECRET_KEY`**. Provision a stable
  `GOGGLES_TOKEN_HASH_KEY` in production so that rotating Django's signing
  key (sessions, CSRF, password reset) does **not** invalidate every issued
  upload token. If `GOGGLES_TOKEN_HASH_KEY` is unset it falls back to
  `DJANGO_SECRET_KEY`, which preserves existing token hashes but recouples
  the two lifecycles. When adopting `GOGGLES_TOKEN_HASH_KEY` on an existing
  deployment, keep the current `DJANGO_SECRET_KEY` in place until legacy
  tokens have authenticated once and been lazily rekeyed; tokens that miss
  that migration window must be reissued. Treat `GOGGLES_TOKEN_HASH_KEY`
  itself as long-lived: rotating from one dedicated value to another has the
  same token-invalidating effect, so only change it deliberately and issue
  replacement tokens before the cutover.
- Bound a token's lifetime by passing `--expires-in-days N` to
  `create_upload_token`; an expired token is rejected with 401. Tokens never
  expire by default.
- Rotate tokens by creating a new token, updating clients, then disabling the old token in Django admin or with:

```sh
docker compose exec web python manage.py shell -c "from forensics.models import UploadToken; UploadToken.objects.filter(token_prefix='OLDPREFIX').update(is_active=False)"
```

- Audit logs preserve raw engine ids, group refs, message ids, digests, payload metadata, raw lines, raw uploaded text, user agents, and source IPs; protect the database and backups accordingly.
- Brain disk encryption is the expected at-rest protection for v1.
- Upload size defaults to 50 MiB via `GOGGLES_MAX_DUMP_BYTES`.
- Purge stored audit data without removing users or upload tokens with
  `manage.py purge_audit_data`. Run it with `--dry-run` first, then
  `--confirm-delete-audit-data` to perform a deployment cutover. Rebuild the
  normalized projections from the preserved raw lines with
  `manage.py rebuild_audit_projections` if a projection needs to be regenerated.
- Validate JSONL against the committed V2 schema with
  `manage.py validate_audit_schema <path>` (or `just validate-schema <path>`)
  before relying on a third-party export.
- Do not log bearer tokens or raw upload bodies. Keep Caddy access logs away from `Authorization` headers.
- Back up the Postgres named volume with `pg_dump`, store backups encrypted, and test restore before relying on them:

```sh
mkdir -p backups
docker compose exec -T db pg_dump -U goggles goggles > backups/goggles-$(date +%F).sql
cat backups/goggles-YYYY-MM-DD.sql | docker compose exec -T db psql -U goggles goggles
```

## What The Dashboard Shows

- Imported audit files (`/uploads/`), validation status, duplicate counts, and quarantined bad lines.
- A per-group dashboard with tabs for overview, state deltas, network observations, message delivery, convergence, evidence (raw lines), and exports.
- Per-account and per-engine investigations that correlate every group a subject touched, with hover correlation and click-to-inspect event details.
- Message traces across engines, including missing observations when one engine saw a message and another did not.
- Fork resolutions and convergence decisions, including witness-weighted branch selection and the rule traces behind each decision.
- Peeler failures, rejections, invalidated messages, and failed message states.
- Agent-state exports (`groups/<slug>/agent-state.json`, schema `goggles-agent-group-state/v1`) and saved reports that snapshot a group analysis as shareable JSON.

The per-tab JSON these views consume is served under `/api/v1/groups/<slug>/...` and is session-gated by Django authentication (not the bearer-token upload API). The internal read API is documented in `docs/api-v1.md`.
