# Goggles

Internal Marmot audit-log explorer.

Goggles accepts sensitive `marmot-forensics-audit/v1` JSONL audit logs from Dark Matter clients, preserves the exact uploaded text and raw lines, normalizes common forensic columns into PostgreSQL tables, and gives the team a login-gated dashboard for comparing what multiple account-device engines saw and decided inside each group.

## Local Development

The easiest local workflow uses `just` and a durable SQLite database at `var/goggles-dev.sqlite3`:

```sh
uv sync --python /opt/homebrew/bin/python3.13
just reset-db
just dev
```

The seeded development login is:

```text
username: admin
password: pass123
```

Useful commands:

```sh
just dev                 # run the dev server on 127.0.0.1:8000
just seed                # create/update admin/pass123 and load sample audit data
just reset-db            # delete, recreate, migrate, and seed the dev database
just token "ios qa"      # create an upload bearer token in the dev database
just migrate             # apply migrations to the dev database
just makemigrations      # create migrations from model changes
just django-check        # run Django's system checks
just lint                # run Ruff lint checks
just format              # format Python code with Ruff
just format-check        # fail if Python code is not Ruff-formatted
just test-postgres       # run tests against a disposable Postgres service
just check               # run tests, Django checks, Ruff, format check, and migrations
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

Each line must be one JSON object in the new action-aware `marmot-forensics-audit/v1` JSONL shape. A valid row must include either `kind.type = "human_action"` or `context.human_action.action`; old action-less audit rows are quarantined. If the JSONL includes valid `group_ref` values, Goggles will create or reuse those groups automatically. One uploaded file can contain multiple groups, but it should normally contain one `engine_id` and one `account_ref`.

```sh
curl -X POST http://127.0.0.1:8000/api/v1/audit-logs/ \
  -H "Authorization: Bearer $GOGGLES_UPLOAD_TOKEN" \
  -H "Content-Type: application/x-ndjson" \
  -H "X-Goggles-Account-Label: Alice" \
  -H "X-Goggles-Device-Label: Alice iPhone" \
  -H "X-Goggles-Platform: ios" \
  -H "X-Goggles-App-Version: 2026.6.8" \
  --data-binary @fixtures/sample-audit-log-alice.jsonl
```

The source metadata headers are optional labels for humans. The forensic joins still come from the JSONL `account_ref`, `engine_id`, and `group_ref` fields.

The group URL is only a fallback for group-less lines or broken logs. Event-level `group_ref` values take precedence:

```sh
curl -X POST http://127.0.0.1:8000/api/v1/groups/qa-fork/audit-logs/ \
  -H "Authorization: Bearer $GOGGLES_UPLOAD_TOKEN" \
  -F "audit_log=@fixtures/sample-audit-log-alice.jsonl;type=application/x-ndjson"
```

Query parameters also work as the same fallback:

```sh
curl -X POST "http://127.0.0.1:8000/api/v1/audit-logs/?group=qa-fork" \
  -H "Authorization: Bearer $GOGGLES_UPLOAD_TOKEN" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary @fixtures/sample-audit-log-alice.jsonl
```

Upload another one-engine file, such as `fixtures/sample-audit-log-bob.jsonl`, to compare multiple clients in the same group. Invalid JSONL, mixed-engine uploads, or mixed-account uploads return `400` and are still saved as quarantined audit files so damaged lines can be inspected.

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
> `DJANGO_SECRET_KEY` (the historical fallback). Setting a **fresh**
> `GOGGLES_TOKEN_HASH_KEY` on such a deployment immediately invalidates every
> one of those tokens, because `UploadToken.authenticate()` only computes the
> new-key hash and the raw secrets were shown once and never stored. Pick the
> migration path deliberately:
>
> - **Zero-downtime cutover (preserve existing tokens):** set
>   `GOGGLES_TOKEN_HASH_KEY` to the **current** `DJANGO_SECRET_KEY` value. This
>   reproduces the fallback hash exactly, so existing tokens keep working. You
>   can now rotate `DJANGO_SECRET_KEY` freely without breaking uploads. Later,
>   to fully decouple onto a fresh token-hash key, issue replacement tokens and
>   roll clients over **before** changing `GOGGLES_TOKEN_HASH_KEY`, then disable
>   the old tokens.
> - **Clean cutover (reissue everything):** generate a fresh
>   `GOGGLES_TOKEN_HASH_KEY`, accept that all existing tokens break at that
>   moment, and reissue tokens to every client as part of the cutover.
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

The web container runs `collectstatic` into `var/static-assets`. The `static` Compose service serves that directory on `127.0.0.1:8001`, and Caddy proxies `/static/*` to it. Django/Gunicorn handles the application and upload API.

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
  -H "X-Goggles-Account-Label: Alice" \
  -H "X-Goggles-Device-Label: Alice iPhone" \
  -H "X-Goggles-Platform: ios" \
  --data-binary @fixtures/sample-audit-log-alice.jsonl
```

Invalid JSONL is saved as a quarantined upload and returns `400`.

### Operational Safety

- Web UI access uses Django users; there is no public signup.
- Uploads require bearer tokens generated with `create_upload_token`.
- Upload token secrets are shown once and stored only as keyed hashes.
- Upload token hashes are keyed on `GOGGLES_TOKEN_HASH_KEY`, a dedicated
  secret that is **independent of `DJANGO_SECRET_KEY`**. Provision a stable
  `GOGGLES_TOKEN_HASH_KEY` in production so that rotating Django's signing
  key (sessions, CSRF, password reset) does **not** invalidate every issued
  upload token. If `GOGGLES_TOKEN_HASH_KEY` is unset it falls back to
  `DJANGO_SECRET_KEY`, which preserves existing token hashes but recouples
  the two lifecycles — in that case rotating `DJANGO_SECRET_KEY` will
  silently break every upload token, with no migration path because the raw
  secrets were shown once and never stored. Treat `GOGGLES_TOKEN_HASH_KEY`
  itself as long-lived: rotating it has the same token-invalidating effect,
  so only change it deliberately and re-issue tokens afterward. When adopting
  `GOGGLES_TOKEN_HASH_KEY` on an **existing** deployment, follow the migration
  runbook under "Production Deployment" above — setting a fresh key without it
  invalidates every previously issued token at once.
- Rotate tokens by creating a new token, updating clients, then disabling the old token in Django admin or with:

```sh
docker compose exec web python manage.py shell -c "from forensics.models import UploadToken; UploadToken.objects.filter(token_prefix='OLDPREFIX').update(is_active=False)"
```

- Audit logs preserve raw engine ids, group refs, message ids, digests, payload metadata, raw lines, raw uploaded text, user agents, and source IPs; protect the database and backups accordingly.
- Brain disk encryption is the expected at-rest protection for v1.
- Upload size defaults to 50 MiB via `GOGGLES_MAX_DUMP_BYTES`.
- Do not log bearer tokens or raw upload bodies. Keep Caddy access logs away from `Authorization` headers.
- Back up the Postgres named volume with `pg_dump`, store backups encrypted, and test restore before relying on them:

```sh
mkdir -p backups
docker compose exec -T db pg_dump -U goggles goggles > backups/goggles-$(date +%F).sql
cat backups/goggles-YYYY-MM-DD.sql | docker compose exec -T db psql -U goggles goggles
```

## What The Dashboard Shows

- Imported audit files, validation status, duplicate counts, and quarantined bad lines.
- Per-account and per-engine audit timelines with hover correlation and click-to-inspect event details.
- Message traces across engines.
- Missing observations when one engine saw a message and another did not.
- Fork and convergence events.
- Peeler failures, rejections, invalidated messages, and failed message states.
