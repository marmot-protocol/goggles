set dotenv-load := true

# Local development runs in Django debug mode by default. The app now fails closed
# (DEBUG=False) when DJANGO_DEBUG is unset, so opt in here for the SQLite/dev-secret
# local workflow. An explicit DJANGO_DEBUG in the environment or .env still wins.
export DJANGO_DEBUG := env_var_or_default("DJANGO_DEBUG", "1")

dev_db := env_var_or_default("GOGGLES_DEV_DB", "var/goggles-dev.sqlite3")
database_url := "sqlite:///" + justfile_directory() + "/" + dev_db
port := env_var_or_default("GOGGLES_DEV_PORT", "8000")
test_db_port := env_var_or_default("GOGGLES_TEST_DB_PORT", "55432")
test_database_url := env_var_or_default("GOGGLES_TEST_DATABASE_URL", "postgres://goggles:goggles@127.0.0.1:" + test_db_port + "/goggles_test")
python := "uv run python"

alias run := dev
alias reset := reset-db

# Show available commands.
default:
    @just --list

# Install or update local Python dependencies.
sync:
    uv sync

# Install locked dependencies exactly as GitHub Actions does.
sync-frozen:
    uv sync --frozen

# Apply migrations to the durable local development database.
migrate: _dev-db-dir
    DATABASE_URL='{{database_url}}' {{python}} manage.py migrate

# Create Django migrations from model changes.
makemigrations:
    {{python}} manage.py makemigrations

# Fail if model changes need migrations.
check-migrations:
    {{python}} manage.py makemigrations --check --dry-run

# Run Django's system checks.
django-check:
    {{python}} manage.py check

# Seed admin/pass123 and sample audit-log data into the dev database.
seed: migrate
    DATABASE_URL='{{database_url}}' {{python}} manage.py seed_dev

# Delete, recreate, migrate, and seed the durable local development database.
reset-db: _dev-db-dir
    rm -f '{{justfile_directory()}}/{{dev_db}}' '{{justfile_directory()}}/{{dev_db}}-shm' '{{justfile_directory()}}/{{dev_db}}-wal'
    DATABASE_URL='{{database_url}}' {{python}} manage.py migrate
    DATABASE_URL='{{database_url}}' {{python}} manage.py seed_dev

# Run the Django dev server against the durable local development database.
dev: migrate
    @echo 'Goggles dev: http://127.0.0.1:{{port}}'
    @echo 'Seeded login: admin / pass123'
    DATABASE_URL='{{database_url}}' {{python}} manage.py runserver 127.0.0.1:{{port}}

# Create a reusable upload bearer token in the durable local development
# database. Pass extra flags through, e.g. `just token "ios qa" --expires-in-days 30`.
token name *args: migrate
    DATABASE_URL='{{database_url}}' {{python}} manage.py create_upload_token "{{name}}" {{args}}

# Delete audit uploads, events, groups, projections, and saved reports while
# preserving users and upload tokens. Pass `--dry-run` first, then
# `--confirm-delete-audit-data` when performing the deployment cutover.
purge-audit-data *args: migrate
    DATABASE_URL='{{database_url}}' {{python}} manage.py purge_audit_data {{args}}

# Open a Django shell against the durable local development database.
shell: migrate
    DATABASE_URL='{{database_url}}' {{python}} manage.py shell

# Validate JSONL audit events against committed V2/V3 schemas by row version.
validate-schema *paths:
    {{python}} manage.py validate_audit_schema {{paths}}

# Run the Django test suite.
test:
    {{python}} manage.py test

# Run the Django test suite against a disposable Postgres service.
test-postgres:
    #!/usr/bin/env bash
    set -euo pipefail
    GOGGLES_ENV_FILE='.env.example' GOGGLES_TEST_DB_PORT='{{test_db_port}}' docker compose up -d --wait db-test
    trap "GOGGLES_ENV_FILE='.env.example' GOGGLES_TEST_DB_PORT='{{test_db_port}}' docker compose rm -sf db-test >/dev/null" EXIT
    DATABASE_URL='{{test_database_url}}' {{python}} manage.py test

# Run Ruff checks.
lint:
    uv run ruff check .

# Audit the locked dependency set.
audit-dependencies:
    #!/usr/bin/env bash
    set -euo pipefail
    requirements_file="$(mktemp)"
    trap 'rm -f "$requirements_file"' EXIT
    uv export --locked --all-groups --format requirements-txt -o "$requirements_file"
    uv run --with pip-audit==2.10.1 pip-audit \
      -r "$requirements_file" \
      --strict \
      --require-hashes \
      --disable-pip \
      --progress-spinner off

# Format Python code with Ruff.
format:
    uv run ruff format .

# Fail if Python code is not formatted with Ruff.
format-check:
    uv run ruff format --check .

# Run the normal local verification suite.
check: test django-check lint format-check check-migrations

# Run the same push/PR checks as GitHub Actions.
ci: sync-frozen test test-postgres django-check lint format-check check-migrations audit-dependencies

_dev-db-dir:
    @mkdir -p "$(dirname '{{justfile_directory()}}/{{dev_db}}')"
