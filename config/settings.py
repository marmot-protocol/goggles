import os
from pathlib import Path

import dj_database_url
from django.core.exceptions import ImproperlyConfigured
from django.utils.csp import CSP

BASE_DIR = Path(__file__).resolve().parent.parent


def env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def env_list(name: str, default: str) -> list[str]:
    return [item.strip() for item in os.environ.get(name, default).split(",") if item.strip()]


def env_float(name: str, default: float) -> float:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError as exc:
        raise ImproperlyConfigured(f"{name} must be a floating point number.") from exc


SENSITIVE_EVENT_KEYS = {
    "authorization",
    "cookie",
    "cookies",
    "data",
    "engine_id",
    "group",
    "group_ref",
    "http_authorization",
    "ip_address",
    "message_id",
    "msg_id",
    "payload",
    "payload_digest",
    "query_string",
    "raw",
    "raw_body",
    "raw_line",
    "raw_text",
    "remote_addr",
    "request_body",
    "source_ip",
    "token",
    "upload",
    "upload_token",
    "user-agent",
    "user_agent",
    "x-forwarded-for",
    "x-goggles-account-label",
    "x-goggles-app-version",
    "x-goggles-device-label",
    "x-goggles-group",
    "x-goggles-platform",
    "x-real-ip",
}
SENSITIVE_EVENT_KEY_PARTS = (
    "account_ref",
    "audit",
    "authorization",
    "bearer",
    "body",
    "digest",
    "engine_id",
    "group_ref",
    "message_id",
    "msg_id",
    "payload",
    "raw",
    "secret",
    "token",
)
SCRUBBED_VALUE = "[Filtered]"


def _scrub_glitchtip_value(value):
    if isinstance(value, dict):
        scrubbed = {}
        for key, child in value.items():
            normalized = str(key).lower().replace("_", "-")
            normalized_with_underscores = normalized.replace("-", "_")
            if (
                normalized in SENSITIVE_EVENT_KEYS
                or normalized_with_underscores in SENSITIVE_EVENT_KEYS
                or any(part in normalized_with_underscores for part in SENSITIVE_EVENT_KEY_PARTS)
            ):
                scrubbed[key] = SCRUBBED_VALUE
            else:
                scrubbed[key] = _scrub_glitchtip_value(child)
        return scrubbed
    if isinstance(value, list):
        return [_scrub_glitchtip_value(child) for child in value]
    return value


def scrub_glitchtip_event(event, _hint):
    event = _scrub_glitchtip_value(event)
    request = event.get("request")
    if isinstance(request, dict):
        request.pop("data", None)
        request.pop("cookies", None)
        request.pop("query_string", None)
        request.pop("env", None)
        headers = request.get("headers")
        if isinstance(headers, dict):
            for key in list(headers):
                normalized = str(key).lower()
                if normalized in SENSITIVE_EVENT_KEYS or normalized.startswith("x-goggles-"):
                    headers[key] = SCRUBBED_VALUE
    user = event.get("user")
    if isinstance(user, dict):
        user.pop("ip_address", None)
    return event


# Fail closed: an absent DJANGO_DEBUG must default to production-safe (DEBUG=False)
# so a missing/commented-out env var does not silently boot the app in debug mode
# with the dev SECRET_KEY and SQLite fallback. Operators must opt in to debug mode
# explicitly (DJANGO_DEBUG=1); the local `just` workflow and CI set it for development.
DEBUG = env_bool("DJANGO_DEBUG", False)
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-only-change-me")
if not DEBUG and (not SECRET_KEY or SECRET_KEY == "dev-only-change-me"):
    raise ImproperlyConfigured("DJANGO_SECRET_KEY must be set when DJANGO_DEBUG=0.")

# Key used to HMAC upload-token secrets. This is intentionally decoupled
# from the Django signing key: rotating that key (sessions, CSRF, password
# reset) must not silently invalidate every previously issued upload token.
# Set GOGGLES_TOKEN_HASH_KEY to a dedicated, stable secret in production so
# the two rotation lifecycles stay independent. When it is unset we fall back
# to the Django signing key, which preserves historical behavior and keeps
# existing token hashes verifiable for deployments that have not yet
# provisioned a dedicated key.
GOGGLES_TOKEN_HASH_KEY = os.environ.get("GOGGLES_TOKEN_HASH_KEY") or SECRET_KEY

ALLOWED_HOSTS = env_list(
    "DJANGO_ALLOWED_HOSTS",
    "127.0.0.1,localhost" if DEBUG else "",
)
if not DEBUG and (not ALLOWED_HOSTS or "*" in ALLOWED_HOSTS):
    raise ImproperlyConfigured("DJANGO_ALLOWED_HOSTS must be tightly set when DJANGO_DEBUG=0.")

CSRF_TRUSTED_ORIGINS = env_list("DJANGO_CSRF_TRUSTED_ORIGINS", "")
if not DEBUG and not CSRF_TRUSTED_ORIGINS:
    raise ImproperlyConfigured(
        "DJANGO_CSRF_TRUSTED_ORIGINS must include the public HTTPS origin when DJANGO_DEBUG=0."
    )

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.humanize",
    "forensics",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

GLITCHTIP_DSN = os.environ.get("GLITCHTIP_DSN", "")
GLITCHTIP_SECURITY_ENDPOINT = os.environ.get("GLITCHTIP_SECURITY_ENDPOINT", "")
GLITCHTIP_ENVIRONMENT = os.environ.get(
    "GLITCHTIP_ENVIRONMENT",
    "development" if DEBUG else "production",
)
GLITCHTIP_RELEASE = os.environ.get("GLITCHTIP_RELEASE", "")
GLITCHTIP_TRACES_SAMPLE_RATE = env_float("GLITCHTIP_TRACES_SAMPLE_RATE", 0.05)

if GLITCHTIP_SECURITY_ENDPOINT:
    MIDDLEWARE.insert(1, "django.middleware.csp.ContentSecurityPolicyMiddleware")
    SECURE_CSP_REPORT_ONLY = {
        "default-src": [CSP.SELF],
        "script-src": [CSP.SELF, CSP.UNSAFE_INLINE],
        "style-src": [CSP.SELF, CSP.UNSAFE_INLINE],
        "img-src": [CSP.SELF, "data:"],
        "font-src": [CSP.SELF],
        "connect-src": [CSP.SELF, "https://glitch.ipf.dev"],
        "object-src": [CSP.NONE],
        "frame-ancestors": [CSP.NONE],
        "base-uri": [CSP.SELF],
        "form-action": [CSP.SELF],
        "report-uri": [GLITCHTIP_SECURITY_ENDPOINT],
    }

if GLITCHTIP_DSN:
    import sentry_sdk

    sentry_sdk.init(
        dsn=GLITCHTIP_DSN,
        traces_sample_rate=GLITCHTIP_TRACES_SAMPLE_RATE,
        auto_session_tracking=False,
        send_default_pii=False,
        max_request_body_size="never",
        include_local_variables=False,
        environment=GLITCHTIP_ENVIRONMENT,
        release=GLITCHTIP_RELEASE or None,
        before_send=scrub_glitchtip_event,
    )

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DEBUG and not DATABASE_URL:
    raise ImproperlyConfigured("DATABASE_URL must be set to Postgres when DJANGO_DEBUG=0.")

DATABASES = {
    "default": dj_database_url.config(
        default=DATABASE_URL or f"sqlite:///{BASE_DIR / 'db.sqlite3'}",
        conn_max_age=60,
    )
}
if not DEBUG and DATABASES["default"]["ENGINE"] == "django.db.backends.sqlite3":
    raise ImproperlyConfigured("Production DATABASE_URL must not use SQLite.")
# Transaction-pooling connection poolers (e.g. PgBouncer) are incompatible with
# Postgres server-side cursors, which the streaming export relies on. Set this behind
# such a pooler; streaming reads then fall back to client-side chunked fetches, still
# bounded by the query chunk_size. See docs/deployment.md.
if env_bool("GOGGLES_DISABLE_SERVER_SIDE_CURSORS", False):
    DATABASES["default"]["DISABLE_SERVER_SIDE_CURSORS"] = True

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "group-list"
LOGOUT_REDIRECT_URL = "login"

# Upload ceiling. Marmot clients refuse to upload a segment larger than 64 MiB,
# so the server accepts exactly that: anything lower leaves a band of files the
# client will re-post forever and the server never sees. The edge proxy's body
# limit must sit *above* this value (see deploy/Caddyfile.goggles.ipf.dev) so the
# 413 is decided -- and recorded as an UploadRejection -- here, not at the edge.
GOGGLES_MAX_DUMP_BYTES = int(os.environ.get("GOGGLES_MAX_DUMP_BYTES", 64 * 1024 * 1024))
# Record cap sized so it is not the binding limit for a legitimate 64 MiB log
# (real audit lines run ~0.7-1 KiB) while still bounding per-line object
# expansion for pathological tiny-line bodies.
GOGGLES_MAX_DUMP_RECORDS = int(os.environ.get("GOGGLES_MAX_DUMP_RECORDS", 100_000))
GOGGLES_MAX_JSONL_LINE_BYTES = int(os.environ.get("GOGGLES_MAX_JSONL_LINE_BYTES", 2 * 1024 * 1024))
GOGGLES_MAX_ACTION_EVENTS_PER_REQUEST = int(
    os.environ.get("GOGGLES_MAX_ACTION_EVENTS_PER_REQUEST", 50_000)
)
GOGGLES_AGENT_EXPORT_MAX_EVENTS = int(os.environ.get("GOGGLES_AGENT_EXPORT_MAX_EVENTS", 50_000))
GOGGLES_UPLOADS_ENABLED = env_bool("GOGGLES_UPLOADS_ENABLED", True)
# How long raw audit evidence (uploaded files and their events) is kept. The
# prune_audit_data management command — run by the web container at startup —
# deletes evidence older than this window and rebuilds the affected groups'
# projections. Set to a large positive value to lengthen retention.
GOGGLES_AUDIT_RETENTION_DAYS = int(os.environ.get("GOGGLES_AUDIT_RETENTION_DAYS", 14))
# Operational kill-switch for the streaming group-export endpoint, mirroring the
# upload toggle. Lets an operator shed a resource-intensive read surface without a
# redeploy.
GOGGLES_EXPORTS_ENABLED = env_bool("GOGGLES_EXPORTS_ENABLED", True)
DATA_UPLOAD_MAX_MEMORY_SIZE = GOGGLES_MAX_DUMP_BYTES
FILE_UPLOAD_MAX_MEMORY_SIZE = min(
    GOGGLES_MAX_DUMP_BYTES,
    int(os.environ.get("GOGGLES_FILE_UPLOAD_MEMORY_BYTES", 1024 * 1024)),
)
for setting_name in (
    "GOGGLES_MAX_DUMP_BYTES",
    "GOGGLES_MAX_DUMP_RECORDS",
    "GOGGLES_MAX_JSONL_LINE_BYTES",
    "GOGGLES_MAX_ACTION_EVENTS_PER_REQUEST",
    "GOGGLES_AGENT_EXPORT_MAX_EVENTS",
    "GOGGLES_AUDIT_RETENTION_DAYS",
    "FILE_UPLOAD_MAX_MEMORY_SIZE",
):
    if globals()[setting_name] <= 0:
        raise ImproperlyConfigured(f"{setting_name} must be a positive integer.")
# The upload endpoint only ever ingests a single file part, and every part at
# or under FILE_UPLOAD_MAX_MEMORY_SIZE is buffered in RAM. Keep that threshold
# much smaller than the accepted dump size so normal multipart uploads spool to
# a temporary file before ingestion. Capping the number of files at 1 stops a
# multipart request from accumulating many sub-threshold parts, while
# MaxDumpSizeUploadHandler additionally bounds cumulative bytes across parts.
DATA_UPLOAD_MAX_NUMBER_FILES = 1

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = env_bool("DJANGO_SECURE_SSL_REDIRECT", False)
SESSION_COOKIE_SECURE = env_bool("DJANGO_SESSION_COOKIE_SECURE", not DEBUG)
CSRF_COOKIE_SECURE = env_bool("DJANGO_CSRF_COOKIE_SECURE", not DEBUG)
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = False
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_SECONDS = int(os.environ.get("DJANGO_SECURE_HSTS_SECONDS", 0 if DEBUG else 31536000))
SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool("DJANGO_SECURE_HSTS_INCLUDE_SUBDOMAINS", False)
SECURE_HSTS_PRELOAD = env_bool("DJANGO_SECURE_HSTS_PRELOAD", False)
X_FRAME_OPTIONS = "DENY"
