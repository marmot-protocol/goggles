import os
from pathlib import Path

import dj_database_url
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent


def env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def env_list(name: str, default: str) -> list[str]:
    return [item.strip() for item in os.environ.get(name, default).split(",") if item.strip()]


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

GOGGLES_MAX_DUMP_BYTES = int(os.environ.get("GOGGLES_MAX_DUMP_BYTES", 50 * 1024 * 1024))
GOGGLES_UPLOADS_ENABLED = env_bool("GOGGLES_UPLOADS_ENABLED", True)
DATA_UPLOAD_MAX_MEMORY_SIZE = GOGGLES_MAX_DUMP_BYTES
FILE_UPLOAD_MAX_MEMORY_SIZE = GOGGLES_MAX_DUMP_BYTES
# The upload endpoint only ever ingests a single file part, and every part at
# or under FILE_UPLOAD_MAX_MEMORY_SIZE is buffered in RAM. Capping the number
# of files at 1 stops a multipart request from accumulating many sub-threshold
# parts (each passing the per-file size check) into multiple gigabytes of
# resident memory. MaxDumpSizeUploadHandler additionally bounds the cumulative
# bytes across parts as defense in depth.
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
