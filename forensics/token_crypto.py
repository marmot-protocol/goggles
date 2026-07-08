"""Shared secret-token crypto for the app's bearer-token models.

Single-sources the security-critical mechanics — HMAC-SHA256 hashing keyed on a
dedicated, rotatable secret, constant-time verification, one-way lazy rekeying of
legacy ``SECRET_KEY``-derived hashes, and expiry enforcement — so that
``UploadToken`` and ``PersonalAccessToken`` cannot drift apart on how a credential
is minted or checked.

Raw token format: ``<type_prefix>_<lookup_prefix>_<secret>``. The type prefix
(``goggles`` for uploads, ``gpat`` for personal access tokens) makes the two
credential families structurally un-confusable: :func:`authenticate` rejects a raw
token whose type prefix is not the caller's own.

Duck-typed token protocol (both models satisfy it): a ``token_prefix`` /
``token_hash`` / ``is_active`` / ``expires_at`` field set, an ``objects`` manager,
and an ``is_expired()`` method. Model-specific checks (e.g. "owner is active") are
layered by the caller on the returned row, keeping this module model-agnostic.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta

from django.conf import settings
from django.utils import timezone

# A sanity ceiling on token lifetime (~100 years). It rejects absurd input and keeps
# ``now() + timedelta(days=...)`` well clear of the OverflowError that extreme day
# counts would otherwise raise.
MAX_TOKEN_EXPIRY_DAYS = 36500


def generate_raw_token(type_prefix: str) -> tuple[str, str, str]:
    """Mint a fresh credential, returning ``(raw_token, lookup_prefix, secret)``.

    Only the hash of ``secret`` is ever persisted; the raw token is shown once to
    the caller and never stored.
    """
    # 8 bytes → 16 hex chars, filling the token_prefix max_length=16. 64 bits keeps an
    # accidental collision on the unique lookup key negligible; issuance does not retry.
    lookup_prefix = secrets.token_hex(8)
    secret = secrets.token_urlsafe(32)
    raw_token = f"{type_prefix}_{lookup_prefix}_{secret}"
    return raw_token, lookup_prefix, secret


def hash_secret(secret: str, *, key: str | None = None) -> str:
    # Keyed on GOGGLES_TOKEN_HASH_KEY (a dedicated, independently rotatable
    # secret) rather than SECRET_KEY, so rotating the Django signing key does not
    # invalidate every issued token. The setting falls back to SECRET_KEY when
    # unset, preserving existing hashes for deployments that have not provisioned
    # a dedicated key.
    hash_key = key or settings.GOGGLES_TOKEN_HASH_KEY
    return hmac.new(hash_key.encode("utf-8"), secret.encode("utf-8"), hashlib.sha256).hexdigest()


def legacy_hash_keys() -> tuple[str, ...]:
    """Return fallback keys for one-way lazy migration of legacy hashes.

    Before GOGGLES_TOKEN_HASH_KEY existed, token hashes were keyed on SECRET_KEY.
    During the first dedicated-key cutover, an active token can be authenticated
    against that legacy hash and then rekeyed to the dedicated setting.
    """
    if settings.SECRET_KEY and settings.SECRET_KEY != settings.GOGGLES_TOKEN_HASH_KEY:
        return (settings.SECRET_KEY,)
    return ()


def is_expired(token, *, at: datetime | None = None) -> bool:
    if token.expires_at is None:
        return False
    return (at or timezone.now()) >= token.expires_at


def expiry_from_days(days: int) -> datetime:
    """Return a bounded expiry datetime for a positive day count.

    Rejects non-positive and absurdly large values with ``ValueError`` *before* any
    ``timedelta`` arithmetic, so a crafted day count is a clean rejection rather than
    an ``OverflowError`` from ``timedelta`` / ``datetime`` overflow.
    """
    if days <= 0:
        raise ValueError("Token expiry must be a positive number of days.")
    if days > MAX_TOKEN_EXPIRY_DAYS:
        raise ValueError(f"Token expiry must be at most {MAX_TOKEN_EXPIRY_DAYS} days.")
    return timezone.now() + timedelta(days=days)


def authenticate(model, raw_token: str | None, type_prefix: str):
    """Return the active, unexpired ``model`` row matching ``raw_token``, or None.

    Validates the type prefix, looks the token up by its lookup prefix, verifies
    the secret in constant time (with legacy-key fallback and lazy rekey to the
    dedicated key), and enforces expiry. Callers layer any model-specific checks
    on the result.
    """
    if not raw_token:
        return None
    parts = raw_token.split("_", 2)
    if len(parts) != 3 or parts[0] != type_prefix:
        return None
    _, lookup_prefix, secret = parts
    try:
        token = model.objects.get(token_prefix=lookup_prefix, is_active=True)
    except model.DoesNotExist:
        return None

    current_hash = hash_secret(secret)
    matched_legacy_key = False
    if not hmac.compare_digest(token.token_hash, current_hash):
        for legacy_key in legacy_hash_keys():
            legacy = hash_secret(secret, key=legacy_key)
            if hmac.compare_digest(token.token_hash, legacy):
                matched_legacy_key = True
                break
        else:
            return None

    if is_expired(token):
        return None

    if matched_legacy_key:
        token.token_hash = current_hash
        token.save(update_fields=["token_hash"])

    return token
