
"""Password storage for Bayyina's local break-glass accounts. Rules: README.md, "What to build", part 3."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import unicodedata


CURRENT_N = 2**14
CURRENT_R = 8
CURRENT_P = 5
SALT_LENGTH = 16
HASH_LENGTH = 32
MAXMEM = 64 * 1024 * 1024


def _normalise_password(password: str) -> str:
    if not isinstance(password, str):
        raise TypeError("Password must be a string")

    password = unicodedata.normalize("NFKC", password)

    if not 8 <= len(password) <= 128:
        raise ValueError("Password length must be between 8 and 128 characters")

    return password


def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("Invalid Base64 value")

    padded = value + "=" * (-len(value) % 4)
    return base64.b64decode(
        padded.encode("ascii"),
        altchars=b"-_",
        validate=True,
    )


def hash_password(password: str) -> str:
    """Create a scrypt password hash."""
    password = _normalise_password(password)

    salt = secrets.token_bytes(SALT_LENGTH)

    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=CURRENT_N,
        r=CURRENT_R,
        p=CURRENT_P,
        dklen=HASH_LENGTH,
        maxmem=MAXMEM,
    )

    return (
        f"scrypt${CURRENT_N}${CURRENT_R}${CURRENT_P}"
        f"${_b64_encode(salt)}${_b64_encode(derived)}"
    )


def _parse_stored(stored: str):
    if not isinstance(stored, str):
        return None

    try:
        parts = stored.split("$")
        if len(parts) != 6 or parts[0] != "scrypt":
            return None

        n = int(parts[1])
        r = int(parts[2])
        p = int(parts[3])

        if n < 2 or n > 2**20 or (n & (n - 1)) != 0:
            return None

        if not 1 <= r <= 32:
            return None

        if not 1 <= p <= 16:
            return None

        salt = _b64_decode(parts[4])
        expected_hash = _b64_decode(parts[5])

        if len(salt) < SALT_LENGTH:
            return None

        if len(expected_hash) != HASH_LENGTH:
            return None

        return n, r, p, salt, expected_hash

    except (ValueError, TypeError, UnicodeError, OverflowError):
        return None


def verify_password(password: str, stored: str) -> bool:
    """Return True only if the password matches. Never raises."""
    try:
        password = _normalise_password(password)
        parsed = _parse_stored(stored)

        if parsed is None:
            return False

        n, r, p, salt, expected_hash = parsed

        actual_hash = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=HASH_LENGTH,
            maxmem=MAXMEM,
        )

        return hmac.compare_digest(actual_hash, expected_hash)

    except Exception:
        return False


def needs_rehash(stored: str) -> bool:
    """Return True if the stored hash is malformed or uses weaker parameters."""
    parsed = _parse_stored(stored)

    if parsed is None:
        return True

    n, r, p, _, _ = parsed

    return (
        n < CURRENT_N
        or r < CURRENT_R
        or p < CURRENT_P
    )
