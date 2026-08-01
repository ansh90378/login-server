"""Security utilities: password hashing, JWT signing/verification."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt

from core.config import settings

# ── Password hashing ──────────────────────────────────────────────────────


def hash_password(password: str) -> str:
    """Return a bcrypt hash of *password*."""
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=settings.BCRYPT_ROUNDS),
    ).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Return ``True`` if *plain* matches *hashed*."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def validate_password_policy(password: str) -> tuple[bool, str]:
    """Check password against the configured policy.

    Returns ``(is_valid, error_message)``.
    """
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit."
    return True, ""


# ── JWT ──────────────────────────────────────────────────────────────────


def _get_private_key() -> str:
    key = settings.jwt_private_key
    if not key:
        msg = "JWT_PRIVATE_KEY is not configured"
        raise RuntimeError(msg)
    return key


def _get_public_key() -> str:
    key = settings.jwt_public_key
    if not key:
        msg = "JWT_PUBLIC_KEY is not configured"
        raise RuntimeError(msg)
    return key


def create_access_token(
    subject: str,
    email: str,
    role: str = "user",
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """Issue a short-lived access token (JWT)."""
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "email": email,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=settings.ACCESS_TOKEN_TTL)).timestamp()),
        "jti": uuid.uuid4().hex,
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(
        payload,
        _get_private_key(),
        algorithm=settings.JWT_ALGORITHM,
        headers={"kid": settings.JWT_KEY_ID},
    )


def create_refresh_token(subject: str) -> str:
    """Issue a long-lived refresh token."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=settings.REFRESH_TOKEN_TTL)).timestamp()),
        "jti": uuid.uuid4().hex,
        "type": "refresh",
    }
    return jwt.encode(
        payload,
        _get_private_key(),
        algorithm=settings.JWT_ALGORITHM,
        headers={"kid": settings.JWT_KEY_ID},
    )


def decode_token(token: str) -> dict[str, Any]:
    """Decode and verify a JWT.

    Raises ``jwt.PyJWTError`` on invalid/expired tokens.
    """
    return jwt.decode(
        token,
        _get_public_key(),
        algorithms=[settings.JWT_ALGORITHM],
    )


def get_jwks() -> dict[str, Any]:
    """Return a JWKS-compatible key set for the public key."""
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    pub_key = _get_public_key().encode("utf-8")
    key = serialization.load_pem_public_key(pub_key)
    if not isinstance(key, rsa.RSAPublicKey):
        msg = "Only RSA public keys are supported for JWKS"
        raise TypeError(msg)

    numbers = key.public_numbers()

    def _int_to_base64url(n: int) -> str:
        return base64.urlsafe_b64encode(
            n.to_bytes((n.bit_length() + 7) // 8, "big")
        ).rstrip(b"=").decode()

    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": settings.JWT_KEY_ID,
                "alg": settings.JWT_ALGORITHM,
                "use": "sig",
                "n": _int_to_base64url(numbers.n),
                "e": _int_to_base64url(numbers.e),
            }
        ]
    }