"""Tests for core/security.py."""

from __future__ import annotations

import jwt
import pytest

from core.config import settings
from core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    validate_password_policy,
    verify_password,
)


class TestPasswordHashing:
    def test_hash_and_verify(self) -> None:
        pw = "MySecurePass1"
        hashed = hash_password(pw)
        assert hashed != pw
        assert verify_password(pw, hashed) is True
        assert verify_password("WrongPass1", hashed) is False

    def test_same_password_different_hashes(self) -> None:
        pw = "SamePass1"
        h1 = hash_password(pw)
        h2 = hash_password(pw)
        assert h1 != h2  # bcrypt salting


class TestPasswordPolicy:
    def test_valid_password(self) -> None:
        valid, msg = validate_password_policy("StrongPass1")
        assert valid is True
        assert msg == ""

    def test_too_short(self) -> None:
        valid, msg = validate_password_policy("Sh0rt")
        assert valid is False
        assert "8 characters" in msg

    def test_no_uppercase(self) -> None:
        valid, msg = validate_password_policy("lowercase1")
        assert valid is False
        assert "uppercase" in msg

    def test_no_lowercase(self) -> None:
        valid, msg = validate_password_policy("UPPERCASE1")
        assert valid is False
        assert "lowercase" in msg

    def test_no_digit(self) -> None:
        valid, msg = validate_password_policy("NoDigits!")
        assert valid is False
        assert "digit" in msg


class TestJWT:
    def test_create_and_decode_access_token(self) -> None:
        token = create_access_token(
            subject="user-123",
            email="alice@test.com",
            role="admin",
        )
        payload = decode_token(token)
        assert payload["sub"] == "user-123"
        assert payload["email"] == "alice@test.com"
        assert payload["role"] == "admin"
        assert payload["jti"] is not None
        assert payload["exp"] > payload["iat"]

    def test_create_and_decode_refresh_token(self) -> None:
        token = create_refresh_token(subject="user-123")
        payload = decode_token(token)
        assert payload["sub"] == "user-123"
        assert payload["type"] == "refresh"
        assert payload["jti"] is not None

    def test_expired_token_raises(self) -> None:
        import time

        from core.security import create_access_token

        token = create_access_token(
            subject="user-123",
            email="x@y.com",
            extra_claims={"exp": int(time.time()) - 10},
        )
        with pytest.raises(jwt.ExpiredSignatureError):
            decode_token(token)

    def test_invalid_signature_raises(self) -> None:
        # Tamper with the token
        token = create_access_token(subject="u1", email="a@b.com")
        parts = token.split(".")
        tampered = parts[0] + "." + parts[1] + ".invalidsig"
        with pytest.raises(jwt.InvalidSignatureError):
            decode_token(tampered)

    def test_access_and_refresh_have_different_expiry(self) -> None:
        access = create_access_token(subject="u1", email="a@b.com")
        refresh = create_refresh_token(subject="u1")
        access_payload = decode_token(access)
        refresh_payload = decode_token(refresh)
        refresh_ttl = refresh_payload["exp"] - refresh_payload["iat"]
        access_ttl = access_payload["exp"] - access_payload["iat"]
        assert refresh_ttl > access_ttl