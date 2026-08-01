"""Business logic for authentication."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from core.config import settings
from core.exceptions import (
    AccountLockedException,
    InvalidCredentialsException,
    UserAlreadyExistsException,
)
from core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    validate_password_policy,
    verify_password,
)
from repositories.session_repository import SessionRepository
from repositories.user_repository import UserRepository


class AuthService:
    def __init__(
        self,
        user_repo: UserRepository,
        session_repo: SessionRepository,
    ) -> None:
        self._user_repo = user_repo
        self._session_repo = session_repo

    async def register(
        self,
        email: str,
        password: str,
        display_name: str | None = None,
    ) -> dict:
        # Validate password policy
        valid, msg = validate_password_policy(password)
        if not valid:
            raise InvalidCredentialsException(msg)

        # Check uniqueness
        existing = await self._user_repo.get_by_email(email)
        if existing:
            raise UserAlreadyExistsException()

        # Create user
        pw_hash = hash_password(password)
        user = await self._user_repo.create(
            email=email,
            password_hash=pw_hash,
            display_name=display_name,
        )
        return {"user_id": str(user.id), "email": user.email}

    async def login(self, email: str, password: str) -> dict:
        user = await self._user_repo.get_by_email(email)
        if not user:
            raise InvalidCredentialsException()

        # Check lockout
        if await self._user_repo.is_locked(user):
            raise AccountLockedException()

        # Verify password
        if not verify_password(password, user.password_hash):
            await self._user_repo.increment_failed_attempts(user)
            raise InvalidCredentialsException()

        # Success
        await self._user_repo.update_last_login(user)

        access_token = create_access_token(
            subject=str(user.id),
            email=user.email,
            role="user",
        )
        refresh_jti = uuid.uuid4().hex
        refresh_token = create_refresh_token(subject=str(user.id))

        # Decode to get the jti
        decoded = decode_token(refresh_token)
        await self._session_repo.store_refresh_token(
            jti=decoded["jti"],
            user_id=str(user.id),
            family_id=refresh_jti,
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_TTL,
        }

    async def refresh(self, refresh_token: str) -> dict:
        try:
            payload = decode_token(refresh_token)
        except Exception:
            raise InvalidCredentialsException("Invalid or expired refresh token")

        if payload.get("type") != "refresh":
            raise InvalidCredentialsException("Token is not a refresh token")

        jti = payload["jti"]
        if await self._session_repo.is_blacklisted(jti):
            raise InvalidCredentialsException("Token has been revoked")

        # Check global not-before
        not_before = await self._session_repo.get_global_not_before()
        if not_before and payload["iat"] < not_before:
            raise InvalidCredentialsException("Token issued before global revocation")

        stored = await self._session_repo.get_refresh_token(jti)
        if not stored:
            raise InvalidCredentialsException("Refresh token not found")

        # Rotate: delete old, create new
        await self._session_repo.delete_refresh_token(jti)

        new_access = create_access_token(
            subject=payload["sub"],
            email=payload.get("email", ""),
            role=payload.get("role", "user"),
        )
        new_refresh_jti = uuid.uuid4().hex
        new_refresh = create_refresh_token(subject=payload["sub"])
        decoded_new = decode_token(new_refresh)

        await self._session_repo.store_refresh_token(
            jti=decoded_new["jti"],
            user_id=payload["sub"],
            family_id=new_refresh_jti,
        )

        return {
            "access_token": new_access,
            "refresh_token": new_refresh,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_TTL,
        }

    async def logout(self, refresh_token: str) -> None:
        try:
            payload = decode_token(refresh_token)
        except Exception:
            return  # Silently accept invalid tokens on logout

        jti = payload["jti"]
        await self._session_repo.delete_refresh_token(jti)
        await self._session_repo.blacklist_refresh_token(
            jti=jti,
            original_ttl=settings.REFRESH_TOKEN_TTL,
        )