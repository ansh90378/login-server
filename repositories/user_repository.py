"""Data access for the users table."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from core.config import settings
from models.user import User

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        email: str,
        password_hash: str,
        display_name: str | None = None,
    ) -> User:
        user = User(
            email=email,
            password_hash=password_hash,
            display_name=display_name,
        )
        self._session.add(user)
        await self._session.flush()
        return user

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        stmt = select(User).where(User.id == user_id)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> User | None:
        stmt = select(User).where(User.email == email)
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def update_last_login(self, user: User) -> None:
        user.last_login_at = datetime.now(timezone.utc)
        user.failed_login_attempts = 0
        user.locked_until = None

    async def increment_failed_attempts(self, user: User) -> None:
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.MAX_LOGIN_ATTEMPTS:
            user.locked_until = datetime.now(timezone.utc) + timedelta(
                minutes=settings.LOGIN_LOCKOUT_MINUTES
            )

    async def is_locked(self, user: User) -> bool:
        if user.locked_until is None:
            return False
        if datetime.now(timezone.utc) >= user.locked_until:
            user.locked_until = None
            user.failed_login_attempts = 0
            return False
        return True

    async def set_mfa_secret(self, user: User, secret: str) -> None:
        user.mfa_secret = secret
        user.mfa_enabled = True