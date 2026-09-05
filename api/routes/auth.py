"""Authentication route handlers."""

from __future__ import annotations

import uuid
import hmac
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_session
from core.config import settings
from core.exceptions import InvalidCredentialsException, UserNotFoundException
from core.security import decode_token, get_jwks
from repositories.session_repository import SessionRepository
from repositories.user_repository import UserRepository
from schemas.auth import (
    ErrorResponse,
    ActiveSessionResponse,
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    RefreshRequest,
    RefreshResponse,
    RegisterRequest,
    RegisterResponse,
    UserResponse,
)
from services.auth_service import AuthService

router = APIRouter(prefix="/api/v1", tags=["auth"])


def _get_auth_service(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> AuthService:
    user_repo = UserRepository(session)
    session_repo = SessionRepository()
    return AuthService(user_repo=user_repo, session_repo=session_repo)


@router.post(
    "/register",
    response_model=RegisterResponse,
    responses={409: {"model": ErrorResponse}},
    status_code=201,
)
async def register(
    body: RegisterRequest,
    auth: Annotated[AuthService, Depends(_get_auth_service)],
) -> RegisterResponse:
    result = await auth.register(
        email=body.email,
        password=body.password,
        display_name=body.display_name,
    )
    return RegisterResponse(**result)


@router.post(
    "/login",
    response_model=LoginResponse,
    responses={401: {"model": ErrorResponse}, 423: {"model": ErrorResponse}},
)
async def login(
    body: LoginRequest,
    auth: Annotated[AuthService, Depends(_get_auth_service)],
) -> LoginResponse:
    result = await auth.login(email=body.email, password=body.password)
    return LoginResponse(**result)


@router.post(
    "/refresh",
    response_model=RefreshResponse,
    responses={401: {"model": ErrorResponse}},
)
async def refresh(
    body: RefreshRequest,
    auth: Annotated[AuthService, Depends(_get_auth_service)],
) -> RefreshResponse:
    result = await auth.refresh(refresh_token=body.refresh_token)
    return RefreshResponse(**result)


@router.post("/logout", responses={200: {"description": "Successfully logged out"}})
async def logout(
    body: LogoutRequest,
    auth: Annotated[AuthService, Depends(_get_auth_service)],
) -> dict:
    await auth.logout(refresh_token=body.refresh_token)
    return {"detail": "Successfully logged out"}


@router.get(
    "/me",
    response_model=UserResponse,
    responses={401: {"model": ErrorResponse}},
)
async def get_current_user(
    session: Annotated[AsyncSession, Depends(get_session)],
    authorization: Annotated[str, Header()] = "",
) -> UserResponse:
    """Get the current authenticated user's profile."""
    if not authorization.startswith("Bearer "):
        raise InvalidCredentialsException()

    token = authorization.removeprefix("Bearer ")
    try:
        payload = decode_token(token)
    except Exception:
        raise InvalidCredentialsException()

    user_repo = UserRepository(session)
    import uuid
    user = await user_repo.get_by_id(uuid.UUID(payload["sub"]))
    if not user:
        raise UserNotFoundException()

    return UserResponse(
        id=str(user.id),
        email=user.email,
        display_name=user.display_name,
        mfa_enabled=user.mfa_enabled,
        is_active=user.is_active,
        created_at=user.created_at.isoformat(),
        last_login_at=user.last_login_at.isoformat() if user.last_login_at else None,
    )


@router.get(
    "/admin/active-sessions",
    response_model=list[ActiveSessionResponse],
    responses={403: {"model": ErrorResponse}, 503: {"model": ErrorResponse}},
)
async def get_active_sessions(
    session: Annotated[AsyncSession, Depends(get_session)],
    admin_key: Annotated[str, Header(alias="X-Admin-Key")] = "",
) -> list[ActiveSessionResponse]:
    """List users with a currently active refresh-token session."""
    if not settings.ADMIN_API_KEY:
        raise HTTPException(status_code=503, detail="Admin access is not configured")
    if not hmac.compare_digest(admin_key, settings.ADMIN_API_KEY):
        raise HTTPException(status_code=403, detail="Invalid admin key")

    user_repo = UserRepository(session)
    active_sessions = []
    for stored_session in await SessionRepository.get_active_sessions():
        user = await user_repo.get_by_id(uuid.UUID(stored_session["user_id"]))
        if not user or not user.is_active:
            continue
        active_sessions.append(
            ActiveSessionResponse(
                user_id=str(user.id),
                email=user.email,
                display_name=user.display_name,
                last_login_at=(
                    user.last_login_at.isoformat() if user.last_login_at else None
                ),
                expires_at=stored_session["expires_at"],
            )
        )
    return active_sessions


@router.get("/.well-known/jwks.json")
async def jwks_endpoint() -> dict:
    return get_jwks()