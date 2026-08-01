"""Auth-related Pydantic schemas."""

from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    display_name: str | None = None


class RegisterResponse(BaseModel):
    user_id: str
    email: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


class RefreshResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class LogoutRequest(BaseModel):
    refresh_token: str


class TokenData(BaseModel):
    sub: str
    email: str
    role: str
    jti: str
    exp: int
    iat: int


class MfaSetupResponse(BaseModel):
    secret: str
    qr_code_url: str


class MfaVerifyRequest(BaseModel):
    code: str


class MfaVerifyResponse(BaseModel):
    verified: bool


class UserResponse(BaseModel):
    id: str
    email: str
    display_name: str | None
    mfa_enabled: bool
    is_active: bool
    created_at: str
    last_login_at: str | None


class ErrorResponse(BaseModel):
    detail: str