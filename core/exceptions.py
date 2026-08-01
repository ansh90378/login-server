"""Custom exception classes mapped to HTTP error responses."""

from __future__ import annotations

from fastapi import HTTPException, status


class AppException(HTTPException):
    """Base application exception."""

    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    detail = "Internal server error"

    def __init__(self, detail: str | None = None) -> None:
        super().__init__(
            status_code=self.status_code,
            detail=detail or self.detail,
        )


class CredentialsException(AppException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Could not validate credentials"


class InvalidCredentialsException(AppException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Invalid email or password"


class TokenExpiredException(AppException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Token has expired"


class UserAlreadyExistsException(AppException):
    status_code = status.HTTP_409_CONFLICT
    detail = "A user with this email already exists"


class UserNotFoundException(AppException):
    status_code = status.HTTP_404_NOT_FOUND
    detail = "User not found"


class AccountLockedException(AppException):
    status_code = status.HTTP_423_LOCKED
    detail = "Account is temporarily locked due to too many failed attempts"


class RateLimitExceededException(AppException):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    detail = "Rate limit exceeded"


class MFARequiredException(AppException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "MFA verification required"


class InvalidMFACodeException(AppException):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Invalid MFA code"