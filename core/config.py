"""Application configuration via environment variables."""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


def _read_pem(path: str | None) -> str:
    """Read a PEM file from disk, falling back to the path itself."""
    if not path:
        return ""
    p = Path(path)
    if p.is_file():
        return p.read_text(encoding="utf-8").strip()
    return path  # treat it as the raw key


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Local demo shortcuts ─────────────────────────────────────────────
    # When USE_SQLITE=true the database URL is ignored and an in-memory
    # (file-backed) SQLite database is used instead — no PostgreSQL needed.
    USE_SQLITE: bool = False
    # When DISABLE_REDIS=true the session/blacklist store is backed by an
    # in-process dict and no Redis server is required. Refresh-token
    # rotation still works but does not survive a process restart.
    DISABLE_REDIS: bool = False

    # ── Database ──────────────────────────────────────────────────────────
    DATABASE_URL: str = (
        "postgresql+asyncpg://postgres:postgres@localhost:5432/login_db"
    )

    # ── Redis ─────────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── JWT ───────────────────────────────────────────────────────────────
    JWT_PRIVATE_KEY: str = ""
    JWT_PRIVATE_KEY_PATH: str = "private.pem"
    JWT_PUBLIC_KEY: str = ""
    JWT_PUBLIC_KEY_PATH: str = "public.pem"
    ACCESS_TOKEN_TTL: int = 900  # 15 minutes
    REFRESH_TOKEN_TTL: int = 604800  # 7 days
    JWT_ALGORITHM: str = "RS256"
    JWT_KEY_ID: str = "2026-07-key-1"

    @property
    def jwt_private_key(self) -> str:
        return self.JWT_PRIVATE_KEY or _read_pem(self.JWT_PRIVATE_KEY_PATH)

    @property
    def jwt_public_key(self) -> str:
        return self.JWT_PUBLIC_KEY or _read_pem(self.JWT_PUBLIC_KEY_PATH)

    # ── Rate Limiting ─────────────────────────────────────────────────────
    RATE_LIMIT: str = "20/minute"

    # ── Password Policy ───────────────────────────────────────────────────
    PASSWORD_MIN_LENGTH: int = 8
    BCRYPT_ROUNDS: int = 12
    MAX_LOGIN_ATTEMPTS: int = 5
    LOGIN_LOCKOUT_MINUTES: int = 15

    # ── CORS ──────────────────────────────────────────────────────────────
    # Browsers reject credentialed cross-origin requests when the origin is
    # the wildcard "*". Store as a comma-separated string so it reads cleanly
    # from a .env file — use the `cors_origins` property to get the parsed
    # list. Override via the CORS_ORIGINS env var (comma-separated).
    CORS_ORIGINS: str = (
        "http://localhost:5500,"
        "http://127.0.0.1:5500,"
        "http://localhost:5501,"
        "http://127.0.0.1:5501,"
        "http://localhost:8000,"
        "http://localhost:3000"
    )

    @property
    def cors_origins(self) -> list[str]:
        """Parse CORS_ORIGINS into a list, tolerating JSON arrays or CSV."""
        raw = self.CORS_ORIGINS.strip()
        if raw.startswith("["):
            import json
            try:
                return [o.strip() for o in json.loads(raw) if o.strip()]
            except json.JSONDecodeError:
                pass
        return [o.strip() for o in raw.split(",") if o.strip()]

    # ── App ───────────────────────────────────────────────────────────────
    APP_NAME: str = "Login Server"
    DEBUG: bool = False

    # ── Audit ─────────────────────────────────────────────────────────────
    AUDIT_LOG_TABLE: str = "audit_log"


settings = Settings()  # type: ignore[call-arg]