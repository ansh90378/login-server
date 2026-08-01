"""Database engine and async session factory."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from core.config import settings

# When USE_SQLITE is set, ignore DATABASE_URL and use a local SQLite file so
# the server can run with zero external infrastructure (no Postgres).
_db_url = settings.DATABASE_URL
if settings.USE_SQLITE:
    _db_url = "sqlite+aiosqlite:///./login_demo.db"

# Postgres-specific pool options are unsupported by SQLite.
_kwargs: dict = {}
if not _db_url.startswith("sqlite"):
    _kwargs = {"pool_pre_ping": True, "pool_size": 10, "max_overflow": 20}

engine = create_async_engine(
    _db_url,
    echo=settings.DEBUG,
    **_kwargs,
)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def get_session() -> AsyncSession:  # type: ignore[misc]
    """Dependency that yields an async database session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Create all tables (useful for dev / testing)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Dispose of the engine."""
    await engine.dispose()