"""Pytest fixtures for testing the Login Server."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any, AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from core.database import Base, get_session
from core.security import create_access_token, hash_password
from models.user import User

# ── In-memory SQLite for tests ───────────────────────────────────────────

TEST_DATABASE_URL = "sqlite+aiosqlite:///./test_login.db"

_test_engine = create_async_engine(
    TEST_DATABASE_URL,
    echo=False,
)

_test_session_factory = async_sessionmaker(
    _test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# ── Mock Redis ───────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def mock_redis():
    """Mock Redis calls to avoid needing a running Redis server during tests.

    Uses a simple dict-based store for token operations.
    """
    store: dict[str, Any] = {}
    mock_redis_client = MagicMock()
    mock_redis_client.incr = AsyncMock(return_value=1)
    mock_redis_client.expire = AsyncMock(return_value=True)
    mock_redis_client.set = AsyncMock(side_effect=lambda key, value, **kwargs: store.update({key: value}))
    mock_redis_client.get = AsyncMock(side_effect=lambda key: store.get(key))
    mock_redis_client.delete = AsyncMock(side_effect=lambda key: store.pop(key, None))
    mock_redis_client.exists = AsyncMock(side_effect=lambda key: 1 if key in store else 0)

    with patch("core.redis._redis", mock_redis_client), \
             patch("core.redis.get_redis", return_value=mock_redis_client):
        yield


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(autouse=True)
async def setup_db() -> AsyncGenerator[None, None]:
    """Create tables before each test, drop after."""
    async with _test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with _test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    async with _test_session_factory() as session:
        yield session


@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession) -> User:
    """Create and return a test user."""
    user = User(
        id=uuid.uuid4(),
        email="testuser@example.com",
        password_hash=hash_password("StrongPass1"),
        display_name="Test User",
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def access_token(test_user: User) -> str:
    """Return a valid access token for the test user."""
    return create_access_token(
        subject=str(test_user.id),
        email=test_user.email,
        role="user",
    )


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Return an httpx AsyncClient wired to the FastAPI app with a test DB session."""

    async def _get_test_session() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    from app import create_app

    app = create_app()
    app.dependency_overrides[get_session] = _get_test_session

    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac