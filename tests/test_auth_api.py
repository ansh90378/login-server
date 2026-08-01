"""Integration tests for auth API endpoints."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


class TestRegister:
    async def test_register_success(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/api/v1/register",
            json={
                "email": "newuser@example.com",
                "password": "StrongPass1",
                "display_name": "New User",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "user_id" in data
        assert data["email"] == "newuser@example.com"

    async def test_register_duplicate_email(
        self, client: AsyncClient, test_user
    ) -> None:
        resp = await client.post(
            "/api/v1/register",
            json={
                "email": "testuser@example.com",
                "password": "StrongPass1",
            },
        )
        assert resp.status_code == 409
        assert "already exists" in resp.json()["detail"]

    async def test_register_weak_password(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/api/v1/register",
            json={
                "email": "weak@example.com",
                "password": "short",
            },
        )
        assert resp.status_code == 422  # FastAPI validation

    async def test_register_invalid_email(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/api/v1/register",
            json={
                "email": "not-an-email",
                "password": "StrongPass1",
            },
        )
        assert resp.status_code == 422


class TestLogin:
    async def test_login_success(self, client: AsyncClient, test_user) -> None:
        resp = await client.post(
            "/api/v1/login",
            json={
                "email": "testuser@example.com",
                "password": "StrongPass1",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] > 0

    async def test_login_wrong_password(
        self, client: AsyncClient, test_user
    ) -> None:
        resp = await client.post(
            "/api/v1/login",
            json={
                "email": "testuser@example.com",
                "password": "WrongPass1",
            },
        )
        assert resp.status_code == 401

    async def test_login_nonexistent_user(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/api/v1/login",
            json={
                "email": "nobody@example.com",
                "password": "StrongPass1",
            },
        )
        assert resp.status_code == 401


class TestRefresh:
    async def test_refresh_success(self, client: AsyncClient, test_user) -> None:
        # Login first
        login_resp = await client.post(
            "/api/v1/login",
            json={
                "email": "testuser@example.com",
                "password": "StrongPass1",
            },
        )
        refresh_token = login_resp.json()["refresh_token"]

        # Refresh
        resp = await client.post(
            "/api/v1/refresh",
            json={"refresh_token": refresh_token},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        # Token should have been rotated
        assert data["refresh_token"] != refresh_token

    async def test_refresh_invalid_token(self, client: AsyncClient) -> None:
        resp = await client.post(
            "/api/v1/refresh",
            json={"refresh_token": "invalid.jwt.here"},
        )
        assert resp.status_code == 401


class TestLogout:
    async def test_logout_success(self, client: AsyncClient, test_user) -> None:
        # Login
        login_resp = await client.post(
            "/api/v1/login",
            json={
                "email": "testuser@example.com",
                "password": "StrongPass1",
            },
        )
        refresh_token = login_resp.json()["refresh_token"]

        # Logout
        resp = await client.post(
            "/api/v1/logout",
            json={"refresh_token": refresh_token},
        )
        assert resp.status_code == 200

        # Using the logged-out refresh token should fail
        refresh_resp = await client.post(
            "/api/v1/refresh",
            json={"refresh_token": refresh_token},
        )
        assert refresh_resp.status_code == 401


class TestMe:
    async def test_get_me_success(
        self, client: AsyncClient, access_token: str
    ) -> None:
        resp = await client.get(
            "/api/v1/me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == "testuser@example.com"
        assert data["display_name"] == "Test User"
        assert data["is_active"] is True

    async def test_get_me_no_token(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/me")
        assert resp.status_code == 401

    async def test_get_me_invalid_token(self, client: AsyncClient) -> None:
        resp = await client.get(
            "/api/v1/me",
            headers={"Authorization": "Bearer invalidtoken"},
        )
        assert resp.status_code == 401


class TestHealth:
    async def test_health(self, client: AsyncClient) -> None:
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


class TestJWKS:
    async def test_jwks_endpoint(self, client: AsyncClient) -> None:
        resp = await client.get("/api/v1/.well-known/jwks.json")
        assert resp.status_code == 200
        data = resp.json()
        assert "keys" in data
        assert len(data["keys"]) == 1
        key = data["keys"][0]
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"