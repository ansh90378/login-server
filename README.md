# Login Server — Architecture Document

> A design overview of the authentication / login server, covering components, data flow, security, and deployment.

---

## Table of Contents

- [1. Overview](#1-overview)
- [2. Architecture Diagram](#2-architecture-diagram)
- [3. Core Components](#3-core-components)
- [4. Authentication Flow](#4-authentication-flow)
- [5. Data Models](#5-data-models)
- [6. API Endpoints](#6-api-endpoints)
- [7. Security Considerations](#7-security-considerations)
- [8. Technology Stack](#8-technology-stack)
- [9. Deployment](#9-deployment)
- [10. Future Improvements](#10-future-improvements)

---

## 1. Overview

The Login Server is a stateless authentication service that handles user registration, login, session management, and token issuance. It acts as the **gatekeeper** for downstream services, validating credentials and issuing signed JWTs (JSON Web Tokens) for authorized access.

### Goals

- Centralize authentication logic into a single service.
- Issue short-lived access tokens and long-lived refresh tokens.
- Support password-based, OAuth2, and MFA flows.
- Log all auth events for audit and anomaly detection.

---

## 2. Architecture Diagram

```
┌──────────────┐       ┌──────────────────┐       ┌────────────────┐
│              │  TLS  │                  │       │                │
│   Client     │──────▶│   Login Server   │──────▶│   User DB      │
│  (Web / App) │       │   (FastAPI)      │       │  (PostgreSQL)  │
│              │◀──────│                  │◀──────│                │
└──────────────┘       └──────────────────┘       └────────────────┘
                               │
                               │
                     ┌─────────▼──────────┐
                     │                     │
                     │   Redis Cache       │
                     │  (sessions / rate   │
                     │   limits / black-   │
                     │   listed tokens)    │
                     │                     │
                     └─────────────────────┘
```

**Data flow at a glance:**

1. Client sends credentials over **TLS**.
2. Server validates against the **User DB**.
3. On success, issues an **Access Token** (short-lived) + **Refresh Token** (long-lived).
4. Refresh tokens are stored in **Redis** for revocation support.
5. Subsequent requests carry the access token in the `Authorization` header; downstream services verify it against the server's public key (or call the server's introspection endpoint).

---

## 3. Core Components

### 3.1 API Layer (`api/`)
Handles HTTP request/response. Validates input schemas (Pydantic), calls the service layer, and returns structured JSON.

- `routes/auth.py` — `/login`, `/register`, `/refresh`, `/logout`
- `routes/users.py` — `/users/me`, `/users/{id}` (admin)
- `middleware/rate_limiter.py` — per-IP / per-user rate limiting
- `middleware/cors.py` — CORS policy

### 3.2 Service Layer (`services/`)
Business logic, separated from HTTP concerns.

- `auth_service.py` — password hashing (bcrypt), credential verification, token creation
- `token_service.py` — JWT signing & verification (RS256), token blacklisting
- `user_service.py` — CRUD for user profiles
- `mfa_service.py` — TOTP / SMS code generation and validation

### 3.3 Data Layer (`repositories/`)
Database access via SQLAlchemy async sessions.

- `user_repository.py` — user queries
- `session_repository.py` — refresh token persistence in Redis
- `audit_repository.py` — write-only audit log

### 3.4 Shared (`core/`)
- `security.py` — password policies, hashing utilities
- `config.py` — Pydantic `BaseSettings` (env vars → settings)
- `database.py` — engine & session factory
- `redis.py` — Redis client wrapper
- `exceptions.py` — custom exceptions → HTTP error mapping

---

## 4. Authentication Flow

### 4.1 Registration

```
Client                     Login Server               User DB
  │                            │                        │
  │  POST /register            │                        │
  │  {email, password, name}   │                        │
  │ ─────────────────────────▶│                        │
  │                            │  hash password         │
  │                            │  check uniqueness      │
  │                            │  ─────────────────────▶│
  │                            │  INSERT user           │
  │                            │◀──────────────────────│
  │  201 {user_id, email}      │                        │
  │◀──────────────────────────│                        │
```

### 4.2 Login

```
Client                     Login Server               Redis
  │                            │                        │
  │  POST /login               │                        │
  │  {email, password}         │                        │
  │ ─────────────────────────▶│                        │
  │                            │  verify credentials    │
  │                            │  (fail → 401)         │
  │                            │  check MFA required   │
  │                            │  generate token pair   │
  │                            │  store refresh token ──│──▶ SETEX
  │                            │◀──────────────────────│
  │  200 {access, refresh,     │                        │
  │       expires_in}          │                        │
  │◀──────────────────────────│                        │
```

### 4.3 Token Refresh

```
Client                     Login Server               Redis
  │                            │                        │
  │  POST /refresh             │                        │
  │  {refresh_token}           │                        │
  │ ─────────────────────────▶│                        │
  │                            │  verify JWT signature  │
  │                            │  check not blacklisted │
  │                            │  EXISTS key? ─────────▶│
  │                            │◀──────────────────────│
  │                            │  rotate token pair     │
  │                            │  delete old refresh ──▶│ DEL
  │                            │  store new refresh  ──▶│ SETEX
  │  200 {access, refresh,     │                        │
  │       expires_in}          │                        │
  │◀──────────────────────────│                        │
```

### 4.4 Logout

- Client sends the refresh token.
- Server adds the refresh token to a Redis blacklist with a TTL matching its original expiry.
- Access tokens are not explicitly revoked — their short TTL (~15 min) makes revocation unnecessary. For emergency revocation, a token `iat` (issued-at) claim is checked against a global "not before" timestamp in Redis.

---

## 5. Data Models

### 5.1 User (PostgreSQL)

```
users
├── id              UUID        PK
├── email           VARCHAR(255) UNIQUE NOT NULL
├── password_hash   VARCHAR(255) NOT NULL
├── display_name    VARCHAR(100)
├── mfa_enabled     BOOLEAN     DEFAULT false
├── mfa_secret      VARCHAR(32) -- encrypted
├── is_active       BOOLEAN     DEFAULT true
├── created_at      TIMESTAMPTZ DEFAULT NOW()
├── updated_at      TIMESTAMPTZ DEFAULT NOW()
└── last_login_at   TIMESTAMPTZ
```

### 5.2 Refresh Token (Redis)

```
Key:   refresh_token:{jti}
Value: { user_id, expires_at, family_id }
TTL:   7 days (configurable)
```

> Token **family** — each refresh token belongs to a family. Reuse of an old, already-rotated token within the same family invalidates all tokens in that family (theft detection).

### 5.3 JWT Access Token (stateless)

```json
// Header
{ "alg": "RS256", "typ": "JWT", "kid": "2026-07-key-1" }

// Payload
{
  "sub": "user-uuid",
  "email": "user@example.com",
  "role": "user",
  "iat": 1721856000,
  "exp": 1721856900,
  "jti": "unique-token-id"
}
```

---

## 6. API Endpoints

| Method | Path               | Auth Required | Description              |
|--------|--------------------|---------------|--------------------------|
| POST   | `/api/v1/register` | No            | Create a new account     |
| POST   | `/api/v1/login`    | No            | Authenticate & get token |
| POST   | `/api/v1/refresh`  | No            | Rotate refresh token     |
| POST   | `/api/v1/logout`   | Yes           | Revoke refresh token     |
| GET    | `/api/v1/me`       | Yes           | Get current user profile |
| POST   | `/api/v1/mfa/setup`| Yes           | Enable TOTP MFA          |
| POST   | `/api/v1/mfa/verify`| Yes          | Verify MFA code          |
| GET    | `/api/v1/.well-known/jwks.json` | No | Public keys for signature verification |

---

## 7. Security Considerations

| Threat                    | Mitigation                                                 |
|---------------------------|------------------------------------------------------------|
| Brute-force login         | Rate limiting (per IP + per account) + gradual delay       |
| Password leakage           | bcrypt (cost ≥12), never log or return passwords           |
| Token theft               | Short TTL (15 min access), refresh rotation, family detection |
| CSRF                      | SameSite=Strict cookies for browser clients                |
| SQL injection             | Parameterized queries via SQLAlchemy                        |
| Token replay              | `jti` uniqueness checked at `/refresh`                     |
| Timing attack on login    | Constant-time comparison of password hashes                |
| Leaked JWKS private key   | Key rotation every 90 days; `kid` header for key selection |

### Password Policy

- Minimum 8 characters, at least one uppercase, one lowercase, one digit.
- Check against a known compromised-password list (Have I Been Pwned API).
- Max 5 failed login attempts before a 15-minute lockout.

---

## 8. Technology Stack

| Layer        | Technology                      |
|--------------|---------------------------------|
| Framework    | FastAPI (Python)                |
| Auth Tokens  | PyJWT with RS256                |
| Password     | bcrypt via `passlib`            |
| ORM          | SQLAlchemy 2.0 (async)          |
| Database     | PostgreSQL 16                   |
| Cache        | Redis 7                         |
| Validation   | Pydantic v2                     |
| Migration    | Alembic                         |
| Testing      | pytest + httpx (async)          |
| Container    | Docker + docker-compose         |
| Reverse Proxy| Nginx (TLS termination)         |

---

## 9. Deployment

### 9.1 Quick Start (Docker — recommended)

```bash
# 1. Generate RSA keys (one time)
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in private.pem -out public.pem

# 2. Start everything (app, PostgreSQL, Redis)
docker compose up --build
# App runs at http://localhost:8000
# Docs at http://localhost:8000/docs
```

### 9.2 Quick Start (Local — no Docker)

**Prerequisites:** Python 3.12+, PostgreSQL 16+, Redis 7+

```bash
# 1. Clone & set up virtual environment
cd login-server
python -m venv .venv
source .venv/bin/activate   # Linux/Mac
# .venv\Scripts\activate    # Windows PowerShell

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate RSA keys (one time)
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in private.pem -out public.pem

# 4. Configure environment
#    Edit .env if your PostgreSQL/Redis credentials differ from defaults.
#    Keys are auto-loaded from private.pem / public.pem.

# 5. Start PostgreSQL and Redis (e.g., via Docker)
docker compose up -d db redis

# 6. Start the server
uvicorn app:app --reload --port 8000
```

### 9.3 Test the server

```bash
# Health check
curl http://localhost:8000/health
# → {"status":"ok"}

# Register a user
curl -X POST http://localhost:8000/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"StrongPass1","display_name":"Test"}'

# Login
curl -X POST http://localhost:8000/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"StrongPass1"}'

# Use the returned access_token for authenticated requests
curl http://localhost:8000/api/v1/me \
  -H "Authorization: Bearer <access_token>"

# Get public JWKS
curl http://localhost:8000/api/v1/.well-known/jwks.json
```

### 9.4 Environment Variables

| Variable              | Default                                                             | Description                |
|-----------------------|---------------------------------------------------------------------|----------------------------|
| `DATABASE_URL`        | `postgresql+asyncpg://postgres:postgres@localhost:5432/login_db`    | PostgreSQL connection      |
| `REDIS_URL`           | `redis://localhost:6379/0`                                          | Redis connection           |
| `JWT_PRIVATE_KEY_PATH`| `private.pem`                                                       | Path to RSA private key    |
| `JWT_PUBLIC_KEY_PATH` | `public.pem`                                                        | Path to RSA public key     |
| `ACCESS_TOKEN_TTL`    | `900`                                                               | Access token lifetime (s)  |
| `REFRESH_TOKEN_TTL`   | `604800`                                                            | Refresh token lifetime (s) |
| `RATE_LIMIT`          | `20/minute`                                                         | Max requests per minute    |
| `DEBUG`               | `false`                                                             | Debug / SQL echo mode      |

### 9.5 Production

- Run behind **Nginx** with TLS 1.3.
- Use **Kubernetes** or **Nomad** for orchestration (horizontal scaling).
- Store RSA keys in **Vault** or AWS Secrets Manager (never commit them).
- Set `DEBUG=false`, tune `RATE_LIMIT`, and configure `CORS_ORIGINS`.
- Health check: `GET /health` → `{"status": "ok"}`

---

## 10. Future Improvements

- [ ] **WebAuthn / Passkeys** — passwordless authentication.
- [ ] **OAuth2 / Social Login** — Google, GitHub, Microsoft.
- [ ] **Session dashboard** — for users to view and revoke active sessions.
- [ ] **Anomaly detection** — geo-IP velocity checks, impossible-travel detection.
- [ ] **Rate-limit tiers** — stricter for `/login` than `/register`.
- [ ] **gRPC API** — internal services bypass HTTP for lower latency.
- [ ] **OpenTelemetry integration** — traces and metrics for observability.

---

*Last updated: 2026-07-25*