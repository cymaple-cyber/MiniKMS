# MiniKMS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a runnable phase-one MiniKMS backend with FastAPI, SQLAlchemy, JWT authentication, RBAC, envelope encryption, key lifecycle APIs, audit logs, Docker support, and README documentation.

**Architecture:** Implement a route/service/model/schema split. Store only wrapped DEKs in the database, unwrap in memory for active key operations, and record audit rows at the route and permission boundaries.

**Tech Stack:** Python, FastAPI, SQLAlchemy, SQLite, bcrypt, PyJWT, cryptography AESGCM, pytest, Docker.

---

### Task 1: Tests

**Files:**
- Create: `tests/conftest.py`
- Create: `tests/test_minikms_api.py`

- [x] Write API-level tests for registration, login, `/auth/me`, password hashing, admin user creation, app-user RBAC denial, key creation, encrypt/decrypt, disabled/revoked/destroyed enforcement, and audit logs.
- [x] Run `.venv/bin/python -m pytest -q`.
- [x] Verify tests fail before implementation because `app.models.key` is missing.

### Task 2: Core Application

**Files:**
- Create: `app/main.py`
- Create: `app/config.py`
- Create: `app/database.py`
- Create: `app/models/user.py`
- Create: `app/models/key.py`
- Create: `app/models/audit_log.py`

- [x] Define environment-driven settings.
- [x] Define SQLAlchemy engine/session/base.
- [x] Define user, key, and audit models with enum status/role fields.
- [x] Create tables on application startup for local phase-one development.

### Task 3: Security, Services, and Schemas

**Files:**
- Create: `app/utils/security.py`
- Create: `app/utils/permissions.py`
- Create: `app/services/auth_service.py`
- Create: `app/services/user_service.py`
- Create: `app/services/key_service.py`
- Create: `app/services/crypto_service.py`
- Create: `app/services/audit_service.py`
- Create: `app/schemas/*.py`

- [x] Implement bcrypt hashing and verification.
- [x] Implement JWT creation and current-user loading.
- [x] Implement RBAC dependency helpers that log permission denials.
- [x] Implement key creation, listing, lookup, disable, revoke, destroy, and rotate placeholder.
- [x] Implement AES-256-GCM wrapping of DEKs with `MASTER_KEY`.
- [x] Implement data encrypt/decrypt with fresh nonces and generic decrypt failures.

### Task 4: Routes and Documentation

**Files:**
- Create: `app/api/auth.py`
- Create: `app/api/users.py`
- Create: `app/api/keys.py`
- Create: `app/api/crypto.py`
- Create: `app/api/audit.py`
- Create: `Dockerfile`
- Create: `docker-compose.yml`
- Create: `.env.example`
- Create: `README.md`

- [x] Expose Swagger-testable endpoints.
- [x] Add Docker deployment files.
- [x] Document architecture, running instructions, Swagger usage, security design, audit logs, and expansion directions.

### Task 5: Verification

- [x] Run `.venv/bin/python -m pytest -q`.
- [x] Run `.venv/bin/python -m compileall app tests`.
- [x] Start Uvicorn and confirm `/openapi.json` returns HTTP 200.
