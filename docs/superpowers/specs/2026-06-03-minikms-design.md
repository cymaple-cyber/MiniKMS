# MiniKMS Design

## Goal

MiniKMS is a lightweight FastAPI key management system for a portfolio-ready security engineering project. The current backend focuses on JWT authentication, RBAC, AES-256-GCM data encryption, envelope-encrypted data keys, versioned key rotation, key lifecycle state changes, and audit logging through Swagger-friendly APIs.

## Architecture

The application is organized as a modular FastAPI backend:

- `app/api/` exposes HTTP routes and request-aware audit hooks.
- `app/models/` defines SQLAlchemy ORM tables for users, managed keys, key versions, and audit logs.
- `app/schemas/` defines Pydantic request and response contracts that never expose key material.
- `app/services/` owns authentication, user creation, key lifecycle, cryptographic operations, and audit log persistence.
- `app/utils/` holds reusable security and RBAC helpers.

SQLite is the default database through `DATABASE_URL=sqlite:///./minikms.db`. SQLAlchemy 2.x is used with a URL-driven engine so the same service and model code can move to PostgreSQL by changing the URL and adding migrations later.

## Security Decisions

Passwords are stored with bcrypt hashes. JWT signing secrets and the envelope encryption master key are read from environment variables. The master key is a base64 encoded 32-byte value. Data encryption keys are generated as 32 random bytes, wrapped with AES-GCM using `MASTER_KEY`, and stored only as ciphertext plus nonce.

Every data encryption call creates a fresh random nonce. Decryption failures return a generic error. API responses exclude `encrypted_key_material`, key wrapping nonce values, plaintext DEKs, `MASTER_KEY`, and password hashes.

## Roles

- `admin`: can create users, inspect all key metadata, inspect audit logs, and change key lifecycle state.
- `key_manager`: can create keys, view key metadata, and disable, revoke, or destroy keys.
- `app_user`: can view active key metadata and use active keys for encrypt/decrypt operations.

The first registered user is bootstrapped as `admin`. Later public registrations become `app_user`; admins can create users with explicit roles through `/users`.

## Key Lifecycle

Keys support `active`, `disabled`, `revoked`, and `destroyed` states. Only active keys can be used for encrypt/decrypt. Rotating a key generates a new wrapped DEK, increments `key_version`, and keeps earlier wrapped DEKs in `key_versions` so ciphertext produced before rotation can still be decrypted when the caller provides the historical version. Destroying a key marks it as `destroyed` and wipes the stored wrapped DEK fields for both current and historical versions, making future decrypt operations impossible.

## Audit

Audit logs record login success/failure, key creation, metadata reads, crypto operations, key rotation, lifecycle changes, and RBAC denials. Logs include user id when known, action, target type/id, request IP address, user agent, result, and timestamp.

## Testing

Tests exercise the public API through FastAPI `TestClient`: authentication, password hashing, RBAC denial logging, key lifecycle state transitions, versioned key rotation, envelope encryption safety, and required audit events.
