from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api import audit, auth, crypto, keys, users
from app.config import get_settings
from app.database import Base, engine
from app.services.enclave_client import get_enclave_client, reset_enclave_client

# Import models so SQLAlchemy registers all tables before create_all.
from app.models import AuditLog, KeyVersion, ManagedKey, User  # noqa: F401


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    settings = get_settings()
    if settings.use_enclave:
        get_enclave_client().connect_and_attest()
    yield
    if settings.use_enclave:
        reset_enclave_client()


settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version="0.2.0",
    description=(
        "Lightweight key management backend with JWT, RBAC, envelope encryption, "
        "versioned key rotation, audit logs, and optional TEE enclave backend."
    ),
    lifespan=lifespan,
)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(keys.router)
app.include_router(crypto.router)
app.include_router(audit.router)


@app.get("/", tags=["Health"])
def health():
    payload: dict[str, str] = {
        "service": "TrustedKMS" if settings.use_enclave else "MiniKMS",
        "status": "ok",
        "crypto_backend": "enclave" if settings.use_enclave else "local",
    }
    if settings.use_enclave:
        payload["enclave"] = "connected" if get_enclave_client().is_connected else "disconnected"
    return payload
