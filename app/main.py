from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api import audit, auth, crypto, keys, users
from app.config import get_settings
from app.database import Base, engine

# Import models so SQLAlchemy registers all tables before create_all.
from app.models import AuditLog, KeyVersion, ManagedKey, User  # noqa: F401


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="Lightweight key management backend with JWT, RBAC, envelope encryption, versioned key rotation, and audit logs.",
    lifespan=lifespan,
)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(keys.router)
app.include_router(crypto.router)
app.include_router(audit.router)


@app.get("/", tags=["Health"])
def health():
    return {"service": "MiniKMS", "status": "ok"}
