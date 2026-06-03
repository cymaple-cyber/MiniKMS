import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Enum, ForeignKey, Integer, String, Text, UniqueConstraint

from app.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class KeyStatus(str, enum.Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    REVOKED = "revoked"
    DESTROYED = "destroyed"


class ManagedKey(Base):
    __tablename__ = "managed_keys"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    key_name = Column(String(128), nullable=False, index=True)
    key_type = Column(String(32), nullable=False, default="AES-256-GCM")
    key_usage = Column(String(32), nullable=False, default="encrypt/decrypt")
    key_status = Column(
        Enum(
            KeyStatus,
            values_callable=lambda values: [item.value for item in values],
            native_enum=False,
            name="key_status",
        ),
        nullable=False,
        default=KeyStatus.ACTIVE,
    )
    key_version = Column(Integer, nullable=False, default=1)
    encrypted_key_material = Column(Text, nullable=True)
    nonce = Column(String(64), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    rotated_at = Column(DateTime(timezone=True), nullable=True)


class KeyVersion(Base):
    __tablename__ = "key_versions"
    __table_args__ = (
        UniqueConstraint("key_id", "version", name="uq_key_versions_key_id_version"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    key_id = Column(String(36), ForeignKey("managed_keys.id"), nullable=False, index=True)
    version = Column(Integer, nullable=False)
    encrypted_key_material = Column(Text, nullable=True)
    nonce = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
