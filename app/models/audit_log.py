from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String

from app.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    action = Column(String(64), nullable=False, index=True)
    target_type = Column(String(64), nullable=False)
    target_id = Column(String(128), nullable=True)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(512), nullable=True)
    result = Column(String(32), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)

