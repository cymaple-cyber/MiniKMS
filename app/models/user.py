import enum
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Enum, Integer, String

from app.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    KEY_MANAGER = "key_manager"
    APP_USER = "app_user"


class UserStatus(str, enum.Enum):
    ACTIVE = "active"
    DISABLED = "disabled"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(
        Enum(
            UserRole,
            values_callable=lambda values: [item.value for item in values],
            native_enum=False,
            name="user_role",
        ),
        nullable=False,
        default=UserRole.APP_USER,
    )
    status = Column(
        Enum(
            UserStatus,
            values_callable=lambda values: [item.value for item in values],
            native_enum=False,
            name="user_status",
        ),
        nullable=False,
        default=UserStatus.ACTIVE,
    )
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

