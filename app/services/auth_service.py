from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.config import Settings
from app.models.user import User, UserRole, UserStatus
from app.schemas.user_schema import RegisterRequest, UserCreate
from app.utils.security import create_access_token, hash_password, verify_password


def _ensure_unique_identity(db: Session, *, username: str, email: str) -> None:
    existing = (
        db.query(User)
        .filter(or_(User.username == username, User.email == email))
        .first()
    )
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already exists",
        )


def register_public_user(db: Session, payload: RegisterRequest) -> User:
    _ensure_unique_identity(db, username=payload.username, email=payload.email)
    user_count = db.query(User).count()
    role = UserRole.ADMIN if user_count == 0 else UserRole.APP_USER
    user = User(
        username=payload.username,
        email=str(payload.email),
        password_hash=hash_password(payload.password),
        role=role,
        status=UserStatus.ACTIVE,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def create_user(db: Session, payload: UserCreate) -> User:
    _ensure_unique_identity(db, username=payload.username, email=payload.email)
    user = User(
        username=payload.username,
        email=str(payload.email),
        password_hash=hash_password(payload.password),
        role=payload.role,
        status=UserStatus.ACTIVE,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def authenticate_user(db: Session, *, username: str, password: str) -> User | None:
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        return None
    if user.status != UserStatus.ACTIVE:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def mark_login_success(db: Session, user: User) -> User:
    user.last_login_at = datetime.now(timezone.utc)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def issue_token(user: User, settings: Settings) -> str:
    return create_access_token(subject=str(user.id), settings=settings)

