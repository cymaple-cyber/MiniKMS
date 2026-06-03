from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.schemas.user_schema import LoginRequest, RegisterRequest, TokenResponse, UserOut
from app.services import audit_service, auth_service
from app.utils.permissions import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    return auth_service.register_public_user(db, payload)


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = auth_service.authenticate_user(
        db,
        username=payload.username,
        password=payload.password,
    )
    if user is None:
        audit_service.record_event(
            db,
            request=request,
            user_id=None,
            action="login_failed",
            target_type="user",
            target_id=payload.username,
            result="failure",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    auth_service.mark_login_success(db, user)
    audit_service.record_event(
        db,
        request=request,
        user_id=user.id,
        action="login_success",
        target_type="user",
        target_id=str(user.id),
        result="success",
    )
    token = auth_service.issue_token(user, get_settings())
    return TokenResponse(access_token=token)


@router.get("/me", response_model=UserOut)
def me(current_user=Depends(get_current_user)):
    return current_user

