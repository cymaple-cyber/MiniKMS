from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import UserRole
from app.schemas.user_schema import UserCreate, UserOut
from app.services import audit_service, auth_service, user_service
from app.utils.permissions import require_roles

router = APIRouter(prefix="/users", tags=["Users"])


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    request: Request,
    admin=Depends(require_roles(UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    user = auth_service.create_user(db, payload)
    audit_service.record_event(
        db,
        request=request,
        user_id=admin.id,
        action="create_user",
        target_type="user",
        target_id=str(user.id),
        result="success",
    )
    return user


@router.get("", response_model=list[UserOut])
def list_users(
    admin=Depends(require_roles(UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    return user_service.list_users(db)

