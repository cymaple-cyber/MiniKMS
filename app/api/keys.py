from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import UserRole
from app.schemas.key_schema import KeyCreate, KeyMetadata
from app.services import audit_service, key_service
from app.utils.permissions import get_current_user, require_roles

router = APIRouter(prefix="/keys", tags=["Keys"])


@router.post("", response_model=KeyMetadata, status_code=status.HTTP_201_CREATED)
def create_key(
    payload: KeyCreate,
    request: Request,
    current_user=Depends(require_roles(UserRole.ADMIN, UserRole.KEY_MANAGER)),
    db: Session = Depends(get_db),
):
    key = key_service.create_key(db, payload=payload, creator=current_user)
    audit_service.record_event(
        db,
        request=request,
        user_id=current_user.id,
        action="create_key",
        target_type="key",
        target_id=key.id,
        result="success",
    )
    return key


@router.get("", response_model=list[KeyMetadata])
def list_keys(
    request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    keys = key_service.list_key_metadata(db, user=current_user)
    audit_service.record_event(
        db,
        request=request,
        user_id=current_user.id,
        action="list_key_metadata",
        target_type="key",
        target_id="all",
        result="success",
    )
    return keys


@router.get("/{key_id}", response_model=KeyMetadata)
def get_key(
    key_id: str,
    request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    key = key_service.get_key_metadata(db, key_id=key_id, user=current_user)
    audit_service.record_event(
        db,
        request=request,
        user_id=current_user.id,
        action="get_key_metadata",
        target_type="key",
        target_id=key.id,
        result="success",
    )
    return key


@router.post("/{key_id}/disable", response_model=KeyMetadata)
def disable_key(
    key_id: str,
    request: Request,
    current_user=Depends(require_roles(UserRole.ADMIN, UserRole.KEY_MANAGER)),
    db: Session = Depends(get_db),
):
    key = key_service.disable_key(db, key_id=key_id)
    audit_service.record_event(
        db,
        request=request,
        user_id=current_user.id,
        action="disable_key",
        target_type="key",
        target_id=key.id,
        result="success",
    )
    return key


@router.post("/{key_id}/revoke", response_model=KeyMetadata)
def revoke_key(
    key_id: str,
    request: Request,
    current_user=Depends(require_roles(UserRole.ADMIN, UserRole.KEY_MANAGER)),
    db: Session = Depends(get_db),
):
    key = key_service.revoke_key(db, key_id=key_id)
    audit_service.record_event(
        db,
        request=request,
        user_id=current_user.id,
        action="revoke_key",
        target_type="key",
        target_id=key.id,
        result="success",
    )
    return key


@router.delete("/{key_id}", response_model=KeyMetadata)
def destroy_key(
    key_id: str,
    request: Request,
    current_user=Depends(require_roles(UserRole.ADMIN, UserRole.KEY_MANAGER)),
    db: Session = Depends(get_db),
):
    key = key_service.destroy_key(db, key_id=key_id)
    audit_service.record_event(
        db,
        request=request,
        user_id=current_user.id,
        action="destroy_key",
        target_type="key",
        target_id=key.id,
        result="success",
    )
    return key


@router.post("/{key_id}/rotate", response_model=KeyMetadata)
def rotate_key(
    key_id: str,
    request: Request,
    current_user=Depends(require_roles(UserRole.ADMIN, UserRole.KEY_MANAGER)),
    db: Session = Depends(get_db),
):
    key = key_service.rotate_key(db, key_id=key_id)
    audit_service.record_event(
        db,
        request=request,
        user_id=current_user.id,
        action="rotate_key",
        target_type="key",
        target_id=key.id,
        result="success",
    )
    return key
