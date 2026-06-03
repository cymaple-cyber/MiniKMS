from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.crypto_schema import (
    DecryptRequest,
    DecryptResponse,
    EncryptRequest,
    EncryptResponse,
)
from app.services import audit_service, crypto_service
from app.utils.permissions import get_current_user

router = APIRouter(prefix="/crypto", tags=["Crypto"])


@router.post("/encrypt", response_model=EncryptResponse)
def encrypt(
    payload: EncryptRequest,
    request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        encrypted = crypto_service.encrypt_data(
            db,
            key_id=payload.key_id,
            plaintext=payload.plaintext,
        )
    except HTTPException as exc:
        audit_service.record_event(
            db,
            request=request,
            user_id=current_user.id,
            action="encrypt",
            target_type="key",
            target_id=payload.key_id,
            result="failure",
        )
        raise exc
    audit_service.record_event(
        db,
        request=request,
        user_id=current_user.id,
        action="encrypt",
        target_type="key",
        target_id=payload.key_id,
        result="success",
    )
    return encrypted


@router.post("/decrypt", response_model=DecryptResponse)
def decrypt(
    payload: DecryptRequest,
    request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        plaintext = crypto_service.decrypt_data(
            db,
            key_id=payload.key_id,
            key_version=payload.key_version,
            nonce=payload.nonce,
            ciphertext=payload.ciphertext,
        )
    except HTTPException as exc:
        audit_service.record_event(
            db,
            request=request,
            user_id=current_user.id,
            action="decrypt",
            target_type="key",
            target_id=payload.key_id,
            result="failure",
        )
        raise exc
    audit_service.record_event(
        db,
        request=request,
        user_id=current_user.id,
        action="decrypt",
        target_type="key",
        target_id=payload.key_id,
        result="success",
    )
    return DecryptResponse(plaintext=plaintext)
