from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.key import KeyStatus, KeyVersion, ManagedKey, utc_now
from app.models.user import User, UserRole
from app.schemas.key_schema import KeyCreate
from app.services.crypto_service import generate_dek, wrap_dek


def create_key(db: Session, *, payload: KeyCreate, creator: User) -> ManagedKey:
    dek = generate_dek()
    encrypted_key_material, nonce = wrap_dek(dek)
    key = ManagedKey(
        key_name=payload.key_name,
        key_type=payload.key_type,
        key_usage=payload.key_usage,
        key_status=KeyStatus.ACTIVE,
        key_version=1,
        encrypted_key_material=encrypted_key_material,
        nonce=nonce,
        created_by=creator.id,
        expires_at=payload.expires_at,
    )
    db.add(key)
    db.flush()
    db.add(
        KeyVersion(
            key_id=key.id,
            version=key.key_version,
            encrypted_key_material=encrypted_key_material,
            nonce=nonce,
        )
    )
    db.commit()
    db.refresh(key)
    return key


def list_key_metadata(db: Session, *, user: User) -> list[ManagedKey]:
    query = db.query(ManagedKey)
    if user.role == UserRole.APP_USER:
        query = query.filter(ManagedKey.key_status == KeyStatus.ACTIVE)
    return query.order_by(ManagedKey.created_at.desc()).all()


def get_key_metadata(db: Session, *, key_id: str, user: User) -> ManagedKey:
    key = db.get(ManagedKey, key_id)
    if key is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")
    if user.role == UserRole.APP_USER and key.key_status != KeyStatus.ACTIVE:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")
    return key


def disable_key(db: Session, *, key_id: str) -> ManagedKey:
    key = _get_lifecycle_key(db, key_id)
    key.key_status = KeyStatus.DISABLED
    db.add(key)
    db.commit()
    db.refresh(key)
    return key


def revoke_key(db: Session, *, key_id: str) -> ManagedKey:
    key = _get_lifecycle_key(db, key_id)
    key.key_status = KeyStatus.REVOKED
    db.add(key)
    db.commit()
    db.refresh(key)
    return key


def destroy_key(db: Session, *, key_id: str) -> ManagedKey:
    key = _get_lifecycle_key(db, key_id)
    key.key_status = KeyStatus.DESTROYED
    key.encrypted_key_material = None
    key.nonce = None
    (
        db.query(KeyVersion)
        .filter(KeyVersion.key_id == key.id)
        .update(
            {
                KeyVersion.encrypted_key_material: None,
                KeyVersion.nonce: None,
            },
            synchronize_session=False,
        )
    )
    db.add(key)
    db.commit()
    db.refresh(key)
    return key


def rotate_key(db: Session, *, key_id: str) -> ManagedKey:
    key = _get_lifecycle_key(db, key_id)
    if key.key_status != KeyStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only active keys can be rotated",
        )
    _ensure_current_version_record(db, key)

    new_version = key.key_version + 1
    dek = generate_dek()
    encrypted_key_material, nonce = wrap_dek(dek)
    key.key_version = new_version
    key.encrypted_key_material = encrypted_key_material
    key.nonce = nonce
    key.rotated_at = utc_now()
    db.add(
        KeyVersion(
            key_id=key.id,
            version=new_version,
            encrypted_key_material=encrypted_key_material,
            nonce=nonce,
        )
    )
    db.add(key)
    db.commit()
    db.refresh(key)
    return key


def _get_lifecycle_key(db: Session, key_id: str) -> ManagedKey:
    key = db.get(ManagedKey, key_id)
    if key is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")
    if key.key_status == KeyStatus.DESTROYED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Destroyed keys cannot be modified",
        )
    return key


def _ensure_current_version_record(db: Session, key: ManagedKey) -> None:
    version = (
        db.query(KeyVersion)
        .filter(KeyVersion.key_id == key.id, KeyVersion.version == key.key_version)
        .one_or_none()
    )
    if version is not None or key.encrypted_key_material is None or key.nonce is None:
        return
    db.add(
        KeyVersion(
            key_id=key.id,
            version=key.key_version,
            encrypted_key_material=key.encrypted_key_material,
            nonce=key.nonce,
        )
    )
