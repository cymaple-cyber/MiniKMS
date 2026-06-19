import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.key import KeyStatus, KeyVersion, ManagedKey
from app.services.enclave_client import get_enclave_client

DEK_ASSOCIATED_DATA = b"minikms-dek-v1"


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _b64decode(encoded: str) -> bytes:
    try:
        value = encoded.encode("ascii")
        value += b"=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(value)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid ciphertext payload",
        ) from exc


def _master_aesgcm() -> AESGCM:
    settings = get_settings()
    return AESGCM(settings.master_key_bytes())


def generate_dek() -> bytes:
    return os.urandom(32)


def wrap_dek(dek: bytes) -> tuple[str, str]:
    nonce = os.urandom(12)
    ciphertext = _master_aesgcm().encrypt(nonce, dek, DEK_ASSOCIATED_DATA)
    return _b64encode(ciphertext), _b64encode(nonce)


def unwrap_dek(encrypted_key_material: str, nonce: str) -> bytes:
    try:
        return _master_aesgcm().decrypt(
            _b64decode(nonce),
            _b64decode(encrypted_key_material),
            DEK_ASSOCIATED_DATA,
        )
    except (InvalidTag, ValueError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Key material cannot be used",
        )


def generate_wrapped_dek() -> tuple[str, str]:
    if get_settings().use_enclave:
        return get_enclave_client().generate_wrapped_dek()
    dek = generate_dek()
    return wrap_dek(dek)


def _load_active_key(db: Session, key_id: str) -> ManagedKey:
    key = db.get(ManagedKey, key_id)
    if key is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key not found")
    if (
        key.key_status != KeyStatus.ACTIVE
        or key.encrypted_key_material is None
        or key.nonce is None
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Key is inactive and cannot be used for cryptographic operations",
        )
    return key


def _load_active_key_version(
    db: Session,
    *,
    key_id: str,
    key_version: int | None = None,
) -> tuple[ManagedKey, int, str, str]:
    key = _load_active_key(db, key_id)
    selected_version = key.key_version if key_version is None else key_version
    version = (
        db.query(KeyVersion)
        .filter(KeyVersion.key_id == key.id, KeyVersion.version == selected_version)
        .one_or_none()
    )
    if version is None:
        if selected_version == key.key_version and key.encrypted_key_material and key.nonce:
            return key, selected_version, key.encrypted_key_material, key.nonce
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Key version not found",
        )
    if version.encrypted_key_material is None or version.nonce is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Key version is inactive and cannot be used for cryptographic operations",
        )
    return key, selected_version, version.encrypted_key_material, version.nonce


def encrypt_data(db: Session, *, key_id: str, plaintext: str) -> dict[str, str | int]:
    key, key_version, encrypted_key_material, key_nonce = _load_active_key_version(
        db,
        key_id=key_id,
    )

    if get_settings().use_enclave:
        data_nonce, ciphertext = get_enclave_client().encrypt_data(
            key_id=key.id,
            encrypted_key_material=encrypted_key_material,
            key_nonce=key_nonce,
            plaintext=plaintext,
        )
        return {
            "key_id": key.id,
            "key_version": key_version,
            "nonce": data_nonce,
            "ciphertext": ciphertext,
        }

    dek = unwrap_dek(encrypted_key_material, key_nonce)
    nonce = os.urandom(12)
    ciphertext = AESGCM(dek).encrypt(
        nonce,
        plaintext.encode("utf-8"),
        key.id.encode("utf-8"),
    )
    return {
        "key_id": key.id,
        "key_version": key_version,
        "nonce": _b64encode(nonce),
        "ciphertext": _b64encode(ciphertext),
    }


def decrypt_data(
    db: Session,
    *,
    key_id: str,
    nonce: str,
    ciphertext: str,
    key_version: int | None = None,
) -> str:
    key, _, encrypted_key_material, key_nonce = _load_active_key_version(
        db,
        key_id=key_id,
        key_version=key_version,
    )

    if get_settings().use_enclave:
        return get_enclave_client().decrypt_data(
            key_id=key.id,
            encrypted_key_material=encrypted_key_material,
            key_nonce=key_nonce,
            nonce=nonce,
            ciphertext=ciphertext,
        )

    dek = unwrap_dek(encrypted_key_material, key_nonce)
    try:
        plaintext = AESGCM(dek).decrypt(
            _b64decode(nonce),
            _b64decode(ciphertext),
            key.id.encode("utf-8"),
        )
    except (InvalidTag, ValueError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Decryption failed",
        )
    return plaintext.decode("utf-8")
