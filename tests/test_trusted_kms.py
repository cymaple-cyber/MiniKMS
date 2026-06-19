import base64
import importlib
import os
import sys
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from .conftest import _fresh_import, auth_header, create_key, login, register


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _wait_for_tcp_port(enclave, timeout: float = 10.0) -> int:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if enclave._bound_tcp_port is not None:
            return enclave._bound_tcp_port
        time.sleep(0.05)
    raise RuntimeError("Enclave TCP port not ready")


@pytest.fixture()
def trusted_client(monkeypatch, tmp_path):
    try:
        from enclave.kms_enclave import ENCLAVE_CODE, KmsEnclave
    except ImportError:
        pytest.skip("enclave.kms_enclave not importable")

    master_key = b"E" * 32
    db_path = tmp_path / "trusted-kms-test.db"

    enclave = KmsEnclave(ENCLAVE_CODE, master_key, tcp_port=0)
    thread = threading.Thread(target=enclave.run, daemon=True)
    thread.start()
    port = _wait_for_tcp_port(enclave)

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-jwt-secret-change-me-32-bytes-min")
    monkeypatch.setenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
    monkeypatch.setenv("USE_ENCLAVE", "true")
    monkeypatch.setenv("ENCLAVE_PORT", str(port))
    monkeypatch.delenv("MASTER_KEY", raising=False)

    import app.config

    app.config.get_settings.cache_clear()
    main = _fresh_import("app.main")
    database = importlib.import_module("app.database")
    enclave_client = importlib.import_module("app.services.enclave_client")
    enclave_client.reset_enclave_client()
    database.Base.metadata.drop_all(bind=database.engine)
    database.Base.metadata.create_all(bind=database.engine)

    try:
        with TestClient(main.app) as test_client:
            health = test_client.get("/")
            assert health.status_code == 200
            assert health.json()["crypto_backend"] == "enclave"
            assert health.json()["enclave"] == "connected"
            yield test_client
    finally:
        enclave.stop()
        enclave_client.reset_enclave_client()


def test_trusted_kms_encrypt_decrypt_roundtrip(trusted_client):
    client = trusted_client
    register(client, "admin", "admin@example.com")
    admin_token = login(client, "admin")
    key = create_key(client, admin_token, "trusted-key")

    encrypted = client.post(
        "/crypto/encrypt",
        headers=auth_header(admin_token),
        json={"key_id": key["id"], "plaintext": "hello Trusted KMS"},
    )
    assert encrypted.status_code == 200, encrypted.text
    payload = encrypted.json()

    decrypted = client.post(
        "/crypto/decrypt",
        headers=auth_header(admin_token),
        json={
            "key_id": key["id"],
            "nonce": payload["nonce"],
            "ciphertext": payload["ciphertext"],
        },
    )
    assert decrypted.status_code == 200, decrypted.text
    assert decrypted.json()["plaintext"] == "hello Trusted KMS"


def test_trusted_kms_rotate_and_decrypt_old_version(trusted_client):
    client = trusted_client
    register(client, "admin", "admin@example.com")
    admin_token = login(client, "admin")
    key = create_key(client, admin_token, "rotate-trusted")

    first = client.post(
        "/crypto/encrypt",
        headers=auth_header(admin_token),
        json={"key_id": key["id"], "plaintext": "before rotation"},
    ).json()

    rotated = client.post(f"/keys/{key['id']}/rotate", headers=auth_header(admin_token))
    assert rotated.status_code == 200
    assert rotated.json()["key_version"] == 2

    old_decrypt = client.post(
        "/crypto/decrypt",
        headers=auth_header(admin_token),
        json={
            "key_id": key["id"],
            "key_version": first["key_version"],
            "nonce": first["nonce"],
            "ciphertext": first["ciphertext"],
        },
    )
    assert old_decrypt.status_code == 200
    assert old_decrypt.json()["plaintext"] == "before rotation"
