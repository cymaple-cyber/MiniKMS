from .conftest import auth_header, login, register


def create_user(client, admin_token, username, email, role):
    response = client.post(
        "/users",
        headers=auth_header(admin_token),
        json={
            "username": username,
            "email": email,
            "password": "Password123!",
            "role": role,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def create_key(client, token, key_name="demo-key"):
    response = client.post(
        "/keys",
        headers=auth_header(token),
        json={"key_name": key_name, "expires_at": None},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_first_registered_user_can_login_and_call_me(client):
    response = register(client, "admin", "admin@example.com")
    assert response.status_code == 201
    assert response.json()["role"] == "admin"
    assert "password_hash" not in response.json()

    token = login(client, "admin")
    me = client.get("/auth/me", headers=auth_header(token))

    assert me.status_code == 200
    assert me.json()["username"] == "admin"
    assert me.json()["role"] == "admin"


def test_password_hash_is_not_plaintext(client):
    register(client, "admin", "admin@example.com")

    from app.database import SessionLocal
    from app.models.user import User

    with SessionLocal() as db:
        user = db.query(User).filter(User.username == "admin").one()
        assert user.password_hash != "Password123!"
        assert user.password_hash.startswith("$2")


def test_admin_can_create_user_and_app_user_cannot_create_key(client):
    register(client, "admin", "admin@example.com")
    admin_token = login(client, "admin")
    create_user(client, admin_token, "alice", "alice@example.com", "app_user")
    alice_token = login(client, "alice")

    response = client.post(
        "/keys",
        headers=auth_header(alice_token),
        json={"key_name": "blocked-key"},
    )

    assert response.status_code == 403
    logs = client.get("/audit/logs", headers=auth_header(admin_token)).json()
    assert any(log["action"] == "permission_denied" for log in logs)


def test_key_lifecycle_and_crypto_never_return_key_material(client):
    from app.models.key import KeyStatus

    register(client, "admin", "admin@example.com")
    admin_token = login(client, "admin")
    key = create_key(client, admin_token)

    assert key["key_status"] == "active"
    assert key["key_type"] == "AES-256-GCM"
    assert "encrypted_key_material" not in key
    assert "nonce" not in key

    encrypt_response = client.post(
        "/crypto/encrypt",
        headers=auth_header(admin_token),
        json={"key_id": key["id"], "plaintext": "hello MiniKMS"},
    )
    assert encrypt_response.status_code == 200, encrypt_response.text
    encrypted = encrypt_response.json()
    assert encrypted["key_id"] == key["id"]
    assert encrypted["nonce"]
    assert encrypted["ciphertext"]

    decrypt_response = client.post(
        "/crypto/decrypt",
        headers=auth_header(admin_token),
        json={
            "key_id": key["id"],
            "nonce": encrypted["nonce"],
            "ciphertext": encrypted["ciphertext"],
        },
    )
    assert decrypt_response.status_code == 200, decrypt_response.text
    assert decrypt_response.json()["plaintext"] == "hello MiniKMS"

    disabled = client.post(f"/keys/{key['id']}/disable", headers=auth_header(admin_token))
    assert disabled.status_code == 200
    disabled_encrypt = client.post(
        "/crypto/encrypt",
        headers=auth_header(admin_token),
        json={"key_id": key["id"], "plaintext": "blocked"},
    )
    assert disabled_encrypt.status_code == 400
    assert "inactive" in disabled_encrypt.json()["detail"].lower()

    revoked_key = create_key(client, admin_token, "revoked-key")
    revoked = client.post(f"/keys/{revoked_key['id']}/revoke", headers=auth_header(admin_token))
    assert revoked.status_code == 200
    revoked_decrypt = client.post(
        "/crypto/decrypt",
        headers=auth_header(admin_token),
        json={"key_id": revoked_key["id"], "nonce": encrypted["nonce"], "ciphertext": encrypted["ciphertext"]},
    )
    assert revoked_decrypt.status_code == 400

    destroyed_key = create_key(client, admin_token, "destroyed-key")
    destroyed = client.delete(f"/keys/{destroyed_key['id']}", headers=auth_header(admin_token))
    assert destroyed.status_code == 200
    assert destroyed.json()["key_status"] == "destroyed"

    from app.database import SessionLocal
    from app.models.key import ManagedKey

    with SessionLocal() as db:
        stored = db.get(ManagedKey, destroyed_key["id"])
        assert stored.key_status == KeyStatus.DESTROYED
        assert stored.encrypted_key_material is None
        assert stored.nonce is None


def test_rotate_key_preserves_old_version_for_decrypt(client):
    register(client, "admin", "admin@example.com")
    admin_token = login(client, "admin")
    key = create_key(client, admin_token, "rotating-key")

    first_encrypt = client.post(
        "/crypto/encrypt",
        headers=auth_header(admin_token),
        json={"key_id": key["id"], "plaintext": "before rotation"},
    )
    assert first_encrypt.status_code == 200, first_encrypt.text
    old_ciphertext = first_encrypt.json()
    assert old_ciphertext["key_version"] == 1

    rotated = client.post(f"/keys/{key['id']}/rotate", headers=auth_header(admin_token))

    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["key_version"] == 2
    assert rotated.json()["key_status"] == "active"
    assert rotated.json()["rotated_at"] is not None

    second_encrypt = client.post(
        "/crypto/encrypt",
        headers=auth_header(admin_token),
        json={"key_id": key["id"], "plaintext": "after rotation"},
    )
    assert second_encrypt.status_code == 200, second_encrypt.text
    new_ciphertext = second_encrypt.json()
    assert new_ciphertext["key_version"] == 2

    old_decrypt = client.post(
        "/crypto/decrypt",
        headers=auth_header(admin_token),
        json={
            "key_id": key["id"],
            "key_version": old_ciphertext["key_version"],
            "nonce": old_ciphertext["nonce"],
            "ciphertext": old_ciphertext["ciphertext"],
        },
    )
    assert old_decrypt.status_code == 200, old_decrypt.text
    assert old_decrypt.json()["plaintext"] == "before rotation"

    new_decrypt = client.post(
        "/crypto/decrypt",
        headers=auth_header(admin_token),
        json={
            "key_id": key["id"],
            "key_version": new_ciphertext["key_version"],
            "nonce": new_ciphertext["nonce"],
            "ciphertext": new_ciphertext["ciphertext"],
        },
    )
    assert new_decrypt.status_code == 200, new_decrypt.text
    assert new_decrypt.json()["plaintext"] == "after rotation"


def test_audit_log_records_login_failures_and_key_operations(client):
    register(client, "admin", "admin@example.com")
    failed = client.post(
        "/auth/login",
        json={"username": "admin", "password": "wrong-password"},
    )
    assert failed.status_code == 401

    admin_token = login(client, "admin")
    key = create_key(client, admin_token, "audited-key")
    client.get("/keys", headers=auth_header(admin_token))
    client.get(f"/keys/{key['id']}", headers=auth_header(admin_token))
    client.post(
        "/crypto/encrypt",
        headers=auth_header(admin_token),
        json={"key_id": key["id"], "plaintext": "audit me"},
    )
    client.delete(f"/keys/{key['id']}", headers=auth_header(admin_token))

    logs = client.get("/audit/logs", headers=auth_header(admin_token))
    assert logs.status_code == 200
    actions = [log["action"] for log in logs.json()]

    assert "login_failed" in actions
    assert "login_success" in actions
    assert "create_key" in actions
    assert "list_key_metadata" in actions
    assert "get_key_metadata" in actions
    assert "encrypt" in actions
    assert "destroy_key" in actions
