import base64
import importlib
import os
import sys

import pytest
from fastapi.testclient import TestClient


def _fresh_import(module_name: str):
    for loaded_name in list(sys.modules):
        if loaded_name == module_name or loaded_name.startswith(f"{module_name}."):
            sys.modules.pop(loaded_name)
    return importlib.import_module(module_name)


@pytest.fixture()
def client(monkeypatch, tmp_path):
    master_key = base64.urlsafe_b64encode(b"0" * 32).decode("ascii")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'minikms-test.db'}")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-jwt-secret-change-me-32-bytes-min")
    monkeypatch.setenv("MASTER_KEY", master_key)
    monkeypatch.setenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")

    main = _fresh_import("app.main")
    database = importlib.import_module("app.database")
    database.Base.metadata.drop_all(bind=database.engine)
    database.Base.metadata.create_all(bind=database.engine)

    with TestClient(main.app) as test_client:
        yield test_client


def register(client, username, email, password="Password123!"):
    return client.post(
        "/auth/register",
        json={"username": username, "email": email, "password": password},
    )


def login(client, username, password="Password123!"):
    response = client.post(
        "/auth/login",
        json={"username": username, "password": password},
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}
