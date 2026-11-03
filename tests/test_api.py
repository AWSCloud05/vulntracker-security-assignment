import os
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from database import Base, get_db  # noqa: E402
import main as main_module
from main import app  # noqa: E402

TEST_DB_URL = "sqlite:///./test_vulntracker.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def register_and_login(username="alice", email="alice@example.com", password="password123"):
    client.post("/auth/register", json={"username": username, "email": email, "password": password})
    resp = client.post("/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_user():
    resp = client.post("/auth/register", json={
        "username": "bob",
        "email": "bob@example.com",
        "password": "secret",
    })
    assert resp.status_code == 201
    assert resp.json()["username"] == "bob"


def test_register_duplicate_username():
    payload = {"username": "bob", "email": "bob@example.com", "password": "secret"}
    client.post("/auth/register", json=payload)
    resp = client.post("/auth/register", json={**payload, "email": "bob2@example.com"})
    assert resp.status_code == 400


def test_login_success():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "pw"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_create_scan():
    token = register_and_login()
    resp = client.post("/scans", json={
        "title": "Reflected XSS in search",
        "description": "User input is echoed without sanitisation",
        "severity": "high",
        "affected_component": "GET /search",
    }, headers=auth_headers(token))
    assert resp.status_code == 201
    assert resp.json()["title"] == "Reflected XSS in search"


def test_list_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "Test finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token))
    resp = client.get("/scans", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_search_scans():
    # TODO: add assertions for search results
    token = register_and_login()
    client.post("/scans", json={
        "title": "SQL Injection via login",
        "severity": "critical",
        "affected_component": "POST /auth/login",
    }, headers=auth_headers(token))
    resp = client.get("/scans/search?q=SQL", headers=auth_headers(token))
    assert resp.status_code == 200


def test_update_scan_status():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Open redirect",
        "severity": "medium",
        "affected_component": "redirect handler",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.patch(f"/scans/{scan_id}", json={"status": "in_progress"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"


def test_delete_scan():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Stale finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 204

def test_create_and_access_public_share_link():
    token = register_and_login()
    headers = auth_headers(token)

    scan_resp = client.post("/scans", json={
        "title": "Shared report test",
        "description": "Testing public report access",
        "severity": "high",
        "affected_component": "OpenSSL",
    }, headers=headers)

    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()["id"]

    share_resp = client.post(
        f"/scans/{scan_id}/share",
        json={},
        headers=headers,
    )

    assert share_resp.status_code == 200
    share_url = share_resp.json()["share_url"]
    share_token = share_url.rsplit("/", 1)[-1]

    public_resp = client.get(f"/share/{share_token}")

    assert public_resp.status_code == 200
    assert public_resp.json()["title"] == "Shared report test"


def test_password_protected_share_link():
    token = register_and_login()
    headers = auth_headers(token)

    scan_resp = client.post("/scans", json={
        "title": "Protected report test",
        "severity": "high",
        "affected_component": "OpenSSL",
    }, headers=headers)

    scan_id = scan_resp.json()["id"]

    share_resp = client.post(
        f"/scans/{scan_id}/share",
        json={"password": "SecurePass@123"},
        headers=headers,
    )

    assert share_resp.status_code == 200
    share_token = share_resp.json()["share_url"].rsplit("/", 1)[-1]

    assert client.get(f"/share/{share_token}").status_code == 401

    assert client.get(
        f"/share/{share_token}",
        params={"password": "WrongPass@123"},
    ).status_code == 401

    correct_resp = client.get(
        f"/share/{share_token}",
        params={"password": "SecurePass@123"},
    )

    assert correct_resp.status_code == 200
    assert correct_resp.json()["title"] == "Protected report test"


def test_invalid_share_token():
    response = client.get("/share/invalid-token")
    assert response.status_code == 404
def test_unsigned_jwt_token_is_rejected():
    import base64
    import json

    def encode_segment(data):
        raw = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = encode_segment({"alg": "none", "typ": "JWT"})
    payload = encode_segment({"sub": "alice"})
    unsigned_token = f"{header}.{payload}."

    response = client.get(
        "/scans",
        headers=auth_headers(unsigned_token),
    )

    assert response.status_code == 401


def test_search_rejects_sql_injection_payload():
    token = register_and_login(
        username="sqltest",
        email="sqltest@example.com"
    )
    headers = auth_headers(token)

    create_response = client.post(
        "/scans",
        json={
            "title": "Private baseline scan",
            "description": "A normal scan record",
            "severity": "high",
            "affected_component": "test-component",
        },
        headers=headers,
    )
    assert create_response.status_code == 201

    response = client.get(
        "/scans/search",
        params={"q": "%' OR 1=1 --"},
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["results"] == []


def test_share_link_uses_configured_https_base_url(monkeypatch):
    token = register_and_login(
        username="shareurl",
        email="shareurl@example.com",
    )
    headers = auth_headers(token)

    scan_response = client.post(
        "/scans",
        json={
            "title": "HTTPS share URL regression test",
            "description": "Verify configured public URL",
            "severity": "high",
            "affected_component": "test-component",
        },
        headers=headers,
    )
    assert scan_response.status_code == 201

    monkeypatch.setattr(
        main_module,
        "PUBLIC_BASE_URL",
        "https://reports.example.com",
    )

    response = client.post(
        f"/scans/{scan_response.json()['id']}/share",
        json={},
        headers=headers,
    )

    assert response.status_code == 200
    share_url = response.json()["share_url"]
    assert share_url.startswith("https://reports.example.com/share/")
    assert "localhost" not in share_url
