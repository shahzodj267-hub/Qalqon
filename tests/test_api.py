from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api import main
from api.main import app
from core import models, security
from core.config import settings
from core.db import Base, get_db

PASSWORD = "correct-horse-battery"
EMAIL = "anna@company.org"
FAKE_IOC = {"ioc": "8.8.8.8", "kind": "ip", "score": 0, "verdict": "TOZA", "sources": [], "errors": []}


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setattr(settings, "jwt_secret", "t" * 48)
    monkeypatch.setattr(main, "analyze", lambda value: FAKE_IOC)
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override
    yield TestClient(app), Session
    app.dependency_overrides.clear()
    engine.dispose()


def register(client, email=EMAIL, password=PASSWORD):
    return client.post("/api/auth/register", json={"email": email, "password": password})


def token(client, email=EMAIL, password=PASSWORD):
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    return r.json()["access_token"]


def bearer(t):
    return {"Authorization": f"Bearer {t}"}


def test_health(env):
    client, _ = env
    assert client.get("/health").json() == {"status": "ok"}


def test_register_and_password_is_hashed(env):
    client, Session = env
    r = register(client)
    assert r.status_code == 201
    assert r.json()["role"] == "user" and r.json()["has_access"] is True
    assert "password" not in r.text
    with Session() as db:
        user = db.query(models.User).one()
        assert user.password_hash.startswith("$argon2")
        assert PASSWORD not in user.password_hash


def test_duplicate_email_case_insensitive(env):
    client, _ = env
    register(client)
    assert register(client, email="ANNA@company.org").status_code == 409


def test_short_password_rejected(env):
    client, _ = env
    assert register(client, password="short").status_code == 422


def test_login_wrong_password_and_unknown_user_same_message(env):
    client, _ = env
    register(client)
    wrong = client.post("/api/auth/login", json={"email": EMAIL, "password": "wrong-password-1"})
    unknown = client.post("/api/auth/login", json={"email": "nobody@company.org", "password": "wrong-password-1"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_me_requires_valid_token(env):
    client, _ = env
    register(client)
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/auth/me", headers=bearer("garbage")).status_code == 401
    r = client.get("/api/auth/me", headers=bearer(token(client)))
    assert r.status_code == 200 and r.json()["email"] == EMAIL


def test_expired_and_foreign_tokens_rejected(env):
    client, _ = env
    register(client)
    assert client.get("/api/auth/me", headers=bearer(security.create_token(1, expires_minutes=-1))).status_code == 401
    good = security.create_token(1)
    settings.jwt_secret = "x" * 48  # monkeypatch fixture qaytarib qo'yadi
    assert security.decode_token(good) is None


def test_ioc_requires_token(env):
    client, _ = env
    assert client.post("/api/ioc", json={"value": "8.8.8.8"}).status_code == 401


def test_ioc_with_token(env):
    client, _ = env
    register(client)
    r = client.post("/api/ioc", json={"value": "8.8.8.8"}, headers=bearer(token(client)))
    assert r.status_code == 200 and r.json()["verdict"] == "TOZA"


def test_ioc_invalid_value_is_422(env, monkeypatch):
    client, _ = env
    monkeypatch.undo()  # haqiqiy analyze() ni qaytaramiz (tarmoqsiz: 422 parse bosqichida chiqadi)
    monkeypatch.setattr(settings, "jwt_secret", "t" * 48)
    register(client)
    r = client.post("/api/ioc", json={"value": "salom"}, headers=bearer(token(client)))
    assert r.status_code == 422


def test_expired_trial_gets_402(env):
    client, Session = env
    register(client)
    t = token(client)
    with Session() as db:
        user = db.query(models.User).one()
        user.trial_ends_at = models.utcnow() - timedelta(days=1)
        db.commit()
    assert client.post("/api/ioc", json={"value": "8.8.8.8"}, headers=bearer(t)).status_code == 402


def test_paid_user_has_access_after_trial(env):
    client, Session = env
    register(client)
    t = token(client)
    with Session() as db:
        user = db.query(models.User).one()
        user.trial_ends_at = models.utcnow() - timedelta(days=1)
        user.paid_until = models.utcnow() + timedelta(days=30)
        db.commit()
    assert client.post("/api/ioc", json={"value": "8.8.8.8"}, headers=bearer(t)).status_code == 200


def test_admin_ignores_trial(env):
    client, Session = env
    register(client)
    t = token(client)
    with Session() as db:
        user = db.query(models.User).one()
        user.role = "admin"
        user.trial_ends_at = None
        db.commit()
    assert client.post("/api/ioc", json={"value": "8.8.8.8"}, headers=bearer(t)).status_code == 200
