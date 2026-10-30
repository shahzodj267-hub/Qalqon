from fastapi.testclient import TestClient

from api import main
from api.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_ioc_invalid_value_is_422():
    response = client.post("/api/ioc", json={"value": "salom"})
    assert response.status_code == 422


def test_ioc_empty_value_is_422():
    assert client.post("/api/ioc", json={"value": ""}).status_code == 422


def test_ioc_returns_analysis(monkeypatch):
    fake = {"ioc": "8.8.8.8", "kind": "ip", "score": 0, "verdict": "TOZA", "sources": [], "errors": []}
    monkeypatch.setattr(main, "analyze", lambda value: fake)
    response = client.post("/api/ioc", json={"value": "8.8.8.8"})
    assert response.status_code == 200
    assert response.json()["verdict"] == "TOZA"
