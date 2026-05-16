from fastapi.testclient import TestClient

from app.main import app


def test_healthz_reports_service_name():
    response = TestClient(app).get("/healthz")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["service"]
