from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_login_page_is_served_from_identity_domain():
    response = client.get('/login?return_to=https%3A%2F%2Fdocuments.nerior.ru%2F')
    assert response.status_code == 200
    assert 'Войти в Nerior' in response.text
    assert 'return_to' in response.text


def test_login_proxy_mints_shared_cookie(monkeypatch):
    class FakeResponse:
        status_code = 200
        cookies = {}
        def json(self):
            return {'data': {'user_id': 'usr_1', 'email': 'u@example.com', 'username': 'u', 'tokens': {'access_token': 'a', 'refresh_token': 'r'}}}
    monkeypatch.setattr('app.main._proxy_planner_login', lambda payload: FakeResponse())
    monkeypatch.setattr('app.main._ensure_subject_and_session', lambda session, user_id, email: 'sess_1')
    response = client.post('/api/v1/login', json={'login': 'u', 'password': 'secret'})
    assert response.status_code == 200
    assert response.cookies['ecosystem_session'] == 'sess_1'
