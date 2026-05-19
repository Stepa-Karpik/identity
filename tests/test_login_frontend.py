from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_login_page_is_served_from_identity_domain():
    response = client.get('/login?return_to=https%3A%2F%2Fdocuments.nerior.ru%2F')
    assert response.status_code == 200
    assert 'Войти в Nerior' in response.text
    assert 'return_to' in response.text


