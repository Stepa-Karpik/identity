from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_browser_session_sets_shared_cookie_and_can_be_exchanged():
    subject = client.post('/api/v1/subjects', json={'email': 'user@example.com'}).json()
    session = client.post('/api/v1/browser-sessions', json={'subject_id': subject['subject_id']})
    assert session.status_code == 201
    assert 'ecosystem_session=' in session.headers['set-cookie']
    exchanged = client.post('/api/v1/session-exchange')
    assert exchanged.status_code == 200
    assert exchanged.json()['subject_id'] == subject['subject_id']


def test_logout_clears_shared_cookie():
    subject = client.post('/api/v1/subjects', json={'email': 'logout@example.com'}).json()
    client.post('/api/v1/browser-sessions', json={'subject_id': subject['subject_id']})
    response = client.post('/api/v1/logout')
    assert response.status_code == 200
    assert 'ecosystem_session=""' in response.headers['set-cookie']


def test_internal_session_mint_preserves_existing_subject_id():
    response = client.post('/api/v1/internal/browser-sessions', json={'subject_id': 'planner-user-1'}, headers={'x-internal-key': 'dev-internal-key'})
    assert response.status_code == 201
    assert response.json()['subject_id'] == 'planner-user-1'
