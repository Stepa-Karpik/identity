from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_subject_can_be_registered_and_session_issued():
    created = client.post('/api/v1/subjects', json={'email': 'user@example.com'})
    assert created.status_code == 201
    subject_id = created.json()['subject_id']
    session = client.post('/api/v1/sessions', json={'subject_id': subject_id})
    assert session.status_code == 201
    assert session.json()['subject_id'] == subject_id
