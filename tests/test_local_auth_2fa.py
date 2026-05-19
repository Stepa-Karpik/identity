from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import get_session
from app.main import app
from app.models import Base
from app.repositories import IdentityRepository
from app.security import hash_password, generate_totp_secret, totp_code


def make_client():
    engine = create_engine('sqlite+pysqlite:///:memory:', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)
    def override_session():
        with factory() as session:
            yield session
    app.dependency_overrides[get_session] = override_session
    return TestClient(app), factory


def test_local_password_login_mints_cookie_without_planner(monkeypatch):
    client, factory = make_client()
    with factory() as session:
        IdentityRepository(session).upsert_account(subject_id='usr_1', email='u@example.com', username='stepka', password_hash=hash_password('supersecret'))
    response = client.post('/api/v1/login', json={'login':'stepka','password':'supersecret'})
    assert response.status_code == 200
    assert response.json() == {'ok': True, 'subject_id': 'usr_1'}
    assert response.cookies['ecosystem_session'].startswith('sess_')


def test_totp_2fa_is_completed_inside_identity(monkeypatch):
    client, factory = make_client()
    secret = generate_totp_secret()
    with factory() as session:
        IdentityRepository(session).upsert_account(subject_id='usr_2', email='t@example.com', username='totp', password_hash=hash_password('supersecret'), twofa_method='totp', twofa_totp_secret=secret)
    challenge = client.post('/api/v1/login', json={'login':'totp','password':'supersecret'}).json()
    assert challenge['requires_twofa'] is True
    assert challenge['twofa_method'] == 'totp'
    response = client.post('/api/v1/twofa/totp/verify', json={'twofa_session_id': challenge['twofa_session_id'], 'code': totp_code(secret)})
    assert response.status_code == 200
    assert response.cookies['ecosystem_session'].startswith('sess_')


def test_telegram_2fa_approval_is_stored_in_identity(monkeypatch):
    sent = []
    monkeypatch.setattr('app.twofa.send_telegram_message', lambda chat_id, text, session_id: sent.append((chat_id, session_id)))
    client, factory = make_client()
    with factory() as session:
        repo = IdentityRepository(session)
        repo.upsert_account(subject_id='usr_3', email='g@example.com', username='tg', password_hash=hash_password('supersecret'), twofa_method='telegram')
        repo.upsert_telegram_link(subject_id='usr_3', chat_id=42, username='tguser')
    challenge = client.post('/api/v1/login', json={'login':'tg','password':'supersecret'}).json()
    request = client.post('/api/v1/twofa/telegram/request', json={'twofa_session_id': challenge['twofa_session_id']})
    assert request.status_code == 200
    assert sent and sent[0][0] == 42
    callback = client.post('/api/v1/internal/twofa/telegram/callback', json={'chat_id':42,'twofa_session_id':challenge['twofa_session_id'],'decision':'approve'}, headers={'x-internal-key':'dev-internal-key'})
    assert callback.json()['status'] == 'approved'
    complete = client.post('/api/v1/twofa/telegram/complete', json={'twofa_session_id': challenge['twofa_session_id']})
    assert complete.status_code == 200
    assert complete.cookies['ecosystem_session'].startswith('sess_')
