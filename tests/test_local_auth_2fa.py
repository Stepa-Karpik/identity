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


def test_internal_totp_settings_are_owned_by_identity():
    client, factory = make_client()
    with factory() as session:
        IdentityRepository(session).upsert_account(subject_id='usr_settings', email='s@example.com', username='settings', password_hash=hash_password('supersecret'))

    setup = client.post('/api/v1/internal/accounts/usr_settings/twofa/totp/setup', headers={'x-internal-key': 'dev-internal-key'})
    assert setup.status_code == 200
    data = setup.json()
    code = totp_code(data['secret'])

    verify = client.post(
        '/api/v1/internal/accounts/usr_settings/twofa/totp/verify-setup',
        headers={'x-internal-key': 'dev-internal-key'},
        json={'pending_id': data['pending_id'], 'code': code},
    )
    assert verify.status_code == 200

    settings = client.get('/api/v1/internal/accounts/usr_settings/twofa', headers={'x-internal-key': 'dev-internal-key'})
    assert settings.status_code == 200
    assert settings.json()['twofa_method'] == 'totp'
    assert settings.json()['totp_enabled'] is True


def test_internal_telegram_settings_callback_updates_identity(monkeypatch):
    sent = []
    monkeypatch.setattr('app.twofa.send_telegram_settings_message', lambda chat_id, action, pending_id: sent.append((chat_id, action, pending_id)))
    client, factory = make_client()
    with factory() as session:
        repo = IdentityRepository(session)
        repo.upsert_account(subject_id='usr_tg_settings', email='ts@example.com', username='tgsettings', password_hash=hash_password('supersecret'))
        repo.upsert_telegram_link(subject_id='usr_tg_settings', chat_id=777, username='tguser')

    request = client.post('/api/v1/internal/accounts/usr_tg_settings/twofa/telegram/enable-request', headers={'x-internal-key': 'dev-internal-key'})
    assert request.status_code == 200
    pending_id = request.json()['pending_id']
    assert sent == [(777, 'enable', pending_id)]

    callback = client.post('/api/v1/internal/twofa/telegram/callback', json={'chat_id':777,'twofa_session_id':pending_id,'decision':'approve'}, headers={'x-internal-key':'dev-internal-key'})
    assert callback.status_code == 200
    assert callback.json()['status'] == 'approved'

    settings = client.get('/api/v1/internal/accounts/usr_tg_settings/twofa', headers={'x-internal-key': 'dev-internal-key'})
    assert settings.json()['twofa_method'] == 'telegram'
    assert settings.json()['telegram_confirmed'] is True
