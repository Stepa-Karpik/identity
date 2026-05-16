from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import get_session
from app.main import app
from app.models import Base


def make_client():
    engine = create_engine('sqlite+pysqlite:///:memory:', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)
    def override_session():
        with factory() as session:
            yield session
    app.dependency_overrides[get_session] = override_session
    return TestClient(app)


def test_internal_mint_can_exchange_after_separate_request():
    client = make_client()
    minted = client.post('/api/v1/internal/browser-sessions', json={'subject_id': 'planner-user-1', 'email': 'planner@example.com'}, headers={'x-internal-key': 'dev-internal-key'})
    assert minted.status_code == 201
    client.cookies.set('ecosystem_session', minted.json()['session_id'])
    exchanged = client.post('/api/v1/session-exchange')
    assert exchanged.status_code == 200
    assert exchanged.json()['subject_id'] == 'planner-user-1'
