from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.models import Base
from app.repositories import IdentityRepository


def make_repo():
    engine = create_engine('sqlite+pysqlite:///:memory:')
    Base.metadata.create_all(engine)
    return IdentityRepository(Session(engine))


def test_subject_persists_with_existing_subject_id():
    repo = make_repo()
    subject = repo.ensure_subject(subject_id='planner-user-1', email='user@example.com')
    loaded = repo.get_subject('planner-user-1')
    assert loaded is not None
    assert loaded.id == subject.id
    assert loaded.email == 'user@example.com'


def test_browser_session_persists_and_can_be_revoked():
    repo = make_repo()
    repo.ensure_subject(subject_id='usr_1', email='user@example.com')
    session = repo.create_browser_session(subject_id='usr_1')
    assert repo.get_active_browser_session(session.id) is not None
    repo.revoke_browser_session(session.id)
    assert repo.get_active_browser_session(session.id) is None
