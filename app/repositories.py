from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import BrowserSessionModel, SubjectModel


class IdentityRepository:
    def __init__(self, session: Session):
        self.session = session

    def ensure_subject(self, *, subject_id: str, email: str) -> SubjectModel:
        subject = self.session.get(SubjectModel, subject_id)
        if subject is None:
            subject = SubjectModel(id=subject_id, email=email)
            self.session.add(subject)
            self.session.commit()
            self.session.refresh(subject)
        return subject

    def create_subject(self, *, email: str) -> SubjectModel:
        existing = self.session.scalar(select(SubjectModel).where(SubjectModel.email == email))
        if existing is not None:
            return existing
        subject = SubjectModel(id=f'usr_{uuid4().hex}', email=email)
        self.session.add(subject)
        self.session.commit()
        self.session.refresh(subject)
        return subject

    def get_subject(self, subject_id: str) -> SubjectModel | None:
        return self.session.get(SubjectModel, subject_id)

    def create_browser_session(self, *, subject_id: str) -> BrowserSessionModel:
        session = BrowserSessionModel(id=f'sess_{uuid4().hex}', subject_id=subject_id)
        self.session.add(session)
        self.session.commit()
        self.session.refresh(session)
        return session

    def get_active_browser_session(self, session_id: str) -> BrowserSessionModel | None:
        session = self.session.get(BrowserSessionModel, session_id)
        if session is None or session.revoked_at is not None:
            return None
        return session

    def revoke_browser_session(self, session_id: str) -> None:
        session = self.session.get(BrowserSessionModel, session_id)
        if session is not None:
            session.revoked_at = datetime.now(UTC)
            self.session.commit()
