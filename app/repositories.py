from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models import BrowserSessionModel, SubjectModel, TelegramLinkModel, TwoFALoginSessionModel, TwoFAPendingActionModel


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

    def upsert_account(
        self,
        *,
        subject_id: str,
        email: str,
        username: str | None,
        password_hash: str | None,
        display_name: str | None = None,
        twofa_method: str = 'none',
        twofa_totp_secret: str | None = None,
        twofa_last_totp_step: int | None = None,
    ) -> SubjectModel:
        subject = self.session.get(SubjectModel, subject_id)
        if subject is None:
            subject = SubjectModel(id=subject_id, email=email)
            self.session.add(subject)
        subject.email = email.lower()
        subject.username = username.lower() if username else None
        subject.password_hash = password_hash
        subject.display_name = display_name
        subject.twofa_method = twofa_method or 'none'
        subject.twofa_totp_secret = twofa_totp_secret
        subject.twofa_last_totp_step = twofa_last_totp_step
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

    def get_subject_by_login(self, login: str) -> SubjectModel | None:
        normalized = login.strip().lower()
        return self.session.scalar(select(SubjectModel).where(or_(SubjectModel.email == normalized, SubjectModel.username == normalized)))

    def update_last_totp_step(self, subject_id: str, step: int) -> None:
        subject = self.get_subject(subject_id)
        assert subject is not None
        subject.twofa_last_totp_step = step
        self.session.commit()

    def update_twofa_settings(
        self,
        subject: SubjectModel,
        *,
        method: str | None = None,
        totp_secret: str | None = None,
        clear_totp_secret: bool = False,
        last_totp_step: int | None = None,
        clear_last_totp_step: bool = False,
    ) -> SubjectModel:
        if method is not None:
            subject.twofa_method = method
        if clear_totp_secret:
            subject.twofa_totp_secret = None
        elif totp_secret is not None:
            subject.twofa_totp_secret = totp_secret
        if clear_last_totp_step:
            subject.twofa_last_totp_step = None
        elif last_totp_step is not None:
            subject.twofa_last_totp_step = last_totp_step
        self.session.commit()
        self.session.refresh(subject)
        return subject

    def create_pending_action(self, *, subject_id: str, method: str, action: str, chat_id: int | None = None, secret: str | None = None, ttl_seconds: int = 300) -> TwoFAPendingActionModel:
        record = TwoFAPendingActionModel(
            id=uuid4().hex,
            subject_id=subject_id,
            chat_id=chat_id,
            method=method,
            action=action,
            status='pending',
            secret=secret,
            expires_at=datetime.now(UTC) + timedelta(seconds=ttl_seconds),
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def get_pending_action(self, pending_id: str) -> TwoFAPendingActionModel | None:
        return self.session.get(TwoFAPendingActionModel, pending_id)

    def save_pending_action(self, record: TwoFAPendingActionModel) -> TwoFAPendingActionModel:
        self.session.commit()
        self.session.refresh(record)
        return record

    def upsert_telegram_link(self, *, subject_id: str, chat_id: int, username: str | None) -> TelegramLinkModel:
        link = self.session.get(TelegramLinkModel, subject_id)
        if link is None:
            link = TelegramLinkModel(subject_id=subject_id, telegram_chat_id=chat_id, telegram_username=username)
            self.session.add(link)
        else:
            link.telegram_chat_id = chat_id
            link.telegram_username = username
        self.session.commit()
        self.session.refresh(link)
        return link

    def get_telegram_link_by_subject(self, subject_id: str) -> TelegramLinkModel | None:
        return self.session.get(TelegramLinkModel, subject_id)

    def get_telegram_link_by_chat(self, chat_id: int) -> TelegramLinkModel | None:
        return self.session.scalar(select(TelegramLinkModel).where(TelegramLinkModel.telegram_chat_id == chat_id))

    def create_twofa_session(self, *, subject_id: str, method: str) -> TwoFALoginSessionModel:
        record = TwoFALoginSessionModel(
            id=f'tfa_{uuid4().hex}',
            subject_id=subject_id,
            method=method,
            status='pending',
            attempts=0,
            sent_to_telegram=0,
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def get_twofa_session(self, session_id: str) -> TwoFALoginSessionModel | None:
        return self.session.get(TwoFALoginSessionModel, session_id)

    def save_twofa_session(self, record: TwoFALoginSessionModel) -> TwoFALoginSessionModel:
        self.session.commit()
        self.session.refresh(record)
        return record

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
