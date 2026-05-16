import os
from typing import Annotated

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db import get_session
from app.repositories import IdentityRepository

app = FastAPI(title='identity')
COOKIE_NAME = 'ecosystem_session'
COOKIE_DOMAIN = os.getenv('IDENTITY_COOKIE_DOMAIN') or None
COOKIE_SECURE = os.getenv('IDENTITY_COOKIE_SECURE', 'false').lower() == 'true'
INTERNAL_API_KEY = os.getenv('IDENTITY_INTERNAL_API_KEY', 'dev-internal-key')
SessionDep = Annotated[Session, Depends(get_session)]

class SubjectCreate(BaseModel):
    email: str
class SessionCreate(BaseModel):
    subject_id: str
    email: str | None = None

@app.get('/healthz')
def healthz(): return {'status': 'ok', 'service': 'identity'}

@app.post('/api/v1/subjects', status_code=status.HTTP_201_CREATED)
def create_subject(payload: SubjectCreate, session: SessionDep):
    subject = IdentityRepository(session).create_subject(email=payload.email)
    return {'subject_id': subject.id, 'email': subject.email}

@app.post('/api/v1/sessions', status_code=status.HTTP_201_CREATED)
def create_session(payload: SessionCreate, session: SessionDep):
    repo = IdentityRepository(session)
    if repo.get_subject(payload.subject_id) is None:
        raise HTTPException(status_code=404, detail='subject not found')
    browser_session = repo.create_browser_session(subject_id=payload.subject_id)
    return {'session_id': browser_session.id, 'subject_id': browser_session.subject_id}

@app.post('/api/v1/browser-sessions', status_code=status.HTTP_201_CREATED)
def create_browser_session(payload: SessionCreate, response: Response, session: SessionDep):
    repo = IdentityRepository(session)
    if repo.get_subject(payload.subject_id) is None:
        raise HTTPException(status_code=404, detail='subject not found')
    browser_session = repo.create_browser_session(subject_id=payload.subject_id)
    response.set_cookie(COOKIE_NAME, browser_session.id, httponly=True, secure=COOKIE_SECURE, samesite='lax', domain=COOKIE_DOMAIN, path='/')
    return {'session_id': browser_session.id, 'subject_id': browser_session.subject_id}

@app.post('/api/v1/session-exchange')
def exchange_session(session: SessionDep, ecosystem_session: str | None = Cookie(default=None)):
    browser_session = IdentityRepository(session).get_active_browser_session(ecosystem_session or '')
    if browser_session is None:
        raise HTTPException(status_code=401, detail='invalid session')
    return {'subject_id': browser_session.subject_id, 'access_token': f'access_{browser_session.id}'}

@app.post('/api/v1/logout')
def logout(response: Response, session: SessionDep, ecosystem_session: str | None = Cookie(default=None)):
    if ecosystem_session:
        IdentityRepository(session).revoke_browser_session(ecosystem_session)
    response.delete_cookie(COOKIE_NAME, domain=COOKIE_DOMAIN, path='/')
    return {'ok': True}

@app.post('/api/v1/internal/browser-sessions', status_code=status.HTTP_201_CREATED)
def mint_internal_browser_session(payload: SessionCreate, session: SessionDep, x_internal_key: str | None = Header(default=None)):
    if x_internal_key != INTERNAL_API_KEY:
        raise HTTPException(status_code=401, detail='invalid internal key')
    repo = IdentityRepository(session)
    if repo.get_subject(payload.subject_id) is None:
        repo.ensure_subject(subject_id=payload.subject_id, email=payload.email or f'{payload.subject_id}@legacy.local')
    browser_session = repo.create_browser_session(subject_id=payload.subject_id)
    return {'session_id': browser_session.id, 'subject_id': browser_session.subject_id}
