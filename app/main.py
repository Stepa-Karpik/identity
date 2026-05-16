import os
from uuid import uuid4
from fastapi import Cookie, FastAPI, Header, HTTPException, Response, status
from pydantic import BaseModel

app = FastAPI(title="identity")
subjects: dict[str, str] = {}
sessions: dict[str, str] = {}
COOKIE_NAME = 'ecosystem_session'
COOKIE_DOMAIN = os.getenv('IDENTITY_COOKIE_DOMAIN') or None
COOKIE_SECURE = os.getenv('IDENTITY_COOKIE_SECURE', 'false').lower() == 'true'
INTERNAL_API_KEY = os.getenv('IDENTITY_INTERNAL_API_KEY', 'dev-internal-key')

class SubjectCreate(BaseModel):
    email: str
class SessionCreate(BaseModel):
    subject_id: str

@app.get('/healthz')
def healthz(): return {'status': 'ok', 'service': 'identity'}

@app.post('/api/v1/subjects', status_code=status.HTTP_201_CREATED)
def create_subject(payload: SubjectCreate):
    subject_id = f'usr_{uuid4().hex}'
    subjects[subject_id] = payload.email
    return {'subject_id': subject_id, 'email': payload.email}

@app.post('/api/v1/sessions', status_code=status.HTTP_201_CREATED)
def create_session(payload: SessionCreate):
    session_id = f'sess_{uuid4().hex}'
    sessions[session_id] = payload.subject_id
    return {'session_id': session_id, 'subject_id': payload.subject_id}

@app.post('/api/v1/browser-sessions', status_code=status.HTTP_201_CREATED)
def create_browser_session(payload: SessionCreate, response: Response):
    session_id = f'sess_{uuid4().hex}'
    sessions[session_id] = payload.subject_id
    response.set_cookie(COOKIE_NAME, session_id, httponly=True, secure=COOKIE_SECURE, samesite='lax', domain=COOKIE_DOMAIN, path='/')
    return {'session_id': session_id, 'subject_id': payload.subject_id}

@app.post('/api/v1/session-exchange')
def exchange_session(ecosystem_session: str | None = Cookie(default=None)):
    subject_id = sessions.get(ecosystem_session or '')
    if subject_id is None:
        raise HTTPException(status_code=401, detail='invalid session')
    return {'subject_id': subject_id, 'access_token': f'access_{uuid4().hex}'}

@app.post('/api/v1/logout')
def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, domain=COOKIE_DOMAIN, path='/')
    return {'ok': True}


@app.post('/api/v1/internal/browser-sessions', status_code=status.HTTP_201_CREATED)
def mint_internal_browser_session(payload: SessionCreate, x_internal_key: str | None = Header(default=None)):
    if x_internal_key != INTERNAL_API_KEY:
        raise HTTPException(status_code=401, detail='invalid internal key')
    session_id = f'sess_{uuid4().hex}'
    sessions[session_id] = payload.subject_id
    return {'session_id': session_id, 'subject_id': payload.subject_id}
