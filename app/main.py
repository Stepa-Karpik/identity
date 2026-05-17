import html
import os
from typing import Annotated

import httpx
from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Response, status
from fastapi.responses import HTMLResponse
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
class LoginRequest(BaseModel):
    login: str
    password: str

@app.get('/healthz')
def healthz(): return {'status': 'ok', 'service': 'identity'}

@app.get('/login', response_class=HTMLResponse)
def login_page(return_to: str = 'https://planner.nerior.ru/'):
    safe_return_to = html.escape(return_to, quote=True)
    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Nerior — вход</title>
  <style>
    :root {{ color-scheme: dark; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; min-height: 100vh; font-family: Inter, ui-sans-serif, system-ui; background:
      radial-gradient(circle at top left, rgba(59,130,246,.28), transparent 34rem),
      radial-gradient(circle at bottom right, rgba(16,185,129,.16), transparent 28rem),
      #07090f; color: #f8fafc; display: grid; place-items: center; }}
    main {{ width: min(430px, calc(100vw - 32px)); border: 1px solid rgba(255,255,255,.12); background: rgba(15,23,42,.72);
      backdrop-filter: blur(18px); border-radius: 28px; padding: 28px; box-shadow: 0 24px 80px rgba(0,0,0,.42); }}
    small {{ color: #94a3b8; }}
    h1 {{ margin: 8px 0 22px; font-size: 28px; }}
    label {{ display: grid; gap: 8px; margin: 14px 0; color: #cbd5e1; font-size: 13px; }}
    input {{ height: 46px; border-radius: 14px; border: 1px solid rgba(255,255,255,.14); background: rgba(255,255,255,.04);
      color: white; padding: 0 14px; }}
    button {{ width: 100%; height: 46px; border: 0; border-radius: 14px; margin-top: 10px; font-weight: 700; cursor: pointer; }}
    p {{ color: #fca5a5; min-height: 20px; font-size: 13px; }}
  </style>
</head>
<body>
  <main>
    <small>Nerior ID</small>
    <h1>Войти в Nerior</h1>
    <form id="login-form">
      <input type="hidden" name="return_to" value="{safe_return_to}" />
      <label>Логин<input name="login" autocomplete="username" required /></label>
      <label>Пароль<input name="password" type="password" autocomplete="current-password" required /></label>
      <button>Войти</button>
      <p id="error"></p>
    </form>
  </main>
  <script>
    const form = document.getElementById('login-form');
    const error = document.getElementById('error');
    form.addEventListener('submit', async (event) => {{
      event.preventDefault();
      error.textContent = '';
      const data = new FormData(form);
      const response = await fetch('/api/v1/login', {{
        method: 'POST',
        credentials: 'include',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ login: data.get('login'), password: data.get('password') }})
      }});
      if (!response.ok) {{
        error.textContent = 'Не удалось войти. Проверьте логин и пароль.';
        return;
      }}
      const payload = await response.json();
      if (payload.requires_twofa) {{
        location.href = payload.legacy_login_url;
        return;
      }}
      location.href = data.get('return_to');
    }});
  </script>
</body>
</html>"""

def _proxy_planner_login(payload: LoginRequest):
    with httpx.Client(base_url=os.getenv('PLANNER_API_BASE_URL', 'http://planner-api:8000')) as client:
        return client.post('/api/v1/auth/login', json=payload.model_dump())

def _ensure_subject_and_session(session: Session, user_id: str, email: str) -> str:
    repo = IdentityRepository(session)
    repo.ensure_subject(subject_id=user_id, email=email)
    return repo.create_browser_session(subject_id=user_id).id

@app.post('/api/v1/login')
def login(payload: LoginRequest, response: Response, session: SessionDep):
    planner_response = _proxy_planner_login(payload)
    if planner_response.status_code >= 400:
        raise HTTPException(status_code=planner_response.status_code, detail='planner login failed')
    data = planner_response.json().get('data') or {}
    if data.get('requires_twofa'):
        return {'requires_twofa': True, 'legacy_login_url': 'https://planner.nerior.ru/login?legacy=1'}
    user_id, email = data.get('user_id'), data.get('email')
    if not user_id or not email:
        raise HTTPException(status_code=502, detail='invalid planner login response')
    session_id = _ensure_subject_and_session(session, user_id, email)
    response.set_cookie(COOKIE_NAME, session_id, httponly=True, secure=COOKIE_SECURE, samesite='lax', domain=COOKIE_DOMAIN, path='/')
    return {'ok': True, 'subject_id': user_id}

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
