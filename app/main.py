import html
import os
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Response, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db import get_session
from app.planner_migration import migrate_from_planner_database
from app.repositories import IdentityRepository
from app.security import generate_totp_secret, verify_password, verify_totp
from app import twofa as twofa_client

app = FastAPI(title='identity')
COOKIE_NAME = 'ecosystem_session'
COOKIE_DOMAIN = os.getenv('IDENTITY_COOKIE_DOMAIN') or None
COOKIE_SECURE = os.getenv('IDENTITY_COOKIE_SECURE', 'false').lower() == 'true'
INTERNAL_API_KEY = os.getenv('IDENTITY_INTERNAL_API_KEY', 'dev-internal-key')
SessionDep = Annotated[Session, Depends(get_session)]

class SubjectCreate(BaseModel): email: str
class SessionCreate(BaseModel): subject_id: str; email: str | None = None
class LoginRequest(BaseModel): login: str; password: str
class TotpVerifyRequest(BaseModel): twofa_session_id: str; code: str
class TelegramSessionRequest(BaseModel): twofa_session_id: str
class TelegramCallbackRequest(BaseModel): chat_id: int; twofa_session_id: str; decision: Literal['approve','deny']
class TwoFASetMethodRequest(BaseModel): method: Literal['none','telegram','totp']
class TotpSetupVerifyRequest(BaseModel): pending_id: str; code: str
class TotpDisableRequest(BaseModel): code: str
class AccountUpsert(BaseModel):
    subject_id: str; email: str; username: str | None = None; password_hash: str | None = None; display_name: str | None = None
    twofa_method: str = 'none'; twofa_totp_secret: str | None = None; twofa_last_totp_step: int | None = None
class TelegramLinkUpsert(BaseModel): subject_id: str; chat_id: int; username: str | None = None

@app.get('/healthz')
def healthz(): return {'status': 'ok', 'service': 'identity'}

@app.get('/login', response_class=HTMLResponse)
def login_page(return_to: str = 'https://planner.nerior.ru/'):
    safe_return_to = html.escape(return_to, quote=True)
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Nerior — вход</title><style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;font-family:Inter,ui-sans-serif,system-ui;background:radial-gradient(circle at top left,rgba(59,130,246,.28),transparent 34rem),radial-gradient(circle at bottom right,rgba(16,185,129,.16),transparent 28rem),#07090f;color:#f8fafc;display:grid;place-items:center}}main{{width:min(430px,calc(100vw - 32px));border:1px solid rgba(255,255,255,.12);background:rgba(15,23,42,.72);backdrop-filter:blur(18px);border-radius:28px;padding:28px;box-shadow:0 24px 80px rgba(0,0,0,.42)}}small{{color:#94a3b8}}h1{{margin:8px 0 22px;font-size:28px}}label{{display:grid;gap:8px;margin:14px 0;color:#cbd5e1;font-size:13px}}input{{height:46px;border-radius:14px;border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.04);color:white;padding:0 14px}}button{{width:100%;height:46px;border:0;border-radius:14px;margin-top:10px;font-weight:700;cursor:pointer}}p{{color:#fca5a5;min-height:20px;font-size:13px}}.hidden{{display:none}}</style></head><body><main>
<small>Nerior ID</small><h1 id="title">Войти в Nerior</h1>
<form id="login-form"><input type="hidden" name="return_to" value="{safe_return_to}"/><label>Логин<input name="login" autocomplete="username" required/></label><label>Пароль<input name="password" type="password" autocomplete="current-password" required/></label><button>Войти</button></form>
<form id="totp-form" class="hidden"><label>Код из приложения<input name="code" inputmode="numeric" autocomplete="one-time-code"/></label><button>Подтвердить</button></form>
<section id="telegram-box" class="hidden"><p style="color:#cbd5e1">Подтвердите вход в Telegram. Эта страница завершит вход автоматически.</p><button id="telegram-request">Отправить подтверждение ещё раз</button></section>
<p id="error"></p>
</main><script>
const loginForm=document.getElementById('login-form'),totpForm=document.getElementById('totp-form'),telegramBox=document.getElementById('telegram-box'),requestBtn=document.getElementById('telegram-request'),error=document.getElementById('error'),title=document.getElementById('title');let challenge=null;let returnTo=new FormData(loginForm).get('return_to');
function normalizeReturnTo(value){{try{{const u=new URL(value||'https://planner.nerior.ru/today', location.href);if(u.hostname==='auth.nerior.ru')return 'https://planner.nerior.ru/today';return u.href}}catch{{return 'https://planner.nerior.ru/today'}}}}
function fail(t){{error.textContent=t||'Ошибка входа'}}function finish(){{location.href=normalizeReturnTo(returnTo)}}
loginForm.addEventListener('submit',async e=>{{e.preventDefault();error.textContent='';const d=new FormData(loginForm);const r=await fetch('/api/v1/login',{{method:'POST',credentials:'include',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{login:d.get('login'),password:d.get('password')}})}});if(!r.ok)return fail('Не удалось войти. Проверьте логин и пароль.');const p=await r.json();if(!p.requires_twofa)return finish();challenge=p;loginForm.classList.add('hidden');title.textContent='Двухфакторная аутентификация';if(p.twofa_method==='totp')totpForm.classList.remove('hidden');else{{telegramBox.classList.remove('hidden');await requestTelegram();pollTelegram();}}}});
totpForm.addEventListener('submit',async e=>{{e.preventDefault();const code=new FormData(totpForm).get('code');const r=await fetch('/api/v1/twofa/totp/verify',{{method:'POST',credentials:'include',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{twofa_session_id:challenge.twofa_session_id,code}})}});if(!r.ok)return fail('Неверный код или сессия истекла.');finish();}});
async function requestTelegram(){{await fetch('/api/v1/twofa/telegram/request',{{method:'POST',credentials:'include',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{twofa_session_id:challenge.twofa_session_id}})}})}}
requestBtn.addEventListener('click',requestTelegram);
function pollTelegram(){{const timer=setInterval(async()=>{{const s=await fetch('/api/v1/twofa/session/'+challenge.twofa_session_id,{{credentials:'include'}});if(!s.ok){{clearInterval(timer);return fail('Сессия 2FA истекла.')}}const p=await s.json();if(p.status==='approved'){{clearInterval(timer);const c=await fetch('/api/v1/twofa/telegram/complete',{{method:'POST',credentials:'include',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{twofa_session_id:challenge.twofa_session_id}})}});if(c.ok)finish();else fail('Не удалось завершить вход.')}}if(p.status==='denied'||p.status==='expired'){{clearInterval(timer);fail('Вход отклонён или сессия истекла.')}}}},2000)}}
</script></body></html>"""

def _set_cookie(response: Response, session_id: str) -> None:
    response.set_cookie(COOKIE_NAME, session_id, httponly=True, secure=COOKIE_SECURE, samesite='lax', domain=COOKIE_DOMAIN, path='/')

def _mint_session(response: Response, repo: IdentityRepository, subject_id: str) -> dict:
    browser_session = repo.create_browser_session(subject_id=subject_id)
    _set_cookie(response, browser_session.id)
    return {'ok': True, 'subject_id': subject_id}



def _require_internal(x_internal_key: str | None) -> None:
    if x_internal_key != INTERNAL_API_KEY:
        raise HTTPException(status_code=401, detail='invalid internal key')


def _normalize_twofa_method(value: str | None) -> str:
    value = (value or 'none').lower()
    return value if value in {'none', 'telegram', 'totp'} else 'none'


def _settings_payload(repo: IdentityRepository, subject_id: str) -> dict:
    subject = repo.get_subject(subject_id)
    if subject is None:
        raise HTTPException(status_code=404, detail='subject not found')
    link = repo.get_telegram_link_by_subject(subject_id)
    return {
        'twofa_method': _normalize_twofa_method(subject.twofa_method),
        'telegram_linked': link is not None,
        'telegram_confirmed': link is not None,
        'totp_enabled': bool(subject.twofa_totp_secret),
    }


def _pending_payload(pending) -> dict:
    return {
        'pending_id': pending.id,
        'method': pending.method,
        'action': pending.action,
        'status': pending.status,
        'expires_at': pending.expires_at.isoformat(),
    }


def _expire_pending_if_needed(repo: IdentityRepository, pending):
    if pending.status == 'pending' and _as_utc(pending.expires_at) < datetime.now(UTC):
        pending.status = 'expired'
        repo.save_pending_action(pending)
    return pending


def _normalize_code(code: str) -> str:
    digits = ''.join(ch for ch in str(code) if ch.isdigit())
    if len(digits) != 6:
        raise HTTPException(status_code=400, detail='totp code must contain 6 digits')
    return digits

@app.post('/api/v1/login')
def login(payload: LoginRequest, response: Response, session: SessionDep):
    repo = IdentityRepository(session)
    subject = repo.get_subject_by_login(payload.login)
    if subject is None or not subject.password_hash or not verify_password(payload.password, subject.password_hash):
        raise HTTPException(status_code=401, detail='invalid credentials')
    method = (subject.twofa_method or 'none').lower()
    if method in {'totp','telegram'}:
        twofa = repo.create_twofa_session(subject_id=subject.id, method=method)
        return {'requires_twofa': True, 'twofa_method': method, 'twofa_session_id': twofa.id, 'expires_at': twofa.expires_at.isoformat()}
    return _mint_session(response, repo, subject.id)

@app.post('/api/v1/twofa/totp/verify')
def verify_login_totp(payload: TotpVerifyRequest, response: Response, session: SessionDep):
    repo = IdentityRepository(session)
    twofa = repo.get_twofa_session(payload.twofa_session_id)
    if twofa is None or twofa.status != 'pending' or twofa.method != 'totp' or _as_utc(twofa.expires_at) < datetime.now(UTC):
        raise HTTPException(status_code=400, detail='invalid twofa session')
    subject = repo.get_subject(twofa.subject_id)
    if subject is None or not subject.twofa_totp_secret:
        raise HTTPException(status_code=400, detail='totp not configured')
    twofa.attempts += 1
    ok, step = verify_totp(subject.twofa_totp_secret, payload.code)
    if not ok or step is None or (subject.twofa_last_totp_step is not None and step <= subject.twofa_last_totp_step):
        repo.save_twofa_session(twofa)
        raise HTTPException(status_code=400, detail='invalid code')
    repo.update_last_totp_step(subject.id, step)
    twofa.status = 'used'; repo.save_twofa_session(twofa)
    return _mint_session(response, repo, subject.id)

@app.post('/api/v1/twofa/telegram/request')
def request_login_telegram(payload: TelegramSessionRequest, session: SessionDep):
    repo = IdentityRepository(session)
    twofa = repo.get_twofa_session(payload.twofa_session_id)
    if twofa is None or twofa.status != 'pending' or twofa.method != 'telegram' or _as_utc(twofa.expires_at) < datetime.now(UTC):
        raise HTTPException(status_code=400, detail='invalid twofa session')
    link = repo.get_telegram_link_by_subject(twofa.subject_id)
    if link is None:
        raise HTTPException(status_code=400, detail='telegram not linked')
    twofa_client.send_telegram_message(link.telegram_chat_id, 'Подтвердите вход в Nerior', twofa.id)
    twofa.sent_to_telegram = 1; repo.save_twofa_session(twofa)
    return _twofa_session_dict(twofa)

@app.get('/api/v1/twofa/session/{twofa_session_id}')
def get_twofa_session(twofa_session_id: str, session: SessionDep):
    twofa = IdentityRepository(session).get_twofa_session(twofa_session_id)
    if twofa is None:
        raise HTTPException(status_code=404, detail='twofa session not found')
    if twofa.status == 'pending' and _as_utc(twofa.expires_at) < datetime.now(UTC):
        twofa.status = 'expired'; IdentityRepository(session).save_twofa_session(twofa)
    return _twofa_session_dict(twofa)

@app.post('/api/v1/twofa/telegram/complete')
def complete_login_telegram(payload: TelegramSessionRequest, response: Response, session: SessionDep):
    repo = IdentityRepository(session)
    twofa = repo.get_twofa_session(payload.twofa_session_id)
    if twofa is None or twofa.method != 'telegram' or twofa.status != 'approved':
        raise HTTPException(status_code=400, detail='telegram confirmation is not approved')
    twofa.status = 'used'; repo.save_twofa_session(twofa)
    return _mint_session(response, repo, twofa.subject_id)

@app.post('/api/v1/internal/twofa/telegram/callback')
def internal_telegram_callback(payload: TelegramCallbackRequest, session: SessionDep, x_internal_key: str | None = Header(default=None)):
    if x_internal_key != INTERNAL_API_KEY:
        raise HTTPException(status_code=401, detail='invalid internal key')
    repo = IdentityRepository(session)
    twofa = repo.get_twofa_session(payload.twofa_session_id)
    if twofa is not None:
        if twofa.method != 'telegram':
            return {'status': 'expired'}
        link = repo.get_telegram_link_by_subject(twofa.subject_id)
        if link is None or int(link.telegram_chat_id) != int(payload.chat_id):
            raise HTTPException(status_code=401, detail='telegram chat mismatch')
        if twofa.status == 'pending':
            twofa.status = 'approved' if payload.decision == 'approve' else 'denied'
            repo.save_twofa_session(twofa)
        return {'status': twofa.status}

    pending = repo.get_pending_action(payload.twofa_session_id)
    if pending is None or pending.method != 'telegram':
        return {'status': 'expired'}
    pending = _expire_pending_if_needed(repo, pending)
    if pending.status != 'pending':
        return _pending_payload(pending)
    if int(pending.chat_id or 0) != int(payload.chat_id):
        raise HTTPException(status_code=401, detail='telegram chat mismatch')
    if payload.decision == 'deny':
        pending.status = 'denied'; repo.save_pending_action(pending); return _pending_payload(pending)
    subject = repo.get_subject(pending.subject_id)
    if subject is None:
        return {'status': 'expired'}
    if pending.action == 'enable':
        repo.update_twofa_settings(subject, method='telegram')
    elif pending.action == 'disable':
        repo.update_twofa_settings(subject, method='none')
    pending.status = 'approved'; repo.save_pending_action(pending)
    return _pending_payload(pending)



@app.get('/api/v1/internal/accounts/{subject_id}/twofa')
def internal_get_twofa_settings(subject_id: str, session: SessionDep, x_internal_key: str | None = Header(default=None)):
    _require_internal(x_internal_key)
    return _settings_payload(IdentityRepository(session), subject_id)


@app.post('/api/v1/internal/accounts/{subject_id}/twofa/method')
def internal_set_twofa_method(subject_id: str, payload: TwoFASetMethodRequest, session: SessionDep, x_internal_key: str | None = Header(default=None)):
    _require_internal(x_internal_key)
    repo = IdentityRepository(session)
    subject = repo.get_subject(subject_id)
    if subject is None:
        raise HTTPException(status_code=404, detail='subject not found')
    method = _normalize_twofa_method(payload.method)
    if method == 'telegram' and repo.get_telegram_link_by_subject(subject_id) is None:
        raise HTTPException(status_code=400, detail='telegram not linked')
    if method == 'totp' and not subject.twofa_totp_secret:
        raise HTTPException(status_code=400, detail='totp not configured')
    repo.update_twofa_settings(subject, method=method)
    return {'ok': True}


@app.post('/api/v1/internal/accounts/{subject_id}/twofa/totp/setup')
def internal_totp_setup(subject_id: str, session: SessionDep, x_internal_key: str | None = Header(default=None)):
    _require_internal(x_internal_key)
    repo = IdentityRepository(session)
    subject = repo.get_subject(subject_id)
    if subject is None:
        raise HTTPException(status_code=404, detail='subject not found')
    secret = generate_totp_secret()
    pending = repo.create_pending_action(subject_id=subject_id, method='totp', action='setup', secret=secret)
    issuer = 'Nerior'
    account = subject.email or subject.username or subject.id
    from urllib.parse import quote
    return {'pending_id': pending.id, 'secret': secret, 'otpauth_uri': f'otpauth://totp/{quote(issuer + ":" + account)}?secret={quote(secret)}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30', 'expires_at': pending.expires_at.isoformat()}


@app.post('/api/v1/internal/accounts/{subject_id}/twofa/totp/verify-setup')
def internal_totp_verify_setup(subject_id: str, payload: TotpSetupVerifyRequest, session: SessionDep, x_internal_key: str | None = Header(default=None)):
    _require_internal(x_internal_key)
    repo = IdentityRepository(session)
    pending = repo.get_pending_action(payload.pending_id)
    if pending is None or pending.subject_id != subject_id or pending.method != 'totp' or pending.action != 'setup':
        raise HTTPException(status_code=400, detail='invalid pending action')
    pending = _expire_pending_if_needed(repo, pending)
    if pending.status != 'pending' or not pending.secret:
        raise HTTPException(status_code=400, detail='pending action expired')
    ok, _ = verify_totp(pending.secret, _normalize_code(payload.code))
    if not ok:
        raise HTTPException(status_code=400, detail='invalid totp code')
    subject = repo.get_subject(subject_id)
    if subject is None:
        raise HTTPException(status_code=404, detail='subject not found')
    repo.update_twofa_settings(subject, method='totp', totp_secret=pending.secret, clear_last_totp_step=True)
    pending.status = 'approved'; repo.save_pending_action(pending)
    return {'ok': True}


@app.post('/api/v1/internal/accounts/{subject_id}/twofa/totp/disable')
def internal_totp_disable(subject_id: str, payload: TotpDisableRequest, session: SessionDep, x_internal_key: str | None = Header(default=None)):
    _require_internal(x_internal_key)
    repo = IdentityRepository(session)
    subject = repo.get_subject(subject_id)
    if subject is None or not subject.twofa_totp_secret:
        raise HTTPException(status_code=400, detail='totp not configured')
    ok, step = verify_totp(subject.twofa_totp_secret, _normalize_code(payload.code))
    if not ok or step is None or (subject.twofa_last_totp_step is not None and step <= subject.twofa_last_totp_step):
        raise HTTPException(status_code=400, detail='invalid totp code')
    method = 'none' if _normalize_twofa_method(subject.twofa_method) == 'totp' else None
    repo.update_twofa_settings(subject, method=method, clear_totp_secret=True, last_totp_step=step)
    return {'ok': True}


@app.post('/api/v1/internal/accounts/{subject_id}/twofa/telegram/{action}-request')
def internal_telegram_settings_request(subject_id: str, action: Literal['enable','disable'], session: SessionDep, x_internal_key: str | None = Header(default=None)):
    _require_internal(x_internal_key)
    repo = IdentityRepository(session)
    subject = repo.get_subject(subject_id)
    if subject is None:
        raise HTTPException(status_code=404, detail='subject not found')
    link = repo.get_telegram_link_by_subject(subject_id)
    if link is None:
        raise HTTPException(status_code=400, detail='telegram not linked')
    if action == 'enable' and _normalize_twofa_method(subject.twofa_method) == 'telegram':
        raise HTTPException(status_code=400, detail='telegram 2fa already enabled')
    if action == 'disable' and _normalize_twofa_method(subject.twofa_method) != 'telegram':
        raise HTTPException(status_code=400, detail='telegram 2fa is not enabled')
    pending = repo.create_pending_action(subject_id=subject_id, method='telegram', action=action, chat_id=int(link.telegram_chat_id))
    twofa_client.send_telegram_settings_message(int(link.telegram_chat_id), action, pending.id)
    return _pending_payload(pending)


@app.get('/api/v1/internal/accounts/{subject_id}/twofa/pending/{pending_id}')
def internal_twofa_pending_status(subject_id: str, pending_id: str, session: SessionDep, x_internal_key: str | None = Header(default=None)):
    _require_internal(x_internal_key)
    repo = IdentityRepository(session)
    pending = repo.get_pending_action(pending_id)
    if pending is None:
        return {'pending_id': pending_id, 'method': 'telegram', 'action': 'unknown', 'status': 'expired', 'expires_at': None}
    if pending.subject_id != subject_id:
        raise HTTPException(status_code=401, detail='pending action does not belong to subject')
    pending = _expire_pending_if_needed(repo, pending)
    return _pending_payload(pending)

@app.post('/api/v1/internal/accounts')
def upsert_account(payload: AccountUpsert, session: SessionDep, x_internal_key: str | None = Header(default=None)):
    if x_internal_key != INTERNAL_API_KEY:
        raise HTTPException(status_code=401, detail='invalid internal key')
    subject = IdentityRepository(session).upsert_account(**payload.model_dump())
    return {'subject_id': subject.id, 'email': subject.email}

@app.post('/api/v1/internal/telegram-links')
def upsert_telegram_link(payload: TelegramLinkUpsert, session: SessionDep, x_internal_key: str | None = Header(default=None)):
    if x_internal_key != INTERNAL_API_KEY:
        raise HTTPException(status_code=401, detail='invalid internal key')
    link = IdentityRepository(session).upsert_telegram_link(subject_id=payload.subject_id, chat_id=payload.chat_id, username=payload.username)
    return {'subject_id': link.subject_id, 'telegram_chat_id': link.telegram_chat_id}

@app.post('/api/v1/internal/migrate-from-planner')
def migrate_from_planner(session: SessionDep, x_internal_key: str | None = Header(default=None)):
    if x_internal_key != INTERNAL_API_KEY:
        raise HTTPException(status_code=401, detail='invalid internal key')
    stats = migrate_from_planner_database(session)
    return {'users': stats.users, 'telegram_links': stats.telegram_links}

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
        repo.ensure_subject(subject_id=payload.subject_id, email=payload.email or f'{payload.subject_id}@legacy.local')
    return _mint_session(response, repo, payload.subject_id)

@app.post('/api/v1/session-exchange')
def exchange_session(session: SessionDep, ecosystem_session: str | None = Cookie(default=None)):
    repo = IdentityRepository(session)
    browser_session = repo.get_active_browser_session(ecosystem_session or '')
    if browser_session is None:
        raise HTTPException(status_code=401, detail='invalid session')
    subject = repo.get_subject(browser_session.subject_id)
    return {
        'subject_id': browser_session.subject_id,
        'access_token': f'access_{browser_session.id}',
        'email': getattr(subject, 'email', None),
        'username': getattr(subject, 'username', None),
        'display_name': getattr(subject, 'display_name', None),
    }

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

def _as_utc(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value

def _twofa_session_dict(twofa):
    return {'twofa_session_id': twofa.id, 'twofa_method': twofa.method, 'status': twofa.status, 'expires_at': twofa.expires_at.isoformat(), 'sent_to_telegram': bool(twofa.sent_to_telegram)}
