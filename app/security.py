from __future__ import annotations

import base64
import hmac
import secrets
import struct
import time
from hashlib import sha1

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError):
        return False


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')


def _totp_counter(now: int | None = None, period: int = 30) -> int:
    return int((now if now is not None else time.time()) // period)


def totp_code(secret: str, *, counter: int | None = None) -> str:
    padded = secret + '=' * (-len(secret) % 8)
    key = base64.b32decode(padded, casefold=True)
    msg = struct.pack('>Q', counter if counter is not None else _totp_counter())
    digest = hmac.new(key, msg, sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f'{value % 1_000_000:06d}'


def verify_totp(secret: str, code: str, *, window: int = 1) -> tuple[bool, int | None]:
    normalized = ''.join(ch for ch in code if ch.isdigit())
    current = _totp_counter()
    for counter in range(current - window, current + window + 1):
        if hmac.compare_digest(totp_code(secret, counter=counter), normalized):
            return True, counter
    return False, None
