from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from app.repositories import IdentityRepository


@dataclass(slots=True)
class MigrationStats:
    users: int = 0
    telegram_links: int = 0


def migrate_from_planner_database(identity_session: Session, *, planner_database_url: str | None = None) -> MigrationStats:
    url = planner_database_url or os.getenv('PLANNER_DATABASE_URL') or os.getenv('DATABASE_URL')
    if not url:
        raise RuntimeError('PLANNER_DATABASE_URL is required')
    url = url.replace('postgresql+asyncpg://', 'postgresql+psycopg://')
    engine = create_engine(url)
    repo = IdentityRepository(identity_session)
    stats = MigrationStats()
    with engine.connect() as conn:
        users: Iterable[dict] = conn.execute(text('''
            select id::text as id, email, username, display_name, password_hash,
                   coalesce(twofa_method, 'none') as twofa_method,
                   twofa_totp_secret, twofa_last_totp_step
            from users
        ''')).mappings()
        for user in users:
            repo.upsert_account(
                subject_id=user['id'],
                email=user['email'],
                username=user['username'],
                display_name=user['display_name'],
                password_hash=user['password_hash'],
                twofa_method=user['twofa_method'] or 'none',
                twofa_totp_secret=user['twofa_totp_secret'],
                twofa_last_totp_step=user['twofa_last_totp_step'],
            )
            stats.users += 1
        links: Iterable[dict] = conn.execute(text('''
            select user_id::text as user_id, telegram_chat_id, telegram_username
            from telegram_links
            where is_confirmed = true
        ''')).mappings()
        for link in links:
            repo.upsert_telegram_link(subject_id=link['user_id'], chat_id=int(link['telegram_chat_id']), username=link['telegram_username'])
            stats.telegram_links += 1
    return stats
