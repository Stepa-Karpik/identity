from app.db import SessionLocal
from app.planner_migration import migrate_from_planner_database

with SessionLocal() as session:
    stats = migrate_from_planner_database(session)
print({'users': stats.users, 'telegram_links': stats.telegram_links})
