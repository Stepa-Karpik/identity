"""initial identity schema"""
from alembic import op
import sqlalchemy as sa
revision = '0001_initial_identity'
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table(
        'subjects',
        sa.Column('id', sa.String(length=128), primary_key=True),
        sa.Column('email', sa.String(length=320), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_subjects_email', 'subjects', ['email'], unique=True)
    op.create_table(
        'browser_sessions',
        sa.Column('id', sa.String(length=128), primary_key=True),
        sa.Column('subject_id', sa.String(length=128), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_browser_sessions_subject_id', 'browser_sessions', ['subject_id'])

def downgrade() -> None:
    op.drop_index('ix_browser_sessions_subject_id', table_name='browser_sessions')
    op.drop_table('browser_sessions')
    op.drop_index('ix_subjects_email', table_name='subjects')
    op.drop_table('subjects')
