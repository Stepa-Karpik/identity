"""twofa pending actions"""
from alembic import op
import sqlalchemy as sa

revision = '0003_twofa_pending_actions'
down_revision = '0002_accounts_2fa'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'twofa_pending_actions',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('subject_id', sa.String(length=128), nullable=False),
        sa.Column('chat_id', sa.BigInteger(), nullable=True),
        sa.Column('method', sa.String(length=16), nullable=False),
        sa.Column('action', sa.String(length=24), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False, server_default='pending'),
        sa.Column('secret', sa.String(length=128), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_twofa_pending_actions_subject_id', 'twofa_pending_actions', ['subject_id'])


def downgrade() -> None:
    op.drop_index('ix_twofa_pending_actions_subject_id', table_name='twofa_pending_actions')
    op.drop_table('twofa_pending_actions')
