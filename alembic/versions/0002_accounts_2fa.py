from alembic import op
import sqlalchemy as sa
revision = '0002_accounts_2fa'
down_revision = '0001_initial_identity'
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.add_column('subjects', sa.Column('username', sa.String(length=64), nullable=True))
    op.add_column('subjects', sa.Column('password_hash', sa.String(length=512), nullable=True))
    op.add_column('subjects', sa.Column('display_name', sa.String(length=128), nullable=True))
    op.add_column('subjects', sa.Column('twofa_method', sa.String(length=16), nullable=False, server_default='none'))
    op.add_column('subjects', sa.Column('twofa_totp_secret', sa.String(length=128), nullable=True))
    op.add_column('subjects', sa.Column('twofa_last_totp_step', sa.Integer(), nullable=True))
    op.create_index('ix_subjects_username', 'subjects', ['username'], unique=True)
    op.create_table(
        'telegram_links',
        sa.Column('subject_id', sa.String(length=128), primary_key=True),
        sa.Column('telegram_chat_id', sa.BigInteger(), nullable=False),
        sa.Column('telegram_username', sa.String(length=64), nullable=True),
        sa.Column('linked_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_telegram_links_telegram_chat_id', 'telegram_links', ['telegram_chat_id'], unique=True)
    op.create_table(
        'twofa_login_sessions',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('subject_id', sa.String(length=128), nullable=False),
        sa.Column('method', sa.String(length=16), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('attempts', sa.Integer(), nullable=False),
        sa.Column('sent_to_telegram', sa.Integer(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_twofa_login_sessions_subject_id', 'twofa_login_sessions', ['subject_id'])

def downgrade() -> None:
    op.drop_index('ix_twofa_login_sessions_subject_id', table_name='twofa_login_sessions')
    op.drop_table('twofa_login_sessions')
    op.drop_index('ix_telegram_links_telegram_chat_id', table_name='telegram_links')
    op.drop_table('telegram_links')
    op.drop_index('ix_subjects_username', table_name='subjects')
    for column in ['twofa_last_totp_step','twofa_totp_secret','twofa_method','display_name','password_hash','username']:
        op.drop_column('subjects', column)
