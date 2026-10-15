"""add probability columns

Revision ID: 8f2a1d9b7c3e
Revises: 5dbd3ec5d0c2
Create Date: 2026-03-22 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '8f2a1d9b7c3e'
down_revision: Union[str, Sequence[str], None] = '5dbd3ec5d0c2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('scan_results', sa.Column('ml_proba', sa.Float(), nullable=True))
    op.add_column('scan_results', sa.Column('ml_proba_local', sa.Float(), nullable=True))
    op.add_column('scan_results', sa.Column('ml_proba_public', sa.Float(), nullable=True))


def downgrade() -> None:
    op.drop_column('scan_results', 'ml_proba_public')
    op.drop_column('scan_results', 'ml_proba_local')
    op.drop_column('scan_results', 'ml_proba')
