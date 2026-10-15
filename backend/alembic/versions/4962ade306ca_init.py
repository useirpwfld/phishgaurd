"""init

Revision ID: 4962ade306ca
Revises:
Create Date: 2026-02-11 17:55:31.745905

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '4962ade306ca'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'scan_results',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('url', sa.String(length=2048), nullable=False),
        sa.Column('score', sa.Integer(), nullable=False),
        sa.Column('verdict', sa.String(length=32), nullable=False),
        sa.Column('reason', sa.String(length=1024), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scan_results_id'), 'scan_results', ['id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_scan_results_id'), table_name='scan_results')
    op.drop_table('scan_results')
