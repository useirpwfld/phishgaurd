"""add label column to scan_results

Revision ID: 5dbd3ec5d0c2
Revises: 2b57c0cff6ba
Create Date: 2026-02-12 18:37:57.011182

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5dbd3ec5d0c2'
down_revision: Union[str, Sequence[str], None] = '2b57c0cff6ba'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scan_results", sa.Column("label", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("scan_results", "label")
