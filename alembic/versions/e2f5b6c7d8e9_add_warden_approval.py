"""Persist the human approval metadata for Warden profiles."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "e2f5b6c7d8e9"
down_revision: Union[str, Sequence[str], None] = "d1e4f6a7b8c9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("server_manifests", sa.Column("warden_profile_path", sa.String(), nullable=True))
    op.add_column("server_manifests", sa.Column("warden_approved_by", sa.String(), nullable=True))
    op.add_column("server_manifests", sa.Column("warden_approved_at", sa.DateTime(), nullable=True))
    op.add_column("server_manifests", sa.Column("warden_approved_commit", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("server_manifests", "warden_approved_commit")
    op.drop_column("server_manifests", "warden_approved_at")
    op.drop_column("server_manifests", "warden_approved_by")
    op.drop_column("server_manifests", "warden_profile_path")
