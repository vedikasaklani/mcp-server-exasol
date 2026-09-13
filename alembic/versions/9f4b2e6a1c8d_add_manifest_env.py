"""Store per-server confinement environment variables."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "9f4b2e6a1c8d"
down_revision: Union[str, Sequence[str], None] = "f3a1c9d2e7b4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "server_manifests",
        sa.Column("env", sa.JSON(), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("server_manifests", "env")
