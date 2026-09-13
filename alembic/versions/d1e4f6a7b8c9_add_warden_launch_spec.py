"""Store the user-supplied Warden launch specification."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d1e4f6a7b8c9"
down_revision: Union[str, Sequence[str], None] = "c8e3f1a2b4d6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("server_manifests", sa.Column("launch_executable", sa.String(), nullable=True))
    op.add_column(
        "server_manifests",
        sa.Column("launch_args", sa.JSON(), nullable=False, server_default="[]"),
    )


def downgrade() -> None:
    op.drop_column("server_manifests", "launch_args")
    op.drop_column("server_manifests", "launch_executable")
