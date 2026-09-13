"""Add the discovered_tools catalog for the dashboard's tool discovery view."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "f3a1c9d2e7b4"
down_revision: Union[str, Sequence[str], None] = "e2f5b6c7d8e9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "discovered_tools",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("server_id", sa.String(), sa.ForeignKey("servers.server_id"), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("parameter_schema", sa.JSON(), nullable=True),
        sa.Column("source", sa.String(), nullable=False, server_default="observed"),
        sa.Column("first_seen_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now()),
        sa.UniqueConstraint("server_id", "name", name="uq_discovered_tools_server_name"),
    )
    op.create_index("ix_discovered_tools_server_id", "discovered_tools", ["server_id"])
    op.create_index("ix_discovered_tools_name", "discovered_tools", ["name"])


def downgrade() -> None:
    op.drop_index("ix_discovered_tools_name", table_name="discovered_tools")
    op.drop_index("ix_discovered_tools_server_id", table_name="discovered_tools")
    op.drop_table("discovered_tools")
