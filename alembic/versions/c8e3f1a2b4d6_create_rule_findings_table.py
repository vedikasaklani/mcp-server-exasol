"""Create the normalized rule findings table."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c8e3f1a2b4d6"
down_revision: Union[str, Sequence[str], None] = "b7f2c8d4e1a0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create rule_findings and remove the former JSON column."""
    op.create_table(
        "rule_findings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_run_id", sa.String(), nullable=False),
        sa.Column("server_id", sa.String(), nullable=False),
        sa.Column("analyzer", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("rule_id", sa.String(), nullable=True),
        sa.Column("file", sa.String(), nullable=True),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(
            ["scan_run_id"], ["rule_analysis_results.scan_run_id"]
        ),
        sa.ForeignKeyConstraint(["server_id"], ["servers.server_id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_rule_findings_scan_run_id", "rule_findings", ["scan_run_id"])
    op.create_index("ix_rule_findings_server_id", "rule_findings", ["server_id"])
    op.create_index("ix_rule_findings_severity", "rule_findings", ["severity"])
    op.execute(
        "ALTER TABLE rule_analysis_results "
        "DROP COLUMN IF EXISTS rule_findings"
    )


def downgrade() -> None:
    """Restore the former JSON column and remove rule_findings."""
    op.add_column(
        "rule_analysis_results",
        sa.Column("rule_findings", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.drop_index("ix_rule_findings_severity", table_name="rule_findings")
    op.drop_index("ix_rule_findings_server_id", table_name="rule_findings")
    op.drop_index("ix_rule_findings_scan_run_id", table_name="rule_findings")
    op.drop_table("rule_findings")
