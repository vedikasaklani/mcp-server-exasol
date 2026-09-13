"""Normalize analysis result JSON into related tables."""

from typing import Sequence, Union
import json

from alembic import op
import sqlalchemy as sa


revision: str = "b7f2c8d4e1a0"
down_revision: Union[str, Sequence[str], None] = "a4195b1b8993"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return json.loads(value) if isinstance(value, str) else []


def upgrade() -> None:
    bind = op.get_bind()
    op.create_table(
        "tool_declarations",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_run_id", sa.String(), nullable=False),
        sa.Column("server_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("parameter_schema", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["scan_run_id"], ["rule_analysis_results.scan_run_id"]),
        sa.ForeignKeyConstraint(["server_id"], ["servers.server_id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("scan_run_id", "server_id", "name"):
        op.create_index(f"ix_tool_declarations_{column}", "tool_declarations", [column])

    op.create_table(
        "tool_behavioral_findings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_run_id", sa.String(), nullable=False),
        sa.Column("tool_declaration_id", sa.Integer()),
        sa.Column("tool_name", sa.String(), nullable=False),
        sa.Column("analyzer", sa.String(), nullable=False, server_default="behavioral_analyzer"),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("threat_summary", sa.Text()),
        sa.Column("threat_names", sa.JSON()),
        sa.Column("mcp_taxonomies", sa.JSON()),
        sa.Column("total_findings", sa.Integer()),
        sa.Column("target", sa.String()),
        sa.ForeignKeyConstraint(["scan_run_id"], ["llm_analysis_results.scan_run_id"]),
        sa.ForeignKeyConstraint(["tool_declaration_id"], ["tool_declarations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("scan_run_id", "tool_declaration_id", "severity"):
        op.create_index(f"ix_tool_behavioral_findings_{column}", "tool_behavioral_findings", [column])

    scan_servers = dict(bind.execute(sa.text("SELECT scan_run_id, server_id FROM scan_runs")).fetchall())
    declarations = {}
    for scan_run_id, raw in bind.execute(sa.text("SELECT scan_run_id, tool_declarations FROM rule_analysis_results")):
        for declaration in _as_list(raw):
            if not isinstance(declaration, dict) or not declaration.get("name"):
                continue
            result = bind.execute(
                sa.text(
                    "INSERT INTO tool_declarations "
                    "(scan_run_id, server_id, name, description, parameter_schema) "
                    "VALUES (:scan_run_id, :server_id, :name, :description, :parameter_schema) "
                    "RETURNING id"
                ),
                {
                    "scan_run_id": scan_run_id,
                    "server_id": scan_servers[scan_run_id],
                    "name": declaration["name"],
                    "description": declaration.get("description"),
                    "parameter_schema": json.dumps(declaration.get("parameter_schema", {})),
                },
            )
            declarations[(scan_run_id, declaration["name"])] = result.scalar_one()

    for scan_run_id, raw in bind.execute(sa.text("SELECT scan_run_id, llm_findings FROM llm_analysis_results")):
        for finding in _as_list(raw):
            if not isinstance(finding, dict):
                continue
            tool_name = finding.get("tool_name") or finding.get("tool") or finding.get("target") or "unknown"
            bind.execute(
                sa.text(
                    "INSERT INTO tool_behavioral_findings "
                    "(scan_run_id, tool_declaration_id, tool_name, analyzer, severity, threat_summary, "
                    "threat_names, mcp_taxonomies, total_findings, target) "
                    "VALUES (:scan_run_id, :tool_declaration_id, :tool_name, :analyzer, :severity, "
                    ":threat_summary, :threat_names, :mcp_taxonomies, :total_findings, :target)"
                ),
                {
                    "scan_run_id": scan_run_id,
                    "tool_declaration_id": declarations.get((scan_run_id, tool_name)),
                    "tool_name": tool_name,
                    "analyzer": finding.get("analyzer", "behavioral_analyzer"),
                    "severity": finding.get("severity", "LOW"),
                    "threat_summary": finding.get("threat_summary"),
                    "threat_names": json.dumps(finding.get("threat_names", [])),
                    "mcp_taxonomies": json.dumps(finding.get("mcp_taxonomies", [])),
                    "total_findings": finding.get("total_findings", 0),
                    "target": finding.get("target"),
                },
            )

    op.drop_column("rule_analysis_results", "tool_declarations")
    op.drop_column("llm_analysis_results", "llm_findings")


def downgrade() -> None:
    op.add_column("rule_analysis_results", sa.Column("tool_declarations", sa.JSON(), nullable=False, server_default="[]"))
    op.add_column("llm_analysis_results", sa.Column("llm_findings", sa.JSON(), nullable=False, server_default="[]"))
    for column in ("severity", "tool_declaration_id", "scan_run_id"):
        op.drop_index(f"ix_tool_behavioral_findings_{column}", table_name="tool_behavioral_findings")
    op.drop_table("tool_behavioral_findings")
    for column in ("name", "server_id", "scan_run_id"):
        op.drop_index(f"ix_tool_declarations_{column}", table_name="tool_declarations")
    op.drop_table("tool_declarations")
