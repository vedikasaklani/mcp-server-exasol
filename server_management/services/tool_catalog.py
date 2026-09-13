"""Postgres mirror of the tool catalog, for the dashboard's tool-discovery
view. Exasol's DIM_TOOL (via runtime_telemetry.py) is the audit-trail-joined
copy; this is the plain relational one a frontend/BI tool can query without
touching Exasol at all, per the explicit requirement that tool information
live in Postgres too.

Best-effort by the same convention the rest of this codebase uses for
Postgres: a server_id that telemetry knows about (e.g. an ad-hoc
warden-console session with no api.py registration) has no matching `servers`
row, so there is nothing to attach a tool row to - upsert_discovered_tools
silently no-ops rather than raising a foreign-key error. A server_id that
Postgres does know about always gets mirrored.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert as pg_insert

from server_management.database.db_config import session_scope
from server_management.database.db_models import DiscoveredTool, Server


def upsert_discovered_tools(server_id: str, tools: list[dict[str, Any]], source: str) -> int:
    if not tools:
        return 0
    with session_scope() as db:
        if db.get(Server, server_id) is None:
            return 0
        written = 0
        for tool in tools:
            name = str(tool.get("name") or "").strip()
            if not name:
                continue
            stmt = pg_insert(DiscoveredTool).values(
                server_id=server_id,
                name=name,
                description=tool.get("description"),
                parameter_schema=tool.get("parameter_schema"),
                source=source,
            )
            stmt = stmt.on_conflict_do_update(
                constraint="uq_discovered_tools_server_name",
                set_={
                    "description": stmt.excluded.description,
                    "parameter_schema": stmt.excluded.parameter_schema,
                    "source": stmt.excluded.source,
                    "updated_at": func.now(),
                },
            )
            db.execute(stmt)
            written += 1
        db.commit()
        return written


def list_tools(server_id: str | None = None, q: str | None = None) -> list[dict[str, Any]]:
    """Global tool catalog for the dashboard's discovery/browse-and-select
    view - every known tool across every registered server, joined with the
    server it belongs to, optionally filtered."""
    with session_scope() as db:
        query = db.query(DiscoveredTool, Server).join(Server, Server.server_id == DiscoveredTool.server_id)
        if server_id:
            query = query.filter(DiscoveredTool.server_id == server_id)
        if q:
            like = f"%{q.lower()}%"
            query = query.filter(DiscoveredTool.name.ilike(like))
        rows = query.order_by(Server.repo_url, DiscoveredTool.name).all()
        return [
            {
                "server_id": tool.server_id,
                "repo_url": server.repo_url,
                "name": tool.name,
                "description": tool.description,
                "parameter_schema": tool.parameter_schema,
                "source": tool.source,
                "first_seen_at": tool.first_seen_at.isoformat() if tool.first_seen_at else None,
                "updated_at": tool.updated_at.isoformat() if tool.updated_at else None,
            }
            for tool, server in rows
        ]
