"""
sync_to_exasol.py - pushes one scan's normalized findings into Exasol.

Called as a FastAPI BackgroundTask right after record_rule_analysis_result()
/ record_llm_analysis_result() commit in Postgres-
Exasol may delay the scan's OLAP data by a few minutes, it never
blocks or fails the scan pipeline itself, which is Postgres-only.

"""
from __future__ import annotations

import json
import os
import ssl
from pathlib import Path

import pyexasol
from dotenv import load_dotenv
from sqlalchemy.orm import Session

from server_management.database.db_models import (
    LlmAnalysisResult,
    ManifestHistory,
    RuleAnalysisResult,
    RuleFinding,
    ScanRun,
    Server,
    ToolBehavioralFinding,
    ToolDeclaration,
)

SCHEMA = "MCP_ANALYTICS"

_FACT_COLUMNS = (
    "SOURCE_TABLE", "SOURCE_ID", "SCAN_RUN_ID", "SERVER_ID", "TOOL_KEY",
    "ANALYZER_KEY", "DATE_KEY", "PHASE", "SEVERITY", "REACHABLE", "MESSAGE", "DETAILS",
)

_SCHEMA_SQL_PATH = Path(__file__).resolve().parents[1] / "exasol" / "star.sql"

load_dotenv(override=True)


def _initialize_schema(exa: pyexasol.ExaConnection) -> None:
    """Create the Exasol schema and tables required by the sync service."""
    exa.execute_sql_script(_SCHEMA_SQL_PATH.read_text(encoding="utf-8"))


def _connect() -> pyexasol.ExaConnection:
    exa = pyexasol.connect(
        dsn=os.environ["EXASOL_DSN"],
        user=os.environ["EXASOL_USER"],
        password=os.environ["EXASOL_PASSWORD"],
        websocket_sslopt={"cert_reqs": ssl.CERT_NONE}
    )
    _initialize_schema(exa)
    return exa


def _date_key(dt) -> int:
    return int(dt.strftime("%Y%m%d"))


def _ensure_dim_server(exa: pyexasol.ExaConnection, server: Server) -> None:
    exa.execute(
        """
        MERGE INTO DIM_SERVER t
        USING (SELECT {server_id} AS SERVER_ID, {repo_url} AS REPO_URL,
                      {installation_id} AS INSTALLATION_ID, {registered_at} AS REGISTERED_AT) s
        ON (t.SERVER_ID = s.SERVER_ID)
        WHEN NOT MATCHED THEN INSERT (SERVER_ID, REPO_URL, INSTALLATION_ID, REGISTERED_AT)
        VALUES (s.SERVER_ID, s.REPO_URL, s.INSTALLATION_ID, s.REGISTERED_AT)
        """,
        {
            "server_id": server.server_id,
            "repo_url": server.repo_url,
            "installation_id": server.installation_id,
            "registered_at": server.created_at,
        },
    )


def _get_or_create_tool_key(
    exa: pyexasol.ExaConnection, server_id: str, tool_name: str | None, scan_run_id: str
) -> int | None:
    """Tools are scoped to (server_id, tool_name), not global - the same
    tool name in two different servers is two different dim_tool rows."""
    if not tool_name:
        return None
    key = exa.execute(
        "SELECT TOOL_KEY FROM DIM_TOOL WHERE SERVER_ID = {s} AND TOOL_NAME = {t}",
        {"s": server_id, "t": tool_name},
    ).fetchval()
    if key is not None:
        return key
    exa.execute(
        "INSERT INTO DIM_TOOL (SERVER_ID, TOOL_NAME, FIRST_SEEN_SCAN_RUN_ID) VALUES ({s}, {t}, {r})",
        {"s": server_id, "t": tool_name, "r": scan_run_id},
    )
    return exa.execute(
        "SELECT TOOL_KEY FROM DIM_TOOL WHERE SERVER_ID = {s} AND TOOL_NAME = {t}",
        {"s": server_id, "t": tool_name},
    ).fetchval()


def _get_or_create_analyzer_key(exa: pyexasol.ExaConnection, analyzer_name: str) -> int:
    key = exa.execute(
        "SELECT ANALYZER_KEY FROM DIM_ANALYZER WHERE ANALYZER_NAME = {a}",
        {"a": analyzer_name},
    ).fetchval()
    if key is not None:
        return key
    exa.execute(
        "INSERT INTO DIM_ANALYZER (ANALYZER_NAME) VALUES ({a})",
        {"a": analyzer_name},
    )
    return exa.execute(
        "SELECT ANALYZER_KEY FROM DIM_ANALYZER WHERE ANALYZER_NAME = {a}",
        {"a": analyzer_name},
    ).fetchval()


def _flush_to_fact_table(exa: pyexasol.ExaConnection, rows: list[tuple]) -> None:
    """Stage -> insert-select -> truncate. See the staging-table comment in
    exasol_star_schema.sql for why this indirection exists."""
    if not rows:
        return
    exa.execute("TRUNCATE TABLE STG_STATIC_FINDINGS")
    exa.import_from_iterable(rows, "STG_STATIC_FINDINGS")
    cols = ", ".join(_FACT_COLUMNS)
    exa.execute(f"INSERT INTO FACT_STATIC_FINDINGS ({cols}) SELECT {cols} FROM STG_STATIC_FINDINGS")
    exa.execute("TRUNCATE TABLE STG_STATIC_FINDINGS")


def sync_rule_phase_findings(pg_session: Session, scan_run_id: str) -> None:
    """Call right after record_rule_analysis_result() commits in Postgres."""
    result = pg_session.get(RuleAnalysisResult, scan_run_id)
    run = pg_session.get(ScanRun, scan_run_id)
    server = pg_session.get(Server, run.server_id)
    findings = pg_session.query(RuleFinding).filter_by(scan_run_id=scan_run_id).all()
    tools = pg_session.query(ToolDeclaration).filter_by(scan_run_id=scan_run_id).all()

    exa = _connect()
    try:
        _ensure_dim_server(exa, server)
        date_key = _date_key(result.reviewed_at)

        # ToolDeclaration rows register the server's tools in dim_tool even
        # though RuleFinding itself (file/line-based, not tool-name-based)
        # never sets TOOL_KEY - that stays NULL for rule-phase findings.
        for t in tools:
            _get_or_create_tool_key(exa, t.server_id, t.name, scan_run_id)

        rows = []
        for f in findings:
            analyzer_key = _get_or_create_analyzer_key(exa, f.analyzer)
            details_json = f.details  # already a dict from Postgres JSON column
            reachable = details_json.get("reachable") if isinstance(details_json, dict) else None
            rows.append((
                "rule_finding", f.id, scan_run_id, f.server_id, None, analyzer_key,
                date_key, "rule", f.severity, reachable, f.message,
                json.dumps(details_json) if details_json else None,
            ))
        _flush_to_fact_table(exa, rows)
    finally:
        exa.close()


def sync_scan_run(pg_session: Session, scan_run_id: str) -> None:
    """Upserts one row per scan run into FACT_SCAN_RUN - this is what makes
    FAILED/REJECTED scans visible in Exasol, not just scans that produced
    findings. Idempotent (MERGE keyed on SCAN_RUN_ID), so it's safe to call
    from every phase transition, including scan_pipeline.py's scan_fail()/
    scan_pass() which run outside the API layer entirely."""
    run = pg_session.get(ScanRun, scan_run_id)
    if run is None:
        return
    rule_result = pg_session.get(RuleAnalysisResult, scan_run_id)
    llm_result = pg_session.get(LlmAnalysisResult, scan_run_id)
    duration = None
    if run.finished_at and run.started_at:
        duration = (run.finished_at - run.started_at).total_seconds()

    exa = _connect()
    try:
        exa.execute(
            """
            MERGE INTO FACT_SCAN_RUN t
            USING (SELECT {scan_run_id} AS SCAN_RUN_ID, {server_id} AS SERVER_ID,
                          {commit_sha} AS COMMIT_SHA, {status} AS STATUS,
                          {rule_verdict} AS RULE_VERDICT, {llm_verdict} AS LLM_VERDICT,
                          {date_key} AS DATE_KEY, {started_at} AS STARTED_AT,
                          {finished_at} AS FINISHED_AT, {duration} AS DURATION_SECONDS) s
            ON (t.SCAN_RUN_ID = s.SCAN_RUN_ID)
            WHEN MATCHED THEN UPDATE SET
                t.STATUS = s.STATUS, t.RULE_VERDICT = s.RULE_VERDICT, t.LLM_VERDICT = s.LLM_VERDICT,
                t.FINISHED_AT = s.FINISHED_AT, t.DURATION_SECONDS = s.DURATION_SECONDS
            WHEN NOT MATCHED THEN INSERT (
                SCAN_RUN_ID, SERVER_ID, COMMIT_SHA, STATUS, RULE_VERDICT, LLM_VERDICT,
                DATE_KEY, STARTED_AT, FINISHED_AT, DURATION_SECONDS
            ) VALUES (
                s.SCAN_RUN_ID, s.SERVER_ID, s.COMMIT_SHA, s.STATUS, s.RULE_VERDICT, s.LLM_VERDICT,
                s.DATE_KEY, s.STARTED_AT, s.FINISHED_AT, s.DURATION_SECONDS
            )
            """,
            {
                "scan_run_id": scan_run_id,
                "server_id": run.server_id,
                "commit_sha": run.commit_sha,
                "status": run.status.value,
                "rule_verdict": rule_result.verdict.value if rule_result else None,
                "llm_verdict": llm_result.verdict.value if llm_result else None,
                "date_key": _date_key(run.started_at),
                "started_at": run.started_at,
                "finished_at": run.finished_at,
                "duration": duration,
            },
        )
    finally:
        exa.close()


def sync_latest_manifest_history(pg_session: Session, server_id: str) -> None:
    """Upserts the most recent ManifestHistory row for this server - the
    audit trail of allowed_destinations changes over time. History rows are
    immutable once written, so this only ever inserts a new version, never
    updates an old one; safe to call redundantly from multiple trigger
    points (operator edits and rule-phase manifest updates both land here)."""
    history = (
        pg_session.query(ManifestHistory)
        .filter_by(server_id=server_id)
        .order_by(ManifestHistory.version.desc())
        .first()
    )
    if history is None:
        return

    exa = _connect()
    try:
        exa.execute(
            """
            MERGE INTO FACT_MANIFEST_HISTORY t
            USING (SELECT {server_id} AS SERVER_ID, {version} AS VERSION,
                          {allowed_destinations} AS ALLOWED_DESTINATIONS,
                          {change_reason} AS CHANGE_REASON,
                          {date_key} AS DATE_KEY, {changed_at} AS CHANGED_AT) s
            ON (t.SERVER_ID = s.SERVER_ID AND t.VERSION = s.VERSION)
            WHEN NOT MATCHED THEN INSERT (
                SERVER_ID, VERSION, ALLOWED_DESTINATIONS, CHANGE_REASON, DATE_KEY, CHANGED_AT
            ) VALUES (
                s.SERVER_ID, s.VERSION, s.ALLOWED_DESTINATIONS, s.CHANGE_REASON, s.DATE_KEY, s.CHANGED_AT
            )
            """,
            {
                "server_id": history.server_id,
                "version": history.version,
                "allowed_destinations": json.dumps(history.allowed_destinations),
                "change_reason": history.change_reason,
                "date_key": _date_key(history.changed_at),
                "changed_at": history.changed_at,
            },
        )
    finally:
        exa.close()


def sync_llm_phase_findings(pg_session: Session, scan_run_id: str) -> None:
    """Call right after record_llm_analysis_result() commits in Postgres."""
    result = pg_session.get(LlmAnalysisResult, scan_run_id)
    run = pg_session.get(ScanRun, scan_run_id)
    findings = pg_session.query(ToolBehavioralFinding).filter_by(scan_run_id=scan_run_id).all()

    exa = _connect()
    try:
        date_key = _date_key(result.reviewed_at)
        rows = []
        for f in findings:
            tool_key = _get_or_create_tool_key(exa, run.server_id, f.tool_name, scan_run_id)
            analyzer_key = _get_or_create_analyzer_key(exa, f.analyzer)
            details = json.dumps({
                "threat_names": f.threat_names,
                "mcp_taxonomies": f.mcp_taxonomies,
                "total_findings": f.total_findings,
                "target": f.target,
            })
            rows.append((
                "tool_behavioral_finding", f.id, scan_run_id, run.server_id, tool_key,
                analyzer_key, date_key, "llm", f.severity, None, f.threat_summary, details,
            ))
        _flush_to_fact_table(exa, rows)
    finally:
        exa.close()