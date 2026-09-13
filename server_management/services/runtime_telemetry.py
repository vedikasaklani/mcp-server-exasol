"""Postgres-free runtime telemetry persistence for the Exasol proxy."""

from __future__ import annotations

import hashlib
import json
import os
import ssl
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pyexasol
from dotenv import load_dotenv

SCHEMA = "MCP_ANALYTICS"
_SCHEMA_SQL_PATH = Path(__file__).resolve().parents[1] / "exasol" / "star.sql"
_TRUST_SCORE_SQL_PATH = Path(__file__).resolve().parents[1] / "exasol" / "trust_score.sql"

load_dotenv(override=True)


def _connect() -> pyexasol.ExaConnection:
    exa = pyexasol.connect(
        dsn=os.environ["EXASOL_DSN"],
        user=os.environ["EXASOL_USER"],
        password=os.environ["EXASOL_PASSWORD"],
        websocket_sslopt={"cert_reqs": ssl.CERT_NONE},
    )
    exa.execute_sql_script(_SCHEMA_SQL_PATH.read_text(encoding="utf-8"))
    current_width = exa.execute(
        """
        SELECT COLUMN_MAXSIZE
        FROM EXA_ALL_COLUMNS
        WHERE COLUMN_SCHEMA = {schema}
          AND COLUMN_TABLE = 'FACT_RUNTIME_EVENTS'
          AND COLUMN_NAME = 'EVENT_ID'
        """,
        {"schema": SCHEMA},
    ).fetchval()
    if current_width is not None and int(current_width) < 255:
        exa.execute(
            "ALTER TABLE FACT_RUNTIME_EVENTS MODIFY EVENT_ID VARCHAR(255)"
        )
    _ensure_dim_date(exa)
    return exa


def _ensure_dim_date(exa: pyexasol.ExaConnection) -> None:
    """DIM_DATE has no seed data of its own in star.sql, but trust_score.sql
    inner-joins FACT_STATIC_FINDINGS to it - an empty dimension silently
    drops every static finding out of the security score. Self-heal it the
    same way the EVENT_ID width fix above does, so a fresh deployment (e.g.
    hostconfig, standing this up from scratch) doesn't need a separate
    manual seeding step."""
    if exa.execute("SELECT COUNT(*) FROM DIM_DATE").fetchval():
        return
    exa.execute(
        """
        INSERT INTO DIM_DATE (DATE_KEY, FULL_DATE, DAY_OF_WEEK, MONTH_NUM, YEAR_NUM, IS_WEEKEND)
        SELECT TO_NUMBER(TO_CHAR(d, 'YYYYMMDD')), d, TO_CHAR(d, 'DY'),
               TO_NUMBER(TO_CHAR(d, 'MM')), TO_NUMBER(TO_CHAR(d, 'YYYY')),
               CASE WHEN TO_CHAR(d, 'DY') IN ('SAT', 'SUN') THEN TRUE ELSE FALSE END
        FROM (SELECT DATE '2020-01-01' + LEVEL - 1 AS d FROM DUAL CONNECT BY LEVEL <= 4018) t
        """
    )


def _parse_timestamp(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc).replace(tzinfo=None)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _date_key(value: datetime) -> int:
    return int(value.strftime("%Y%m%d"))


def _iso(value: Any) -> str:
    """pyexasol returns TIMESTAMP columns as str by default (no dtype
    mapper configured on connect), so a value here may already be text
    rather than a datetime - normalize either shape to an ISO string."""
    if not value:
        return ""
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _ensure_server(exa: pyexasol.ExaConnection, server_id: str, repo_url: str) -> None:
    exa.execute(
        """
        MERGE INTO DIM_SERVER t
        USING (SELECT {server_id} AS SERVER_ID, {repo_url} AS REPO_URL) s
        ON (t.SERVER_ID = s.SERVER_ID)
        WHEN MATCHED THEN UPDATE SET t.REPO_URL = s.REPO_URL
        WHEN NOT MATCHED THEN INSERT (SERVER_ID, REPO_URL)
        VALUES (s.SERVER_ID, s.REPO_URL)
        """,
        {"server_id": server_id, "repo_url": repo_url},
    )


def resolve_server(
    source: str,
    kind: str,
    _ref: str,
    canonical_server_id: str | None = None,
    exa: pyexasol.ExaConnection | None = None,
) -> str:
    """Resolve a server and preserve the PostgreSQL identity when supplied."""
    _ = _ref
    if not source.strip():
        raise ValueError("source must not be empty")
    if canonical_server_id is not None and not canonical_server_id.strip():
        raise ValueError("canonical_server_id must not be empty")
    owns_connection = exa is None
    connection = exa or _connect()
    try:
        server_id = canonical_server_id.strip() if canonical_server_id else None
        if server_id is None:
            existing = connection.execute(
                "SELECT SERVER_ID FROM DIM_SERVER WHERE REPO_URL = {source}",
                {"source": source.strip()},
            ).fetchval()
            server_id = existing or str(
                uuid.uuid5(uuid.NAMESPACE_URL, f"{kind}:{source}")
            )
        _ensure_server(connection, server_id, source.strip())
        return server_id
    finally:
        if owns_connection:
            connection.close()


def ensure_tool_key(
    exa: pyexasol.ExaConnection,
    server_id: str,
    name: str,
    first_seen_scan_run_id: str | None = None,
) -> int:
    """Get-or-create a DIM_TOOL key scoped to (server_id, name)."""
    key = exa.execute(
        "SELECT TOOL_KEY FROM DIM_TOOL WHERE SERVER_ID = {server_id} AND TOOL_NAME = {name}",
        {"server_id": server_id, "name": name},
    ).fetchval()
    if key is not None:
        return int(key)
    if first_seen_scan_run_id:
        exa.execute(
            "INSERT INTO DIM_TOOL (SERVER_ID, TOOL_NAME, FIRST_SEEN_SCAN_RUN_ID) "
            "VALUES ({server_id}, {name}, {first_seen})",
            {"server_id": server_id, "name": name, "first_seen": first_seen_scan_run_id},
        )
    else:
        exa.execute(
            "INSERT INTO DIM_TOOL (SERVER_ID, TOOL_NAME) VALUES ({server_id}, {name})",
            {"server_id": server_id, "name": name},
        )
    inserted_key = exa.execute(
        "SELECT TOOL_KEY FROM DIM_TOOL WHERE SERVER_ID = {server_id} AND TOOL_NAME = {name}",
        {"server_id": server_id, "name": name},
    ).fetchval()
    if inserted_key is None:
        raise RuntimeError(f"could not create tool dimension for {server_id}/{name}")
    return int(inserted_key)


def ensure_analyzer_key(exa: pyexasol.ExaConnection, name: str) -> int:
    """Get-or-create a DIM_ANALYZER key for the given analyzer name."""
    key = exa.execute(
        "SELECT ANALYZER_KEY FROM DIM_ANALYZER WHERE ANALYZER_NAME = {name}",
        {"name": name},
    ).fetchval()
    if key is not None:
        return int(key)
    exa.execute(
        "INSERT INTO DIM_ANALYZER (ANALYZER_NAME) VALUES ({name})",
        {"name": name},
    )
    inserted_key = exa.execute(
        "SELECT ANALYZER_KEY FROM DIM_ANALYZER WHERE ANALYZER_NAME = {name}",
        {"name": name},
    ).fetchval()
    if inserted_key is None:
        raise RuntimeError(f"could not create analyzer dimension {name}")
    return int(inserted_key)


def write_runtime_events(server_id: str, events: list[dict[str, Any]]) -> int:
    if not events:
        return 0
    exa = _connect()
    try:
        if exa.execute(
            "SELECT SERVER_ID FROM DIM_SERVER WHERE SERVER_ID = {server_id}",
            {"server_id": server_id},
        ).fetchval() is None:
            raise ValueError(f"unknown server_id={server_id}")
        written = 0
        for event in events:
            event_id = str(event["event_id"])
            event_ts = _parse_timestamp(event.get("event_ts"))
            tool_name = str(event.get("tool_name") or "")
            tool_key = ensure_tool_key(exa, server_id, tool_name) if tool_name else None
            categories = json.dumps(event.get("sensitive_data_categories") or [])
            exa.execute(
                """
                MERGE INTO FACT_RUNTIME_EVENTS t
                USING (
                    SELECT {event_id} AS EVENT_ID, {server_id} AS SERVER_ID,
                           CAST({tool_key} AS INT) AS TOOL_KEY,
                           {agent_id} AS AGENT_ID, {session_id} AS SESSION_ID,
                           {date_key} AS DATE_KEY, CAST({event_ts} AS TIMESTAMP) AS EVENT_TS,
                           {declared} AS DESTINATION_DECLARED, {actual} AS DESTINATION_ACTUAL,
                           CAST({destination_match} AS BOOLEAN) AS DESTINATION_MATCH,
                           CAST({intent_match} AS BOOLEAN) AS INTENT_MATCH,
                           CAST({sensitive} AS BOOLEAN) AS SENSITIVE_DATA_FLAG,
                           {categories} AS SENSITIVE_DATA_CATEGORIES,
                           {decision} AS DECISION, {reason} AS DECISION_REASON,
                           CAST({latency} AS DECIMAL(10,0)) AS LATENCY_MS,
                           CAST({status} AS DECIMAL(5,0)) AS STATUS_CODE,
                           CAST({sent} AS DECIMAL(18,0)) AS BYTES_SENT,
                           CAST({received} AS DECIMAL(18,0)) AS BYTES_RECEIVED,
                           CAST({retry} AS DECIMAL(5,0)) AS RETRY_COUNT
                ) s
                ON (t.EVENT_ID = s.EVENT_ID)
                WHEN MATCHED THEN UPDATE SET
                    t.SERVER_ID = s.SERVER_ID, t.TOOL_KEY = s.TOOL_KEY,
                    t.EVENT_TS = s.EVENT_TS, t.DECISION = s.DECISION,
                    t.DECISION_REASON = s.DECISION_REASON,
                    t.DESTINATION_DECLARED = s.DESTINATION_DECLARED,
                    t.DESTINATION_ACTUAL = s.DESTINATION_ACTUAL,
                    t.DESTINATION_MATCH = s.DESTINATION_MATCH,
                    t.SENSITIVE_DATA_FLAG = s.SENSITIVE_DATA_FLAG,
                    t.SENSITIVE_DATA_CATEGORIES = s.SENSITIVE_DATA_CATEGORIES,
                    t.LATENCY_MS = s.LATENCY_MS, t.STATUS_CODE = s.STATUS_CODE,
                    t.BYTES_SENT = s.BYTES_SENT, t.BYTES_RECEIVED = s.BYTES_RECEIVED,
                    t.RETRY_COUNT = s.RETRY_COUNT
                WHEN NOT MATCHED THEN INSERT (
                    EVENT_ID, SERVER_ID, TOOL_KEY, AGENT_ID, SESSION_ID, DATE_KEY,
                    EVENT_TS, DESTINATION_DECLARED, DESTINATION_ACTUAL,
                    DESTINATION_MATCH, INTENT_MATCH, SENSITIVE_DATA_FLAG,
                    SENSITIVE_DATA_CATEGORIES, DECISION, DECISION_REASON, LATENCY_MS,
                    STATUS_CODE, BYTES_SENT, BYTES_RECEIVED, RETRY_COUNT
                ) VALUES (
                    s.EVENT_ID, s.SERVER_ID, s.TOOL_KEY, s.AGENT_ID, s.SESSION_ID, s.DATE_KEY,
                    s.EVENT_TS, s.DESTINATION_DECLARED, s.DESTINATION_ACTUAL,
                    s.DESTINATION_MATCH, s.INTENT_MATCH, s.SENSITIVE_DATA_FLAG,
                    s.SENSITIVE_DATA_CATEGORIES, s.DECISION, s.DECISION_REASON, s.LATENCY_MS,
                    s.STATUS_CODE, s.BYTES_SENT, s.BYTES_RECEIVED, s.RETRY_COUNT
                )
                """,
                {
                    "event_id": event_id,
                    "server_id": server_id,
                    "tool_key": tool_key,
                    "agent_id": event.get("agent_id"),
                    "session_id": event.get("session_id"),
                    "date_key": _date_key(event_ts),
                    "event_ts": event_ts,
                    "declared": event.get("destination_declared"),
                    "actual": event.get("destination_actual"),
                    "destination_match": event.get("destination_match"),
                    "intent_match": event.get("intent_match"),
                    "sensitive": bool(event.get("sensitive_data_flag", False)),
                    "categories": categories,
                    "decision": event.get("decision"),
                    "reason": event.get("decision_reason"),
                    "latency": event.get("latency_ms"),
                    "status": event.get("status_code"),
                    "sent": event.get("bytes_sent"),
                    "received": event.get("bytes_received"),
                    "retry": event.get("retry_count"),
                },
            )
            written += 1
        return written
    finally:
        exa.close()


def get_runtime_events(server_id: str, limit: int) -> list[dict[str, Any]]:
    exa = _connect()
    try:
        rows = exa.execute(
            f"""
            SELECT e.EVENT_ID, t.TOOL_NAME, e.EVENT_TS, e.DECISION,
                   e.DECISION_REASON, e.SENSITIVE_DATA_FLAG,
                   e.SENSITIVE_DATA_CATEGORIES, e.DESTINATION_MATCH,
                   e.LATENCY_MS, e.BYTES_SENT, e.BYTES_RECEIVED, e.SESSION_ID
            FROM FACT_RUNTIME_EVENTS e
            LEFT JOIN DIM_TOOL t ON t.TOOL_KEY = e.TOOL_KEY
            WHERE e.SERVER_ID = {{server_id}}
            ORDER BY e.EVENT_TS DESC
            LIMIT {int(min(max(limit, 1), 500))}
            """,
            {"server_id": server_id},
        ).fetchall()
        return [
            {
                "event_id": row[0],
                "tool_name": row[1] or "",
                "event_ts": _iso(row[2]),
                "decision": row[3],
                "decision_reason": row[4] or "",
                "sensitive_data_flag": bool(row[5]),
                "sensitive_data_categories": json.loads(row[6] or "[]"),
                "destination_match": row[7],
                "latency_ms": row[8] or 0,
                "bytes_sent": row[9] or 0,
                "bytes_received": row[10] or 0,
                "session_id": row[11] or "",
            }
            for row in rows
        ]
    finally:
        exa.close()


def list_servers() -> list[dict[str, Any]]:
    """Every known server plus its latest computed trust score, if any -
    the discovery list a dashboard landing page reads first."""
    exa = _connect()
    try:
        rows = exa.execute(
            """
            SELECT s.SERVER_ID, s.REPO_URL, t.OVERALL_SCORE, t.SECURITY_SCORE,
                   t.OPERATIONAL_SCORE, t.DATE_KEY, t.COMPUTED_AT
            FROM DIM_SERVER s
            LEFT JOIN (
                SELECT SERVER_ID, MAX(DATE_KEY) AS DATE_KEY
                FROM FACT_TRUST_SCORE GROUP BY SERVER_ID
            ) latest ON latest.SERVER_ID = s.SERVER_ID
            LEFT JOIN FACT_TRUST_SCORE t
              ON t.SERVER_ID = latest.SERVER_ID AND t.DATE_KEY = latest.DATE_KEY
            ORDER BY s.REPO_URL
            """
        ).fetchall()
        return [
            {
                "server_id": row[0],
                "source": row[1],
                "overall_score": _num(row[2]),
                "security_score": _num(row[3]),
                "operational_score": _num(row[4]),
                "score_date": int(row[5]) if row[5] is not None else None,
                "computed_at": _iso(row[6]),
            }
            for row in rows
        ]
    finally:
        exa.close()


def _num(value: Any) -> float | None:
    """Exasol DECIMAL columns come back as strings over the wire - a naive
    passthrough hands API clients "0" where they expect 0."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def get_tools(server_id: str) -> list[dict[str, Any]]:
    exa = _connect()
    try:
        rows = exa.execute(
            """
            SELECT TOOL_NAME
            FROM DIM_TOOL
            WHERE SERVER_ID = {server_id}
            ORDER BY TOOL_NAME
            """,
            {"server_id": server_id},
        ).fetchall()
        return [
            {"name": row[0], "description": "", "parameter_schema": {}}
            for row in rows
        ]
    finally:
        exa.close()


def write_tools(server_id: str, tools: list[dict[str, Any]]) -> int:
    exa = _connect()
    try:
        if exa.execute(
            "SELECT SERVER_ID FROM DIM_SERVER WHERE SERVER_ID = {server_id}",
            {"server_id": server_id},
        ).fetchval() is None:
            raise ValueError(f"unknown server_id={server_id}")
        for tool in tools:
            name = str(tool.get("name") or "").strip()
            if not name:
                raise ValueError("tool name must not be empty")
            ensure_tool_key(exa, server_id, name)
        return len(tools)
    finally:
        exa.close()


def write_sast_findings(
    server_id: str,
    findings: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    ref: str,
) -> int:
    exa = _connect()
    try:
        if exa.execute(
            "SELECT SERVER_ID FROM DIM_SERVER WHERE SERVER_ID = {server_id}",
            {"server_id": server_id},
        ).fetchval() is None:
            raise ValueError(f"unknown server_id={server_id}")
        for tool in tools:
            name = str(tool.get("name") or "").strip()
            if name:
                ensure_tool_key(exa, server_id, name)
        scan_run_id = f"proxy-{ref}"[:36] or "proxy-scan"
        for finding in findings:
            payload = json.dumps(finding, sort_keys=True)
            source_id = int.from_bytes(
                hashlib.sha256(payload.encode("utf-8")).digest()[:8], "big"
            ) % 10**18
            analyzer_name = str(finding.get("analyzer") or "semgrep")
            analyzer_key = ensure_analyzer_key(exa, analyzer_name)
            event_ts = datetime.now(timezone.utc).replace(tzinfo=None)
            exa.execute(
                """
                MERGE INTO FACT_STATIC_FINDINGS t
                USING (
                    SELECT {source_table} AS SOURCE_TABLE,
                           CAST({source_id} AS DECIMAL(18,0)) AS SOURCE_ID,
                           {scan_run_id} AS SCAN_RUN_ID, {server_id} AS SERVER_ID,
                           CAST({analyzer_key} AS INT) AS ANALYZER_KEY,
                           {date_key} AS DATE_KEY, 'rule' AS PHASE,
                           {severity} AS SEVERITY, {message} AS MESSAGE,
                           {details} AS DETAILS
                ) s
                ON (t.SOURCE_TABLE = s.SOURCE_TABLE AND t.SOURCE_ID = s.SOURCE_ID)
                WHEN MATCHED THEN UPDATE SET
                    t.MESSAGE = s.MESSAGE, t.DETAILS = s.DETAILS
                WHEN NOT MATCHED THEN INSERT (
                    SOURCE_TABLE, SOURCE_ID, SCAN_RUN_ID, SERVER_ID, ANALYZER_KEY,
                    DATE_KEY, PHASE, SEVERITY, MESSAGE, DETAILS
                ) VALUES (
                    s.SOURCE_TABLE, s.SOURCE_ID, s.SCAN_RUN_ID, s.SERVER_ID, s.ANALYZER_KEY,
                    s.DATE_KEY, s.PHASE, s.SEVERITY, s.MESSAGE, s.DETAILS
                )
                """,
                {
                    "source_table": "proxy_sast",
                    "source_id": source_id,
                    "scan_run_id": scan_run_id,
                    "server_id": server_id,
                    "analyzer_key": analyzer_key,
                    "date_key": _date_key(event_ts),
                    "severity": finding.get("severity") or "unknown",
                    "message": finding.get("message"),
                    "details": payload,
                },
            )
        return len(findings)
    finally:
        exa.close()


def compute_scores() -> None:
    exa = _connect()
    try:
        exa.execute_sql_script(_TRUST_SCORE_SQL_PATH.read_text(encoding="utf-8"))
    finally:
        exa.close()


def get_trust_score(server_id: str) -> dict[str, Any] | None:
    exa = _connect()
    try:
        row = exa.execute(
            """
            SELECT SERVER_ID, DATE_KEY, SECURITY_SCORE, OPERATIONAL_SCORE,
                   OVERALL_SCORE, STATIC_PENALTY, RUNTIME_VIOLATION_COUNT,
                   RUNTIME_EXFIL_FLAG_COUNT, SUCCESS_RATE, P95_LATENCY_MS,
                   TOTAL_CALLS_IN_WINDOW, COMPUTED_AT
            FROM FACT_TRUST_SCORE
            WHERE SERVER_ID = {server_id}
            ORDER BY DATE_KEY DESC
            LIMIT 1
            """,
            {"server_id": server_id},
        ).fetchone()
        if row is None:
            return None
        keys = (
            "server_id", "date_key", "security_score", "operational_score",
            "overall_score", "static_penalty", "runtime_violation_count",
            "runtime_exfil_flag_count", "success_rate", "p95_latency_ms",
            "total_calls_in_window", "computed_at",
        )
        result: dict[str, Any] = dict(zip(keys, row))
        numeric = {
            "security_score", "operational_score", "overall_score", "static_penalty",
            "runtime_violation_count", "runtime_exfil_flag_count", "success_rate",
            "p95_latency_ms", "total_calls_in_window",
        }
        for key in numeric:
            result[key] = _num(result[key])
        result["date_key"] = int(result["date_key"]) if result["date_key"] is not None else None
        if result["computed_at"] is not None:
            result["computed_at"] = _iso(result["computed_at"])
        return result
    finally:
        exa.close()


def write_runtime_findings(server_id: str, findings: list[dict[str, Any]]) -> int:
    if not findings:
        return 0
    exa = _connect()
    try:
        if exa.execute(
            "SELECT SERVER_ID FROM DIM_SERVER WHERE SERVER_ID = {server_id}",
            {"server_id": server_id},
        ).fetchval() is None:
            raise ValueError(f"unknown server_id={server_id}")
        for finding in findings:
            event_ts = _parse_timestamp(finding.get("event_ts"))
            request_id = finding.get("request_id") or ""
            detector = str(finding.get("detector") or "unknown")
            finding_id = f"{finding.get('session_id', '')}:{request_id}:{detector}"
            tool_name = str(finding.get("tool_name") or "")
            tool_key = ensure_tool_key(exa, server_id, tool_name) if tool_name else None
            exa.execute(
                """
                MERGE INTO FACT_RUNTIME_FINDINGS t
                USING (
                    SELECT {finding_id} AS FINDING_ID, {server_id} AS SERVER_ID,
                           CAST({tool_key} AS INT) AS TOOL_KEY, {session_id} AS SESSION_ID,
                           {request_id} AS REQUEST_ID, CAST({event_ts} AS TIMESTAMP) AS EVENT_TS,
                           {detector} AS DETECTOR, {family} AS FAMILY, {severity} AS SEVERITY,
                           {confidence} AS CONFIDENCE, CAST({kernel} AS BOOLEAN) AS KERNEL_ATTESTED,
                           {title} AS TITLE, {detail} AS DETAIL, {evidence} AS EVIDENCE,
                           CAST({occurrences} AS DECIMAL(18,0)) AS OCCURRENCES
                ) s
                ON (t.FINDING_ID = s.FINDING_ID)
                WHEN MATCHED THEN UPDATE SET
                    t.OCCURRENCES = s.OCCURRENCES, t.DETAIL = s.DETAIL
                WHEN NOT MATCHED THEN INSERT (
                    FINDING_ID, SERVER_ID, TOOL_KEY, SESSION_ID, REQUEST_ID, EVENT_TS,
                    DETECTOR, FAMILY, SEVERITY, CONFIDENCE, KERNEL_ATTESTED, TITLE,
                    DETAIL, EVIDENCE, OCCURRENCES
                ) VALUES (
                    s.FINDING_ID, s.SERVER_ID, s.TOOL_KEY, s.SESSION_ID, s.REQUEST_ID, s.EVENT_TS,
                    s.DETECTOR, s.FAMILY, s.SEVERITY, s.CONFIDENCE, s.KERNEL_ATTESTED, s.TITLE,
                    s.DETAIL, s.EVIDENCE, s.OCCURRENCES
                )
                """,
                {
                    "finding_id": finding_id,
                    "server_id": server_id,
                    "tool_key": tool_key,
                    "session_id": finding.get("session_id"),
                    "request_id": request_id,
                    "event_ts": event_ts,
                    "detector": detector,
                    "family": finding.get("family"),
                    "severity": finding.get("severity") or "unknown",
                    "confidence": finding.get("confidence"),
                    "kernel": bool(finding.get("kernel_attested", False)),
                    "title": finding.get("title"),
                    "detail": finding.get("detail"),
                    "evidence": json.dumps(finding.get("evidence") or []),
                    "occurrences": finding.get("occurrences", 0),
                },
            )
        return len(findings)
    finally:
        exa.close()


def get_runtime_findings(server_id: str, limit: int) -> list[dict[str, Any]]:
    exa = _connect()
    try:
        rows = exa.execute(
            f"""
            SELECT EVENT_TS, DETECTOR, FAMILY, SEVERITY, CONFIDENCE,
                   KERNEL_ATTESTED, TITLE, DETAIL, OCCURRENCES, SESSION_ID
            FROM FACT_RUNTIME_FINDINGS
            WHERE SERVER_ID = {{server_id}}
            ORDER BY EVENT_TS DESC
            LIMIT {int(min(max(limit, 1), 500))}
            """,
            {"server_id": server_id},
        ).fetchall()
        return [
            {
                "event_ts": _iso(row[0]),
                "detector": row[1],
                "family": row[2] or "",
                "severity": row[3],
                "confidence": row[4] or "",
                "kernel_attested": bool(row[5]),
                "title": row[6] or "",
                "detail": row[7] or "",
                "occurrences": row[8] or 0,
                "sessions": 1,
            }
            for row in rows
        ]
    finally:
        exa.close()


def write_session(server_id: str, session: dict[str, Any]) -> None:
    exa = _connect()
    try:
        if exa.execute(
            "SELECT SERVER_ID FROM DIM_SERVER WHERE SERVER_ID = {server_id}",
            {"server_id": server_id},
        ).fetchval() is None:
            raise ValueError(f"unknown server_id={server_id}")
        started = _parse_timestamp(session.get("started_at"))
        ended = _parse_timestamp(session.get("ended_at")) if session.get("ended_at") else None
        exa.execute(
            """
            MERGE INTO FACT_SESSION t
            USING (
                SELECT {session_id} AS SESSION_ID, {server_id} AS SERVER_ID,
                       CAST({started} AS TIMESTAMP) AS STARTED_AT,
                       CAST({ended} AS TIMESTAMP) AS ENDED_AT,
                       CAST({duration} AS DECIMAL(18,6)) AS DURATION_SECONDS,
                       {posture} AS POSTURE, {reason} AS POSTURE_REASON,
                       CAST({requests} AS DECIMAL(18,0)) AS REQUESTS,
                       CAST({failures} AS DECIMAL(18,0)) AS FAILURES,
                       CAST({denials} AS DECIMAL(18,0)) AS DENIALS,
                       CAST({learning} AS BOOLEAN) AS LEARNING_MODE,
                       {confinement} AS CONFINEMENT, {runtime} AS RUNTIME,
                       CAST({entries} AS DECIMAL(18,0)) AS AUDIT_ENTRIES,
                       CAST({verified} AS BOOLEAN) AS AUDIT_CHAIN_VERIFIED
            ) s
            ON (t.SESSION_ID = s.SESSION_ID)
            WHEN MATCHED THEN UPDATE SET
                t.ENDED_AT = s.ENDED_AT, t.POSTURE = s.POSTURE,
                t.POSTURE_REASON = s.POSTURE_REASON, t.REQUESTS = s.REQUESTS,
                t.FAILURES = s.FAILURES, t.DENIALS = s.DENIALS
            WHEN NOT MATCHED THEN INSERT (
                SESSION_ID, SERVER_ID, STARTED_AT, ENDED_AT, DURATION_SECONDS,
                POSTURE, POSTURE_REASON, REQUESTS, FAILURES, DENIALS, LEARNING_MODE,
                CONFINEMENT, RUNTIME, AUDIT_ENTRIES, AUDIT_CHAIN_VERIFIED
            ) VALUES (
                s.SESSION_ID, s.SERVER_ID, s.STARTED_AT, s.ENDED_AT, s.DURATION_SECONDS,
                s.POSTURE, s.POSTURE_REASON, s.REQUESTS, s.FAILURES, s.DENIALS,
                s.LEARNING_MODE, s.CONFINEMENT, s.RUNTIME, s.AUDIT_ENTRIES,
                s.AUDIT_CHAIN_VERIFIED
            )
            """,
            {
                "session_id": session["session_id"],
                "server_id": server_id,
                "started": started,
                "ended": ended,
                "duration": session.get("duration_seconds", 0),
                "posture": session.get("posture"),
                "reason": session.get("posture_reason"),
                "requests": session.get("requests", 0),
                "failures": session.get("failures", 0),
                "denials": session.get("denials", 0),
                "learning": bool(session.get("learning_mode", False)),
                "confinement": session.get("confinement"),
                "runtime": session.get("runtime"),
                "entries": session.get("audit_entries", 0),
                "verified": bool(session.get("audit_chain_verified", False)),
            },
        )
    finally:
        exa.close()


def get_sessions(server_id: str, limit: int) -> list[dict[str, Any]]:
    exa = _connect()
    try:
        rows = exa.execute(
            f"""
            SELECT SESSION_ID, STARTED_AT, POSTURE, POSTURE_REASON,
                   SEV_CRITICAL, SEV_HIGH, REQUESTS, DENIALS, CONFINEMENT
            FROM FACT_SESSION
            WHERE SERVER_ID = {{server_id}}
            ORDER BY STARTED_AT DESC
            LIMIT {int(min(max(limit, 1), 500))}
            """,
            {"server_id": server_id},
        ).fetchall()
        return [
            {
                "session_id": row[0],
                "started_at": _iso(row[1]),
                "posture": row[2] or "",
                "posture_reason": row[3] or "",
                "critical": row[4] or 0,
                "high": row[5] or 0,
                "requests": row[6] or 0,
                "denials": row[7] or 0,
                "confinement": row[8] or "",
            }
            for row in rows
        ]
    finally:
        exa.close()
