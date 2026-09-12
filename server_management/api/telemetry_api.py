"""HTTP API used by the standalone Exasol runtime proxy.

This module intentionally does not import the PostgreSQL database setup. The
proxy can send runtime telemetry when PostgreSQL is absent; Exasol is the only
required dependency for this service.
"""

from __future__ import annotations

import os
from typing import Any

import pyexasol
from fastapi import APIRouter, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from server_management.services.runtime_telemetry import (
    compute_scores,
    get_runtime_events,
    get_runtime_findings,
    get_sessions,
    get_tools,
    get_trust_score,
    resolve_server,
    write_runtime_events,
    write_runtime_findings,
    write_sast_findings,
    write_session,
    write_tools,
)

router = APIRouter()


class ResolveRequest(BaseModel):
    source: str = Field(min_length=1, max_length=500)
    kind: str = Field(min_length=1, max_length=50)
    ref: str = Field(default="", max_length=255)
    canonical_server_id: str | None = Field(default=None, max_length=255)


class RuntimeEvent(BaseModel):
    event_id: str = Field(min_length=1, max_length=255)
    tool_name: str = Field(default="", max_length=255)
    session_id: str | None = Field(default=None, max_length=64)
    event_ts: str | None = None
    agent_id: str | None = Field(default=None, max_length=255)
    destination_declared: str | None = Field(default=None, max_length=500)
    destination_actual: str | None = Field(default=None, max_length=500)
    destination_match: bool | None = None
    intent_match: bool | None = None
    sensitive_data_flag: bool = False
    sensitive_data_categories: list[str] = Field(default_factory=list)
    decision: str = Field(pattern="^(ALLOWED|BLOCKED|FLAGGED)$")
    decision_reason: str | None = Field(default=None, max_length=255)
    latency_ms: int = Field(ge=0, le=2147483647)
    status_code: int = Field(ge=0, le=99999)
    bytes_sent: int = Field(ge=0)
    bytes_received: int = Field(ge=0)
    retry_count: int = Field(ge=0, le=99999)


class RuntimeEventBatch(BaseModel):
    events: list[RuntimeEvent] = Field(min_length=1, max_length=100)


class RuntimeFindingBatch(BaseModel):
    findings: list[dict[str, Any]] = Field(min_length=1, max_length=100)


class SessionRequest(BaseModel):
    session: dict[str, Any]


class ToolDiscoveryRequest(BaseModel):
    tools: list[dict[str, Any]] = Field(min_length=1, max_length=500)
    source: str = Field(default="observed", pattern="^(declared|observed)$")


class SastFindingsRequest(BaseModel):
    findings: list[dict[str, Any]] = Field(default_factory=list, max_length=5000)
    tool_declarations: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    ref: str = Field(default="", max_length=255)


@router.get("/health")
def health() -> dict[str, Any]:
    try:
        exa = pyexasol.connect(
            dsn=os.environ["EXASOL_DSN"],
            user=os.environ["EXASOL_USER"],
            password=os.environ["EXASOL_PASSWORD"],
        )
        exa.execute("SELECT 1").fetchval()
        exa.close()
    except (KeyError, pyexasol.ExaConnectionError) as exc:
        raise HTTPException(status_code=503, detail=f"Exasol unavailable: {exc}") from exc
    return {"status": "ok", "exasol": True, "postgres": False}


@router.post("/servers/resolve")
def api_resolve_server(req: ResolveRequest) -> dict[str, str]:
    try:
        return {
            "server_id": resolve_server(
                req.source,
                req.kind,
                req.ref,
                req.canonical_server_id,
            )
        }
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/servers/{server_id}/runtime-events", status_code=202)
def api_write_runtime_events(server_id: str, req: RuntimeEventBatch) -> dict[str, int]:
    try:
        count = write_runtime_events(
            server_id,
            [event.model_dump(exclude_none=True) for event in req.events],
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"accepted": count}


@router.get("/servers/{server_id}/runtime-events")
def api_get_runtime_events(
    server_id: str,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, Any]]:
    return get_runtime_events(server_id, limit)


@router.get("/servers/{server_id}/tools")
def api_get_tools(server_id: str) -> list[dict[str, Any]]:
    return get_tools(server_id)


@router.post("/servers/{server_id}/tools", status_code=202)
def api_write_tools(
    server_id: str, req: ToolDiscoveryRequest
) -> dict[str, int]:
    try:
        count = write_tools(server_id, req.tools)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"accepted": count}


@router.post("/servers/{server_id}/sast-findings", status_code=202)
def api_write_sast_findings(
    server_id: str, req: SastFindingsRequest
) -> dict[str, int]:
    try:
        count = write_sast_findings(
            server_id, req.findings, req.tool_declarations, req.ref
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"accepted": count}


@router.post("/servers/{server_id}/runtime-findings", status_code=202)
def api_write_runtime_findings(
    server_id: str, req: RuntimeFindingBatch
) -> dict[str, int]:
    try:
        count = write_runtime_findings(server_id, req.findings)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"accepted": count}


@router.get("/servers/{server_id}/runtime-findings")
def api_get_runtime_findings(
    server_id: str,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, Any]]:
    return get_runtime_findings(server_id, limit)


@router.post("/servers/{server_id}/sessions", status_code=202)
def api_write_session(server_id: str, req: SessionRequest) -> dict[str, str]:
    try:
        write_session(server_id, req.session)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"status": "accepted"}


@router.get("/servers/{server_id}/sessions")
def api_get_sessions(
    server_id: str,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[dict[str, Any]]:
    return get_sessions(server_id, limit)


@router.post("/compute-scores")
def api_compute_scores() -> dict[str, str]:
    compute_scores()
    return {"status": "computed"}


@router.get("/servers/{server_id}/trust-score")
def api_get_trust_score(server_id: str) -> dict[str, Any]:
    score = get_trust_score(server_id)
    if score is None:
        raise HTTPException(status_code=404, detail="trust score not computed")
    return score


app = FastAPI(title="MCP Exasol Telemetry API")
app.include_router(router)
