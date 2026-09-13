"""Registry & Manifest Service HTTP layer (Module 1).

Thin wrapper over onboard_services.py:
  - the operator, via POST /servers and PATCH /servers/{id}/manifest
  - your own internal services (Webhook Listener, Static Analysis Engine),
    via the /scan-runs endpoints
"""
from __future__ import annotations

import os
import uuid
from typing import Any

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from server_management.api import frontend, githubapp
from server_management.api.telemetry_api import router as telemetry_router
from server_management.api.models import (
    CreateScanRunRequest,
    LlmAnalysisResultRequest,
    ManifestResponse,
    RegisterServerRequest,
    RuleAnalysisResultRequest,
    ScanRunResponse,
    ServerResponse,
    ToolDeclarationsResponse,
    UpdateManifestRequest,
    ApproveWardenProfileRequest,
)
from server_management.database.db_config import get_db, session_scope
from server_management.database.db_models import (
    ScanRun,
    Server,
    ServerManifest,
)
from server_management.services.onboard_services import (
    create_scan_run,
    get_manifest,
    get_tool_declarations_for_llm_phase,
    mark_interrupted_scans_failed,
    record_llm_analysis_result,
    record_rule_analysis_result,
    register_server,
    update_manifest,
    approve_warden_profile,
    store_warden_profile,
)
from server_management.services.runtime_telemetry import resolve_server
from server_management.services.tool_catalog import list_tools
from server_management.services.warden_session_manager import warden_sessions
from server_management.services.sync import (
    sync_latest_manifest_history,
    sync_llm_phase_findings,
    sync_rule_phase_findings,
    sync_scan_run,
)

app = FastAPI()
# The dashboard is a browser app on its own origin (localhost:3000 in dev,
# whatever it's deployed to in prod) calling this API directly - without
# this, every request fails at the browser's CORS check before it even
# reaches a route. This is an internal ops tool behind its own network
# controls, not a public multi-tenant API, so a wide-open origin list is
# the right tradeoff here rather than hardcoding a deploy-specific origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Registered before the routers so it wins the match against the telemetry
# router's own /health, which reports `postgres: false` unconditionally
# because that module is deliberately Postgres-free. This app owns both
# stores, so its health check has to actually probe both - a dashboard that
# says "healthy" while Postgres is down is worse than no health check.
@app.get("/health")
def health() -> dict[str, Any]:
    exasol_ok = False
    try:
        import pyexasol

        exa = pyexasol.connect(
            dsn=os.environ["EXASOL_DSN"],
            user=os.environ["EXASOL_USER"],
            password=os.environ["EXASOL_PASSWORD"],
        )
        exa.execute("SELECT 1").fetchval()
        exa.close()
        exasol_ok = True
    except Exception:
        exasol_ok = False

    postgres_ok = False
    try:
        from sqlalchemy import text

        with session_scope() as db:
            db.execute(text("SELECT 1"))
        postgres_ok = True
    except Exception:
        postgres_ok = False

    return {
        "status": "ok" if (exasol_ok and postgres_ok) else "degraded",
        "exasol": exasol_ok,
        "postgres": postgres_ok,
    }


app.include_router(githubapp.router)
app.include_router(frontend.router)
app.include_router(telemetry_router)


@app.on_event("startup")
def recover_interrupted_scans():
    with session_scope() as db:
        mark_interrupted_scans_failed(db)
        _backfill_telemetry_identities(db)
    warden_sessions.reconcile_all()


def _backfill_telemetry_identities(db: Session) -> None:
    """Make sure every registered server exists in the telemetry store.

    Registration seeds this inline, but servers registered before that was
    the case - or during an Exasol outage - would otherwise stay invisible
    to every Exasol-backed endpoint forever. resolve_server is an upsert
    pinned to the PostgreSQL UUID, so re-running it is free and idempotent.
    """
    for server in db.query(Server).all():
        try:
            resolve_server(server.repo_url, "github", "", server.server_id)
        except Exception:
            continue


def _manifest_response(manifest: ServerManifest) -> ManifestResponse:
    return ManifestResponse(
        server_id=manifest.server_id,
        allowed_destinations=manifest.allowed_destinations,
        tool_declarations=manifest.tool_declarations,
        version=manifest.version,
        launch_executable=manifest.launch_executable,
        launch_args=manifest.launch_args or [],
        warden_profile_path=manifest.warden_profile_path,
        warden_approved_by=manifest.warden_approved_by,
        warden_approved_at=manifest.warden_approved_at.isoformat()
        if manifest.warden_approved_at else None,
        warden_approved_commit=manifest.warden_approved_commit,
    )


#for operators
@app.post("/servers", response_model=ServerResponse)
def api_register_server(
    req: RegisterServerRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    # Both of these surface as an opaque 500 otherwise, which reaches the
    # dashboard as a bare "Registration failed" with nothing an operator can
    # act on. They are the two overwhelmingly common ways registration is
    # refused, so each gets a status code and a message that says what to fix.
    try:
        server = register_server(
            db, repo_url=req.repo_url,
            installation_id=req.installation_id,
            allowed_destinations=req.allowed_destinations,
            launch_executable=req.launch_executable,
            launch_args=req.launch_args,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail=f"{req.repo_url} is already registered",
        ) from exc
    # Seed the Exasol side of the identity immediately, pinned to the
    # PostgreSQL UUID. Without this a server only becomes visible to the
    # telemetry store once a scan run syncs - so with no GitHub App
    # credentials configured (or any scan failure) it would stay invisible
    # to every Exasol-backed endpoint, including the dashboard's server
    # list, despite being perfectly registered here.
    try:
        resolve_server(
            server.repo_url,
            "github",
            "",
            server.server_id,
        )
    except Exception:
        # Registration is authoritative in PostgreSQL; a telemetry-store
        # hiccup must not fail it. The scan-run sync path re-resolves with
        # the same canonical id, so this self-heals.
        pass
    background_tasks.add_task(
        githubapp.start_initial_scan,
        server.server_id,
        server.repo_url,
        server.installation_id,
    )
    background_tasks.add_task(warden_sessions.reconcile_server, server.server_id)
    return ServerResponse(
        server_id=server.server_id,
        repo_url=server.repo_url,
        installation_id=server.installation_id,
    )


@app.get("/servers/{server_id}/manifest", response_model=ManifestResponse)
def api_get_manifest(server_id: str, db: Session = Depends(get_db)):
    manifest = get_manifest(db, server_id)
    if manifest is None:
        raise HTTPException(status_code=404, detail="server not found")
    return _manifest_response(manifest)

@app.patch("/servers/{server_id}/manifest", response_model=ManifestResponse)
def api_update_manifest(
    server_id: str, req: UpdateManifestRequest,
    background_tasks: BackgroundTasks, db: Session = Depends(get_db),
):
    try:
        manifest = update_manifest(
            db, server_id,
            allowed_destinations=req.allowed_destinations,
            launch_executable=req.launch_executable,
            launch_args=req.launch_args,
            change_reason="operator_edit",
        )
    except ValueError:
        raise HTTPException(status_code=404, detail="server not found")
    if req.launch_executable is not None or req.launch_args is not None:
        background_tasks.add_task(warden_sessions.stop_server, server_id)
    background_tasks.add_task(sync_latest_manifest_history, db, server_id)
    return _manifest_response(manifest)


@app.post("/servers/{server_id}/warden/approve", response_model=ManifestResponse)
def api_approve_warden_profile(
    server_id: str,
    req: ApproveWardenProfileRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    try:
        manifest = approve_warden_profile(
            db,
            server_id,
            profile_path=req.profile_path,
            commit_sha=req.commit_sha,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    background_tasks.add_task(warden_sessions.reconcile_server, server_id)
    return _manifest_response(manifest)


@app.post("/servers/{server_id}/warden/profile", response_model=ManifestResponse)
async def api_upload_warden_profile(
    server_id: str,
    background_tasks: BackgroundTasks,
    profile: UploadFile = File(..., description="Candidate Warden profile JSON"),
    db: Session = Depends(get_db),
):
    profile_bytes = await profile.read()
    if len(profile_bytes) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Warden profile is larger than 10 MiB")
    try:
        manifest = store_warden_profile(
            db,
            server_id,
            profile_bytes=profile_bytes,
            commit_sha=None,
            profile_root=os.environ.get("WARDEN_PROFILE_ROOT", "/warden-profile"),
        )
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    background_tasks.add_task(warden_sessions.reconcile_server, server_id)
    return _manifest_response(manifest)


class ToolCallRequest(BaseModel):
    tool_name: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)


def _gateway_address(server_id: str) -> str:
    """The running Warden gateway's address for server_id, starting a
    session on demand if none is cached yet - a dashboard shouldn't have to
    know or care whether a server's confined process happens to be warm
    already."""
    try:
        address = warden_sessions.live_address(server_id) or warden_sessions.reconcile_server(
            server_id
        )
    except HTTPException:
        raise
    except Exception as exc:
        # Bringing a sandbox up touches git, npm and gVisor, any of which
        # can fail for reasons an operator needs to read. Surfacing that as
        # a bare 500 with the text only in the server log makes the
        # dashboard's "couldn't start" state undiagnosable.
        raise HTTPException(
            status_code=502, detail=f"could not start a Warden session: {exc}"
        ) from exc
    if not address:
        raise HTTPException(
            status_code=503,
            detail=(
                "no active Warden session for this server - it needs an approved "
                "static analysis pass and a configured launch_executable before it "
                "can run live (see PATCH /servers/{id}/manifest and "
                "POST /servers/{id}/warden/approve)"
            ),
        )
    return address


def _rpc(address: str, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": method, "params": params or {}}
    try:
        response = httpx.post(f"http://{address}/rpc", json=payload, timeout=30.0)
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Warden gateway at {address} is unreachable: {exc}") from exc
    if response.is_error:
        raise HTTPException(status_code=502, detail=f"Warden gateway error: {response.text[-2000:]}")
    return response.json()


@app.get("/servers/{server_id}/live/tools")
def api_live_tools(server_id: str):
    """The server's live tool list straight from its own tools/list
    handshake - the freshest possible answer, as opposed to
    GET /servers/{id}/tools, which is the historical Exasol-persisted
    catalog used for browsing servers that aren't currently running."""
    address = _gateway_address(server_id)
    result = _rpc(address, "tools/list")
    return result.get("result", result)


@app.post("/servers/{server_id}/call")
def api_call_tool(server_id: str, req: ToolCallRequest):
    """Make a real tool call against a live, confined MCP server - the
    dashboard's "run a tool" action. warden-serve records the call (audit
    trail, security findings, latency) to Exasol on its own as it executes;
    nothing extra needs to happen here for that."""
    address = _gateway_address(server_id)
    result = _rpc(address, "tools/call", {"name": req.tool_name, "arguments": req.arguments})
    if "error" in result:
        raise HTTPException(status_code=422, detail=result["error"])
    return result.get("result", result)


@app.get("/servers/{server_id}/live/status")
def api_live_status(server_id: str):
    """Whether a Warden gateway is actually up for this server right now -
    the dashboard's "is this thing running" indicator, distinct from
    whether it has ever run (that's GET /servers/{id}/trust-score)."""
    address = warden_sessions.live_address(server_id)
    if not address:
        return {"running": False, "address": None}
    try:
        response = httpx.get(f"http://{address}/healthz", timeout=5.0)
        return {"running": response.status_code == 200, "address": address}
    except httpx.RequestError:
        return {"running": False, "address": address}


@app.get("/servers/{server_id}/live/metrics")
def api_live_metrics(server_id: str):
    """Live pool/traffic metrics straight from warden-serve - request
    counts, latency, container pool state - for the dashboard's real-time
    monitoring view. Complements the historical per-session summaries in
    GET /servers/{id}/sessions."""
    address = warden_sessions.live_address(server_id)
    if not address:
        raise HTTPException(status_code=503, detail="no active Warden session for this server")
    try:
        response = httpx.get(f"http://{address}/stats", timeout=5.0)
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Warden gateway at {address} is unreachable: {exc}") from exc
    if response.is_error:
        raise HTTPException(status_code=502, detail=f"Warden gateway error: {response.text[-2000:]}")
    return response.json()


@app.get("/tools")
def api_list_tools(server_id: str | None = None, q: str | None = None):
    """Global tool catalog across every registered server, Postgres-backed
    (mirrors Exasol's DIM_TOOL) - what the dashboard's tool-discovery/browse
    view lists and lets an operator pick from, independent of whether any
    particular server is live right now."""
    return list_tools(server_id=server_id, q=q)


#internal, service-to-service
@app.post("/scan-runs", response_model=ScanRunResponse)
def api_create_scan_run(req: CreateScanRunRequest, db: Session = Depends(get_db)):
    run = create_scan_run(db, server_id=req.server_id, commit_sha=req.commit_sha)
    return ScanRunResponse(
        scan_run_id=run.scan_run_id, server_id=run.server_id,
        commit_sha=run.commit_sha, status=run.status,
    )


@app.get("/scan-runs/{scan_run_id}", response_model=ScanRunResponse)
def api_get_scan_run(scan_run_id: str, db: Session = Depends(get_db)):
    run = db.get(ScanRun, scan_run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="scan run not found")
    return ScanRunResponse(
        scan_run_id=run.scan_run_id, server_id=run.server_id,
        commit_sha=run.commit_sha, status=run.status,
    )


@app.post("/scan-runs/{scan_run_id}/rule-analysis-result", response_model=ScanRunResponse)
def api_record_rule_analysis_result(
    scan_run_id: str, req: RuleAnalysisResultRequest,
    background_tasks: BackgroundTasks, db: Session = Depends(get_db),
):
    """Called by the rule-analysis phase"""
    run = record_rule_analysis_result(
        db, scan_run_id,
        verdict=req.verdict,
        rule_findings=req.rule_findings,
        tool_declarations=req.tool_declarations,
    )
    background_tasks.add_task(sync_rule_phase_findings, db, scan_run_id)
    background_tasks.add_task(sync_scan_run, db, scan_run_id)
    # Rule phase updates the manifest (tool_declarations) whenever verdict
    # != FAIL - harmless no-op re-sync of the same latest version otherwise.
    background_tasks.add_task(sync_latest_manifest_history, db, run.server_id)
    return ScanRunResponse(
        scan_run_id=run.scan_run_id, server_id=run.server_id,
        commit_sha=run.commit_sha, status=run.status,
    )


@app.get("/scan-runs/{scan_run_id}/llm-phase-input", response_model=ToolDeclarationsResponse)
def api_get_llm_phase_input(scan_run_id: str, db: Session = Depends(get_db)):
    """LLM-analysis phase fetches the tool_declarations from the
    manifest"""
    run = db.get(ScanRun, scan_run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="scan run not found")
    try:
        declarations = get_tool_declarations_for_llm_phase(db, run.server_id)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    return ToolDeclarationsResponse(tool_declarations=declarations)


@app.post("/scan-runs/{scan_run_id}/llm-analysis-result", response_model=ScanRunResponse)
def api_record_llm_analysis_result(
    scan_run_id: str, req: LlmAnalysisResultRequest,
    background_tasks: BackgroundTasks, db: Session = Depends(get_db),
):
    """Rejects with 409 if called before the rule phase"""
    try:
        run = record_llm_analysis_result(
            db, scan_run_id,
            verdict=req.verdict,
            llm_findings=req.llm_findings,
        )
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    background_tasks.add_task(sync_llm_phase_findings, db, scan_run_id)
    background_tasks.add_task(sync_scan_run, db, scan_run_id)
    return ScanRunResponse(
        scan_run_id=run.scan_run_id, server_id=run.server_id,
        commit_sha=run.commit_sha, status=run.status,
    )