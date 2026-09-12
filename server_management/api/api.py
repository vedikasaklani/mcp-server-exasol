"""
api.py - Registry & Manifest Service HTTP layer (Module 1)
""" """
Thin wrapper over the onboard_services.py:
  - the operator, via POST /servers and PATCH /servers/{id}/manifest
  - your own internal services (Webhook Listener, Static Analysis Engine),
    via the /scan-runs endpoints
"""
from __future__ import annotations

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
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
from server_management.database.db_config import get_db
from server_management.database.db_models import (
    ScanRun,
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
)
from server_management.services.warden_session_manager import warden_sessions
from server_management.services.sync import (
    sync_latest_manifest_history,
    sync_llm_phase_findings,
    sync_rule_phase_findings,
    sync_scan_run,
)

app = FastAPI()
app.include_router(githubapp.router)
app.include_router(frontend.router)
app.include_router(telemetry_router)


@app.on_event("startup")
def recover_interrupted_scans():
    db = next(get_db())
    try:
        mark_interrupted_scans_failed(db)
    finally:
        db.close()
    warden_sessions.reconcile_all()


#for operators
@app.post("/servers", response_model=ServerResponse)
def api_register_server(
    req: RegisterServerRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    server = register_server(
        db, repo_url=req.repo_url,
        installation_id=req.installation_id,
        allowed_destinations=req.allowed_destinations,
        launch_executable=req.launch_executable,
        launch_args=req.launch_args,
    )
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
    return ManifestResponse(
        server_id=manifest.server_id,
        allowed_destinations=manifest.allowed_destinations,
        tool_declarations=manifest.tool_declarations,
        version=manifest.version,
        launch_executable=manifest.launch_executable,
        launch_args=manifest.launch_args or [],
        warden_profile_path=manifest.warden_profile_path,
        warden_approved_by=manifest.warden_approved_by,
        warden_approved_at=manifest.warden_approved_at.isoformat() if manifest.warden_approved_at else None,
        warden_approved_commit=manifest.warden_approved_commit,
    )

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
    return ManifestResponse(
        server_id=manifest.server_id,
        allowed_destinations=manifest.allowed_destinations,
        tool_declarations=manifest.tool_declarations,
        version=manifest.version,
        launch_executable=manifest.launch_executable,
        launch_args=manifest.launch_args or [],
        warden_profile_path=manifest.warden_profile_path,
        warden_approved_by=manifest.warden_approved_by,
        warden_approved_at=manifest.warden_approved_at.isoformat() if manifest.warden_approved_at else None,
        warden_approved_commit=manifest.warden_approved_commit,
    )


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
            approved_by=req.approved_by,
            commit_sha=req.commit_sha,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    background_tasks.add_task(warden_sessions.reconcile_server, server_id)
    return ManifestResponse(
        server_id=manifest.server_id,
        allowed_destinations=manifest.allowed_destinations,
        tool_declarations=manifest.tool_declarations,
        version=manifest.version,
        launch_executable=manifest.launch_executable,
        launch_args=manifest.launch_args or [],
        warden_profile_path=manifest.warden_profile_path,
        warden_approved_by=manifest.warden_approved_by,
        warden_approved_at=manifest.warden_approved_at.isoformat() if manifest.warden_approved_at else None,
        warden_approved_commit=manifest.warden_approved_commit,
    )


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