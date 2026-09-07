"""
api.py - Registry & Manifest Service HTTP layer (Module 1)
""" """
Thin wrapper over the onboard_services.py:
  - the operator, via POST /servers and PATCH /servers/{id}/manifest
  - your own internal services (Webhook Listener, Static Analysis Engine),
    via the /scan-runs endpoints
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from server_management.db_models import (
    Base, ScanRun,
)
from server_management.onboard_services import(
    register_server, get_manifest, update_manifest,
    create_scan_run, record_rule_analysis_result, record_llm_analysis_result,
    get_tool_declarations_for_llm_phase,
)
from server_management.models import (ServerResponse, ManifestResponse, 
        ScanRunResponse, ToolDeclarationsResponse,RegisterServerRequest, UpdateManifestRequest
        , CreateScanRunRequest, RuleAnalysisResultRequest, LlmAnalysisResultRequest)
from server_management.db_config import get_db
import server_management.githubapp as githubapp

engine = create_engine("sqlite:///./registry.db")
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)

app = FastAPI()
app.include_router(githubapp.router)
#for operators
@app.post("/servers", response_model=ServerResponse)
def api_register_server(req: RegisterServerRequest, db: Session = Depends(get_db)):
    server = register_server(
        db, repo_url=req.repo_url,
        installation_id=req.installation_id,
        allowed_destinations=req.allowed_destinations,
    )
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
    )

@app.patch("/servers/{server_id}/manifest", response_model=ManifestResponse)
def api_update_manifest(server_id: str, req: UpdateManifestRequest, db: Session = Depends(get_db)):
    try:
        manifest = update_manifest(
            db, server_id,
            allowed_destinations=req.allowed_destinations,
            change_reason="operator_edit",
        )
    except ValueError:
        raise HTTPException(status_code=404, detail="server not found")
    return ManifestResponse(
        server_id=manifest.server_id,
        allowed_destinations=manifest.allowed_destinations,
        tool_declarations=manifest.tool_declarations,
        version=manifest.version,
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
    scan_run_id: str, req: RuleAnalysisResultRequest, db: Session = Depends(get_db)
):
    """Called by the rule-analysis phase"""
    run = record_rule_analysis_result(
        db, scan_run_id,
        verdict=req.verdict,
        rule_findings=req.rule_findings,
        tool_declarations=req.tool_declarations,
    )
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
    scan_run_id: str, req: LlmAnalysisResultRequest, db: Session = Depends(get_db)
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
    return ScanRunResponse(
        scan_run_id=run.scan_run_id, server_id=run.server_id,
        commit_sha=run.commit_sha, status=run.status,
    )