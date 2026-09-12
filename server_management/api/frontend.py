"""Read-only API routes used by the server dashboard frontend."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from server_management.api.models import (
    ServerOverviewResponse,
    ServerScanDetailResponse,
    ServerScanHistoryResponse,
)
from server_management.database.db_config import get_db
from server_management.services.onboard_services import (
    get_server_dashboard,
    get_server_scan_detail,
    get_server_scan_history,
)

router = APIRouter(prefix="/frontend", tags=["frontend"])


@router.get("/servers/{server_id}", response_model=ServerOverviewResponse)
def get_server_dashboard_for_frontend(
    server_id: str, db: Session = Depends(get_db)
):
    dashboard = get_server_dashboard(db, server_id)
    if dashboard is None:
        raise HTTPException(status_code=404, detail="server not found")
    return dashboard


@router.get(
    "/servers/{server_id}/scan-history",
    response_model=ServerScanHistoryResponse,
)
def get_server_scan_history_for_frontend(
    server_id: str, db: Session = Depends(get_db)
):
    scans = get_server_scan_history(db, server_id)
    if scans is None:
        raise HTTPException(status_code=404, detail="server not found")
    return {"server_id": server_id, "scans": scans}


@router.get(
    "/servers/{server_id}/scans/{scan_id}",
    response_model=ServerScanDetailResponse,
)
def get_server_scan_detail_for_frontend(
    server_id: str, scan_id: str, db: Session = Depends(get_db)
):
    detail = get_server_scan_detail(db, server_id, scan_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return detail
