'''Pipeline for scanning, implementation empty currently'''
'''Do not remove print lines, they are important for logging'''
from sqlalchemy.orm import Session
from server_management.database.db_config import session as SessionLocal
from server_management.database.db_models import Server, ScanRun
from server_management.api.github_auth import get_installation_token

async def trigger_scan(scan_run_id: str) -> None:
    """Loads context for a scan run, exchanges for a repo access token,
    then hands off to analysis. Analysis itself is not wired up yet —
    tool choice (Semgrep vs. open-source alternatives) still open."""
    db: Session = SessionLocal()
    print("scan running...")
    try:
        run = db.get(ScanRun, scan_run_id)
        if run is None:
            return

        server = db.get(Server, run.server_id)
        if server is None:
            await scan_fail(scan_run_id, reason="server not found")
            return

        try:
            access_token = await get_installation_token(server.installation_id)
        except Exception as e:
            await scan_fail(scan_run_id, reason=f"token exchange failed: {e}")
            return

        # TODO: clone server.repo_url at run.commit_sha using access_token,
        # run static analysis, then call scan_pass(...) or scan_fail(...)
    finally:
        db.close()


async def scan_pass(scan_run_id: str, result: dict) -> None:
    print("scan has passed...")
    """TODO: record_rule_analysis_result(db, scan_run_id, verdict=..., 
    rule_findings=result["rule_findings"], tool_declarations=result["tool_declarations"])"""
    pass


async def scan_fail(scan_run_id: str, reason: str) -> None:
    print("scan has failed...")
    """TODO: mark the ScanRun REJECTED, persist the reason"""
    pass