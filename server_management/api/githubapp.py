import asyncio
import hashlib
import hmac
import logging
import os
import traceback

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from server_management.api.models import RegisterServerRequest
from server_management.database.db_config import get_db
from server_management.services.onboard_services import (
    create_scan_run,
    get_server_by_repo_and_installation,
    register_server,
)
from server_management.services.scan_pipeline import trigger_scan

router = APIRouter(prefix="/github", tags=["github"])
logger = logging.getLogger(__name__)

GITHUB_WEBHOOK_SECRET = os.environ["GITHUB_WEBHOOK_SECRET"]


@router.post("/register")
def github_register(req: RegisterServerRequest, db: Session = Depends(get_db)):
    server = register_server(
        db, repo_url=req.repo_url,
        installation_id=req.installation_id,
        allowed_destinations=req.allowed_destinations,
    )
    return {"server_id": server.server_id}


def _verify_signature(body: bytes, signature_header: str | None) -> None:
    if not signature_header:
        raise HTTPException(401, "Missing signature")
    expected = "sha256=" + hmac.new(GITHUB_WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature_header):
        raise HTTPException(401, "Invalid signature")

def _run_scan_background(scan_run_id: str) -> None:
    print(f"BACKGROUND SCAN STARTING: {scan_run_id}", flush=True)
    try:
        asyncio.run(trigger_scan(scan_run_id))
        print(f"BACKGROUND SCAN FINISHED: {scan_run_id}", flush=True)
    except Exception as e:
        print(f"BACKGROUND SCAN CRASHED: {scan_run_id}: {e}", flush=True)
        traceback.print_exc()

@router.post("/webhook")
async def github_webhook(request: Request, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    body = await request.body()
    _verify_signature(body, request.headers.get("X-Hub-Signature-256"))

    if request.headers.get("X-GitHub-Event") != "push":
        logger.info("Ignoring GitHub webhook: event is not push")
        return {"status": "ignored"}

    payload = await request.json()

    if payload.get("ref") != "refs/heads/main":
        logger.info("Ignoring GitHub webhook: ref is not main")
        return {"status": "ignored", "reason": "not main branch"}
    if payload.get("deleted"):
        logger.info("Ignoring GitHub webhook: branch was deleted")
        return {"status": "ignored", "reason": "branch deleted"}

    installation_id = payload["installation"]["id"]
    repo_url = payload["repository"]["clone_url"]
    commit_sha = payload["after"]

    server = get_server_by_repo_and_installation(db, repo_url, installation_id)
    if server is None:
        logger.warning(
            "Ignoring GitHub webhook: no registered server for repo=%s installation_id=%s",
            repo_url,
            installation_id,
        )
        return {"status": "ignored", "reason": "unregistered server"}
    run = create_scan_run(db, server_id=server.server_id, commit_sha=commit_sha)
    background_tasks.add_task(_run_scan_background, run.scan_run_id)
    logger.info("Background scan task added: scan_run_id=%s", run.scan_run_id)
    print(f"Background to trigger scan added {run.scan_run_id}", flush=True)
    return {"status": "accepted"}


@router.get("/setup", response_class=HTMLResponse)
def github_setup(request: Request):
    installation_id = request.query_params.get("installation_id", "")
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Register MCP Server</title></head>
    <body style="font-family: sans-serif; max-width: 480px; margin: 40px auto;">
      <h2>Register your MCP server</h2>
      <form id="register-form">
        <input type="hidden" id="installation_id" value="{installation_id}">
        <label>Repository URL</label><br>
        <input type="text" id="repo_url" placeholder="https://github.com/you/repo.git" style="width:100%" required><br><br>
        <label>Allowed destinations (comma-separated)</label><br>
        <input type="text" id="allowed_destinations" placeholder="api.example.com, api.stripe.com" style="width:100%" required><br><br>
        <button type="submit">Register</button>
      </form>
      <p id="result"></p>
      <script>
        document.getElementById('register-form').addEventListener('submit', async (e) => {{
          e.preventDefault();
          const payload = {{
            repo_url: document.getElementById('repo_url').value,
            installation_id: parseInt(document.getElementById('installation_id').value),
            allowed_destinations: document.getElementById('allowed_destinations').value
              .split(',').map(s => s.trim()).filter(Boolean),
          }};
          const resp = await fetch('/github/register', {{
            method: 'POST',
            headers: {{'Content-Type': 'application/json'}},
            body: JSON.stringify(payload),
          }});
          const data = await resp.json();
          document.getElementById('result').textContent = resp.ok
            ? `Registered! server_id: ${{data.server_id}}`
            : `Error: ${{JSON.stringify(data)}}`;
        }});
      </script>
    </body>
    </html>
    """