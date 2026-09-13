import asyncio
import hashlib
import hmac
import logging
import os
import traceback

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from server_management.api.github_auth import get_installation_token
from server_management.api.models import RegisterServerRequest
from server_management.database.db_config import get_db
from server_management.database.db_config import session_scope
from server_management.services.onboard_services import (
    create_scan_run,
    get_server_by_repo_and_installation,
    normalize_repo_url,
    register_server,
)
from server_management.services.scan_pipeline import trigger_scan

router = APIRouter(prefix="/github", tags=["github"])
logger = logging.getLogger(__name__)

GITHUB_WEBHOOK_SECRET = os.environ["GITHUB_WEBHOOK_SECRET"]


async def start_initial_scan(
    server_id: str, repo_url: str, installation_id: int
) -> None:
    try:
        owner_repo = normalize_repo_url(repo_url)
        token = await get_installation_token(installation_id)
        async with httpx.AsyncClient(
            base_url="https://api.github.com",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
            },
            timeout=20,
        ) as client:
            response = await client.get(f"/repos/{owner_repo}/commits", params={"per_page": 1})
            response.raise_for_status()
            commits = response.json()
        if not commits or not commits[0].get("sha"):
            raise RuntimeError("GitHub returned no commit for the repository default branch")

        with session_scope() as db:
            run = create_scan_run(db, server_id=server_id, commit_sha=commits[0]["sha"])
        print(f"BACKGROUND INITIAL SCAN STARTING: {run.scan_run_id}", flush=True)
        await trigger_scan(run.scan_run_id)
        print(f"BACKGROUND INITIAL SCAN FINISHED: {run.scan_run_id}", flush=True)
    except Exception:
        logger.exception("Initial scan could not start for server_id=%s", server_id)


@router.post("/register")
async def github_register(
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
        start_initial_scan,
        server.server_id,
        server.repo_url,
        server.installation_id,
    )
    logger.info("Registered server_id=%s; initial scan scheduled", server.server_id)
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
    html = f"""
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
        <label>Executable</label><br>
        <input type="text" id="launch_executable" placeholder="python3" style="width:100%" required><br><br>
        <label>Arguments (one per line)</label><br>
        <textarea id="launch_args" placeholder="-m&#10;my_mcp_server" style="width:100%"></textarea><br><br>
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
            launch_executable: document.getElementById('launch_executable').value.trim(),
            launch_args: document.getElementById('launch_args').value
              .split('\\n').map(s => s.trim()).filter(Boolean),
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
    return HTMLResponse(
        content=html,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
        },
    )