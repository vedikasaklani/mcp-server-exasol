"""Warden session + Exasol sync health check, run from a clean state.

Designed to run INSIDE the API container via scripts/warden_healthcheck.ps1.
For every registered server that has a launch spec and a ready scan it:

  1. finds the latest scan run (commit) for the server
  2. clears any stale Warden runner session for the server (idempotent rerun,
     frees the deterministic port before a fresh start)
  3. starts a fresh session through the runner POST (checkout -> observe ->
     serve) and reports the result or the runner's real error
  4. resyncs Exasol for that scan run directly through the idempotent sync
     helpers in server_management/services/sync.py

It deliberately does NOT replay the rule/llm-analysis-result HTTP endpoints:
those INSERT rows keyed by SCAN_RUN_ID, so replaying them on an already
recorded run would hit a primary-key conflict. Exasol resync is done via the
MERGE-based sync helpers instead, which are safe to run any number of times
and never mutate PostgreSQL scan verdicts.

Exit code 0 = everything passed; 1 = any failure.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import traceback

import httpx

from server_management.database.db_config import session as SessionLocal
from server_management.database.db_models import (
    LlmAnalysisResult,
    RuleAnalysisResult,
    ScanRun,
    ScanStatus,
    Server,
    ServerManifest,
)

_READY_STATUSES = {
    ScanStatus.STATIC_ANALYSIS_PASSED,
    ScanStatus.BUILDING_CONTAINER,
    ScanStatus.SANDBOX_RUNNING,
    ScanStatus.SCORING,
    ScanStatus.COMPLETE,
}

DEFAULT_RUNNER_URL = "http://host.docker.internal:8100"


def _candidate_servers(db, server_filter: str | None) -> list[dict]:
    manifests = db.query(ServerManifest).filter(ServerManifest.launch_executable.isnot(None)).all()
    out = []
    for man in manifests:
        if server_filter and man.server_id != server_filter:
            continue
        latest = (
            db.query(ScanRun)
            .filter_by(server_id=man.server_id)
            .order_by(ScanRun.started_at.desc())
            .first()
        )
        server = db.get(Server, man.server_id)
        if latest is None or server is None:
            continue
        if latest.status not in _READY_STATUSES:
            continue
        out.append({
            "server_id": man.server_id,
            "repo_url": server.repo_url,
            "installation_id": server.installation_id,
            "commit_sha": latest.commit_sha,
            "scan_run_id": latest.scan_run_id,
            "executable": man.launch_executable,
            "args": list(man.launch_args or []),
        })
    return out


def _installation_token(installation_id: int) -> str | None:
    try:
        from server_management.api.github_auth import get_installation_token
        return asyncio.run(get_installation_token(installation_id))
    except Exception as exc:
        print(f"    note: no git token (using public-repo checkout): {exc}")
        return None


def _test_session(client: httpx.Client, base: str, token: str | None, spec: dict) -> bool:
    url = f"{base.rstrip('/')}/sessions/{spec['server_id']}"
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    try:
        client.delete(url, headers=headers, timeout=30)
    except httpx.RequestError:
        pass  # stale session might not exist; ignore

    payload = {
        "server_id": spec["server_id"],
        "repo_url": spec["repo_url"],
        "commit_sha": spec["commit_sha"],
        "executable": spec["executable"],
        "args": spec["args"],
        "git_token": _installation_token(spec["installation_id"]),
    }
    print(
        f"  session start  {spec['executable']} {' '.join(spec['args'])} "
        f"@{spec['commit_sha'][:12]}"
    )
    resp = client.post(url, json=payload, headers=headers, timeout=360)
    if resp.status_code == 401:
        print("  FAIL: runner rejected credentials — make WARDEN_RUNNER_TOKEN match "
              "on the runner AND this container")
        return False
    if resp.status_code >= 400:
        try:
            detail = resp.json().get("detail", resp.text)
        except Exception:
            detail = resp.text
        print(f"  FAIL ({resp.status_code}): {detail}")
        return False
    data = resp.json()
    print(f"  OK  profile={data['profile_path']} address={data['address']} reused={data['reused']}")
    return True


def _resync_exasol(server_id: str, scan_run_id: str) -> bool:
    from server_management.services.sync import (
        sync_latest_manifest_history,
        sync_llm_phase_findings,
        sync_rule_phase_findings,
        sync_scan_run,
    )

    db = SessionLocal()
    try:
        sync_scan_run(db, scan_run_id)
        if db.get(RuleAnalysisResult, scan_run_id) is not None:
            sync_rule_phase_findings(db, scan_run_id)
        if db.get(LlmAnalysisResult, scan_run_id) is not None:
            sync_llm_phase_findings(db, scan_run_id)
        sync_latest_manifest_history(db, server_id)
    finally:
        db.close()
    print("  OK  Exasol resync done (FACT_SCAN_RUN, findings, manifest history)")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--server", help="only test this server_id")
    ap.add_argument("--no-session", action="store_true", help="skip the Warden session test")
    ap.add_argument("--no-sync", action="store_true", help="skip the Exasol resync")
    ap.add_argument("--runner-url", default=os.environ.get("WARDEN_RUNNER_URL", DEFAULT_RUNNER_URL))
    ap.add_argument("--runner-token", default=os.environ.get("WARDEN_RUNNER_TOKEN"))
    args = ap.parse_args()

    print(f"preflight: runner at {args.runner_url}")
    try:
        resp = httpx.get(f"{args.runner_url.rstrip('/')}/docs", timeout=10)
        if resp.status_code != 200:
            print("FAIL: Warden runner is not answering. Start uvicorn on the host "
                  "(scripts/warden_runner start) and retry.")
            return 1
    except httpx.RequestError as exc:
        print(f"FAIL: Warden runner unreachable at {args.runner_url}: {exc}")
        return 1
    print("preflight: runner is up")

    db = SessionLocal()
    try:
        specs = _candidate_servers(db, args.server)
    finally:
        db.close()
    if not specs:
        print("no eligible servers (need a manifest launch spec and a ready scan run)")
        return 0

    failed = 0
    with httpx.Client(timeout=360) as client:
        for spec in specs:
            print(f"\n[{spec['server_id']}] {spec['repo_url']} (@{spec['commit_sha'][:12]})")
            if not args.no_session:
                if not _test_session(client, args.runner_url, args.runner_token, spec):
                    failed += 1
            if not args.no_sync:
                try:
                    if not _resync_exasol(spec["server_id"], spec["scan_run_id"]):
                        failed += 1
                except Exception as exc:
                    print(f"  FAIL: Exasol resync: {exc}")
                    traceback.print_exc()
                    failed += 1
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())