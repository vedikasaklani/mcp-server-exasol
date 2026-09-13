"""Coordinator for the remote, host-side Warden runner."""

from __future__ import annotations

import os
import asyncio
import threading
from datetime import datetime, timezone
from typing import Any

import httpx

from server_management.api.github_auth import get_installation_token
from server_management.database.db_config import session_scope
from server_management.database.db_models import (
    ManifestHistory,
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


class WardenSessionManager:
    def __init__(self) -> None:
        self._sessions: dict[str, str] = {}
        self._lock = threading.RLock()

    def reconcile_server(self, server_id: str, git_token: str | None = None) -> None:
        with session_scope() as db:
            manifest = db.get(ServerManifest, server_id)
            latest = (
                db.query(ScanRun)
                .filter(ScanRun.server_id == server_id)
                .order_by(ScanRun.started_at.desc())
                .first()
            )
            server = db.get(Server, server_id)
            if manifest is None or latest is None or server is None:
                return
            if latest.status not in _READY_STATUSES or not manifest.launch_executable:
                return
            if git_token is None:
                git_token = self._get_installation_token(server.installation_id)
            result = self._start_runner_session(
                server_id=server_id,
                repo_url=server.repo_url,
                commit_sha=latest.commit_sha,
                executable=manifest.launch_executable,
                args=list(manifest.launch_args or []),
                git_token=git_token,
            )
            self._record_approval(db, server_id, latest, result["profile_path"])
            with self._lock:
                self._sessions[server_id] = latest.commit_sha

    def _start_runner_session(
        self, *, server_id: str, repo_url: str, commit_sha: str,
        executable: str, args: list[str], git_token: str,
    ) -> dict[str, Any]:
        runner_url = os.environ.get("WARDEN_RUNNER_URL")
        if not runner_url:
            raise RuntimeError("WARDEN_RUNNER_URL is required for automated Warden sessions")
        headers = {}
        token = os.environ.get("WARDEN_RUNNER_TOKEN")
        if token:
            headers["Authorization"] = "Bearer " + token
        runner_endpoint = f"{runner_url.rstrip('/')}/sessions/{server_id}"
        try:
            response = httpx.post(
                runner_endpoint,
                json={
                    "server_id": server_id,
                    "repo_url": repo_url,
                    "commit_sha": commit_sha,
                    "executable": executable,
                    "args": args,
                    "git_token": git_token,
                },
                headers=headers,
                timeout=float(os.environ.get("WARDEN_RUNNER_TIMEOUT", "360")),
            )
        except httpx.RequestError as exc:
            raise RuntimeError(
                f"Warden runner is unreachable at {runner_endpoint}; "
                "check WARDEN_RUNNER_URL and Docker-to-WSL networking"
            ) from exc
        if response.is_error:
            raise RuntimeError(f"Warden runner rejected session: {response.text[-2000:]}")
        return response.json()

    @staticmethod
    def _get_installation_token(installation_id: int) -> str:
        """Exchange installation identity without nesting asyncio.run()."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(get_installation_token(installation_id))

        result: list[str] = []
        failure: list[Exception] = []

        def exchange() -> None:
            try:
                result.append(asyncio.run(get_installation_token(installation_id)))
            except Exception as exc:
                failure.append(exc)

        thread = threading.Thread(target=exchange, name="github-token-exchange")
        thread.start()
        thread.join()
        if failure:
            raise RuntimeError(
                f"GitHub installation token exchange failed for installation {installation_id}"
            ) from failure[0]
        if not result:
            raise RuntimeError("GitHub installation token exchange returned no token")
        return result[0]

    @staticmethod
    def _record_approval(db, server_id: str, latest: ScanRun, profile_path: str) -> None:
        manifest = db.get(ServerManifest, server_id)
        if manifest is None:
            raise RuntimeError(f"server manifest disappeared: {server_id}")
        if (
            manifest.warden_approved_commit == latest.commit_sha
            and manifest.warden_profile_path == profile_path
        ):
            return
        manifest.warden_profile_path = profile_path
        manifest.warden_approved_by = "vedika"
        manifest.warden_approved_at = datetime.now(timezone.utc).replace(tzinfo=None)
        manifest.warden_approved_commit = latest.commit_sha
        manifest.version = int(manifest.version) + 1
        db.add(ManifestHistory(
            server_id=server_id,
            version=int(manifest.version),
            allowed_destinations=manifest.allowed_destinations,
            tool_declarations=manifest.tool_declarations,
            change_reason="warden_profile_auto_approved",
        ))
        db.commit()

    def reconcile_all(self) -> None:
        with session_scope() as db:
            server_ids = [row[0] for row in db.query(ServerManifest.server_id).all()]
        for server_id in server_ids:
            try:
                self.reconcile_server(server_id)
            except Exception as exc:
                print(
                    f"warden runner reconciliation failed for {server_id}: {exc}",
                    flush=True,
                )

    def stop_server(self, server_id: str) -> None:
        runner_url = os.environ.get("WARDEN_RUNNER_URL")
        if runner_url:
            headers = {}
            token = os.environ.get("WARDEN_RUNNER_TOKEN")
            if token:
                headers["Authorization"] = "Bearer " + token
            response = httpx.delete(
                f"{runner_url.rstrip('/')}/sessions/{server_id}",
                headers=headers,
                timeout=float(os.environ.get("WARDEN_RUNNER_TIMEOUT", "30")),
            )
            if response.is_error and response.status_code != 404:
                raise RuntimeError(f"Warden runner failed to stop session: {response.text[-1000:]}")
        with self._lock:
            self._sessions.pop(server_id, None)


warden_sessions = WardenSessionManager()
