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
        # server_id -> (commit_sha, gateway address "host:port"). The
        # address is what makes real-time tool calls possible: it's where
        # warden-serve is listening for this server's confined MCP process,
        # and it's the one piece of session state warden_runner.py's own
        # SessionResponse carries that nothing else persists anywhere.
        self._sessions: dict[str, tuple[str, str]] = {}
        self._lock = threading.RLock()

    def get_address(self, server_id: str) -> str | None:
        with self._lock:
            session = self._sessions.get(server_id)
            return session[1] if session else None

    def reconcile_server(self, server_id: str, git_token: str | None = None) -> str | None:
        """Ensure a session is running for server_id, starting one if
        needed. Returns the gateway address, or None if the server isn't
        ready to run yet (no approved static analysis, no launch_executable
        configured)."""
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
                return None
            if latest.status not in _READY_STATUSES:
                return None
            executable = manifest.launch_executable
            is_npm = server.repo_url.strip().lower().startswith("npm:")
            if not executable and is_npm:
                # An npm package declares its own entrypoint and the runner
                # reads it, so requiring an operator to name one first would
                # be asking them to restate what the package already says.
                # The interpreter is still explicit because gVisor loads the
                # launch executable by parsing its ELF header.
                executable = "node"
            if not executable:
                return None
            # The runner owns the real session state. Ask it before starting
            # anything: this process may have restarted, or the session may
            # have been started against the runner directly, and in both
            # cases a healthy gateway would otherwise be reported offline
            # and then needlessly torn down and rebuilt.
            adopted = self._adopt_runner_session(server_id, latest.commit_sha)
            if adopted is not None:
                return adopted
            if git_token is None:
                # A token is only needed for private repositories. Treating a
                # failed exchange as fatal means a misconfigured or absent
                # GitHub App takes down live sessions for public repos too,
                # which is the overwhelmingly common case here.
                try:
                    git_token = self._get_installation_token(server.installation_id)
                except Exception as exc:
                    print(
                        f"GitHub token exchange failed for {server_id}; "
                        f"continuing unauthenticated: {exc}",
                        flush=True,
                    )
                    git_token = None
            result = self._start_runner_session(
                server_id=server_id,
                repo_url=server.repo_url,
                commit_sha=latest.commit_sha,
                executable=executable,
                args=list(manifest.launch_args or []),
                git_token=git_token,
                env=dict(manifest.env or {}),
            )
            self._record_approval(db, server_id, latest, result["profile_path"])
            address = result["address"]
            with self._lock:
                self._sessions[server_id] = (latest.commit_sha, address)
            return address

    def live_address(self, server_id: str) -> str | None:
        """The gateway address if one is up right now, without starting one.

        Used by status/metrics reads, which must never have the side effect
        of launching a sandbox. Falls back to the runner so a restarted API
        still sees sessions it did not itself start.
        """
        # Ask the runner first rather than trusting the cache. The runner is
        # the only process that knows whether the gateway is still up, and a
        # session it has dropped (crash, restart, explicit stop) would
        # otherwise leave this cache pointing at a dead address indefinitely,
        # so every call would fail against a server the UI still shows live.
        # It is a local request on the critical path, so fall back to the
        # cache if the runner itself is unreachable.
        confirmed = self._adopt_runner_session(server_id, commit_sha=None)
        if confirmed is not None:
            return confirmed
        if self._runner_reachable():
            with self._lock:
                self._sessions.pop(server_id, None)
            return None
        return self.get_address(server_id)

    def _runner_reachable(self) -> bool:
        runner_url = os.environ.get("WARDEN_RUNNER_URL")
        if not runner_url:
            return False
        try:
            httpx.get(f"{runner_url.rstrip('/')}/docs", timeout=5.0)
            return True
        except httpx.RequestError:
            return False

    def _adopt_runner_session(self, server_id: str, commit_sha: str | None) -> str | None:
        """Re-attach to a live gateway the runner already has for this commit."""
        runner_url = os.environ.get("WARDEN_RUNNER_URL")
        if not runner_url:
            return None
        headers = {}
        token = os.environ.get("WARDEN_RUNNER_TOKEN")
        if token:
            headers["Authorization"] = "Bearer " + token
        try:
            response = httpx.get(
                f"{runner_url.rstrip('/')}/sessions/{server_id}",
                headers=headers,
                timeout=10.0,
            )
        except httpx.RequestError:
            return None
        if response.status_code != 200:
            return None
        payload = response.json()
        session_sha = payload.get("commit_sha")
        # A caller that named a commit wants that exact build; a status read
        # passes None and will take whatever is actually running.
        if commit_sha is not None and session_sha != commit_sha:
            return None
        address = payload.get("address")
        if not address or not session_sha:
            return None
        with self._lock:
            self._sessions[server_id] = (session_sha, address)
        return address

    def _start_runner_session(
        self, *, server_id: str, repo_url: str, commit_sha: str,
        executable: str, args: list[str], git_token: str | None,
        env: dict[str, str] | None = None,
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
                    "env": env or {},
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
