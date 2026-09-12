"""Approval-gated, one-process-per-server Warden session manager."""

from __future__ import annotations

import hashlib
import os
import socket
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path

from server_management.database.db_config import session as SessionLocal
from server_management.database.db_models import ScanRun, ScanStatus, ServerManifest


_READY_STATUSES = {
    ScanStatus.STATIC_ANALYSIS_PASSED,
    ScanStatus.BUILDING_CONTAINER,
    ScanStatus.SANDBOX_RUNNING,
    ScanStatus.SCORING,
    ScanStatus.COMPLETE,
}


@dataclass
class WardenSession:
    process: subprocess.Popen
    commit_sha: str
    address: str


class WardenSessionManager:
    def __init__(self) -> None:
        self._sessions: dict[str, WardenSession] = {}
        self._lock = threading.RLock()

    def reconcile_server(self, server_id: str) -> None:
        db = SessionLocal()
        try:
            manifest = db.get(ServerManifest, server_id)
            latest = (
                db.query(ScanRun)
                .filter(ScanRun.server_id == server_id)
                .order_by(ScanRun.started_at.desc())
                .first()
            )
            if manifest is None or latest is None:
                return
            if not self._eligible(manifest, latest):
                return
            self._start_or_replace(
                server_id,
                latest,
                manifest,
            )
        finally:
            db.close()

    def reconcile_all(self) -> None:
        db = SessionLocal()
        try:
            server_ids = [row[0] for row in db.query(ServerManifest.server_id).all()]
        finally:
            db.close()
        for server_id in server_ids:
            self.reconcile_server(server_id)

    def stop_server(self, server_id: str) -> None:
        with self._lock:
            session = self._sessions.pop(server_id, None)
            if session is not None and session.process.poll() is None:
                session.process.terminate()
                session.process.wait(timeout=10)

    @staticmethod
    def _eligible(manifest: ServerManifest, latest: ScanRun) -> bool:
        return bool(
            manifest.launch_executable
            and manifest.warden_profile_path
            and manifest.warden_approved_by
            and manifest.warden_approved_commit == latest.commit_sha
            and latest.status in _READY_STATUSES
            and Path(manifest.warden_profile_path).is_file()
            and os.environ.get("WARDEN_PROBE_BIN")
            and os.environ.get("WARDEN_SERVE_BIN")
        )

    def _start_or_replace(
        self,
        server_id: str,
        latest: ScanRun,
        manifest: ServerManifest,
    ) -> None:
        with self._lock:
            current = self._sessions.get(server_id)
            if current is not None and current.process.poll() is None:
                if current.commit_sha == latest.commit_sha:
                    return
                current.process.terminate()
                current.process.wait(timeout=10)
                self._sessions.pop(server_id, None)

            source_root = os.environ.get("WARDEN_SOURCE_ROOT")
            if not source_root:
                raise RuntimeError("WARDEN_SOURCE_ROOT is required for approved sessions")
            source_dir = Path(source_root).resolve() / server_id / latest.scan_run_id
            if not source_dir.is_dir():
                raise RuntimeError(f"accepted Warden source is missing: {source_dir}")

            address = self._allocate_address(server_id)
            session_id = f"{server_id}-{latest.commit_sha[:12]}"
            command = [
                os.environ["WARDEN_SERVE_BIN"],
                "-profile", manifest.warden_profile_path,
                "-probe", os.environ["WARDEN_PROBE_BIN"],
                "-addr", address,
                "-cwd", str(source_dir),
                "-session", session_id,
                "-env", f"WARDEN_SERVER_SOURCE={latest.server.repo_url}",
                *("--", manifest.launch_executable, *(manifest.launch_args or [])),
            ]
            process = subprocess.Popen(command, cwd=str(source_dir))
            self._sessions[server_id] = WardenSession(process, latest.commit_sha, address)
            threading.Thread(
                target=self._watch_process,
                args=(server_id, process),
                name=f"warden-watch-{server_id}",
                daemon=True,
            ).start()

    def _watch_process(self, server_id: str, process: subprocess.Popen) -> None:
        exit_code = process.wait()
        with self._lock:
            current = self._sessions.get(server_id)
            if current is None or current.process is not process:
                return
            self._sessions.pop(server_id, None)
        print(f"warden session exited: server_id={server_id} exit_code={exit_code}")

    @staticmethod
    def _allocate_address(server_id: str) -> str:
        base = int(os.environ.get("WARDEN_PORT_BASE", "18000"))
        offset = int(hashlib.sha256(server_id.encode()).hexdigest()[:6], 16) % 1000
        port = base + offset
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))
        return f"127.0.0.1:{port}"


warden_sessions = WardenSessionManager()
