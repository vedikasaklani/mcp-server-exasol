"""Host-side Warden runner.

This service belongs on the Ubuntu/WSL host that has git, runsc, and the
Warden binaries. The API service submits repository identity and a commit;
this process owns checkout, profile generation, and the long-lived gateway.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, SecretStr

app = FastAPI(title="Warden runner")
_SHA = re.compile(r"^[0-9a-fA-F]{7,64}$")

# Filesystem types fast enough for gVisor to run a confined process from
# without blowing the warmup handshake's timeout. Anything else (9p/drvfs -
# a WSL2 Windows-drive mount being the classic case, but also cifs/nfs/fuse)
# is flagged rather than enumerated by name, since the failure mode is the
# same regardless of which slow network/virtio filesystem it is.
_FAST_FSTYPES = {"ext4", "ext3", "ext2", "xfs", "btrfs", "overlay", "overlay2", "tmpfs", "f2fs", "zfs"}


def _mount_fstype(path: str) -> str:
    """Filesystem type of the mount that owns path, via /proc/mounts'
    longest-prefix match. Best-effort: returns "" (treated as fine) rather
    than raising if it can't be determined - a platform without /proc, or a
    path with no matching entry, should never block a caller on its own."""
    try:
        resolved = os.path.realpath(path)
        best_mount, best_fstype = "", ""
        with open("/proc/mounts", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                mount_point = parts[1].replace("\\040", " ")
                if resolved == mount_point or resolved.startswith(mount_point.rstrip("/") + "/"):
                    if len(mount_point) > len(best_mount):
                        best_mount, best_fstype = mount_point, parts[2]
        return best_fstype
    except OSError:
        return ""


def _preflight_native_fs(path: str, what: str) -> None:
    """Fail in milliseconds with an actionable error instead of after a
    30s+ gVisor warmup timeout. Confirmed root cause of a real failure: a
    launch_executable (a Python venv interpreter) living under WSL2's
    /mnt/c/... drvfs mount made every syscall gVisor intercepted for it slow
    enough that the container never finished starting before warden-serve's
    handshake gave up - "warmup:initialize timed out after 30s" and/or
    "timed out after 15s waiting for canary handshake" are both this same
    underlying cause, just caught at different points in container bring-up.
    """
    fstype = _mount_fstype(path)
    if not fstype or fstype in _FAST_FSTYPES:
        return
    raise RuntimeError(
        f"{what} at {path!r} is on a {fstype!r} filesystem, which gVisor's per-syscall "
        "interception makes far too slow for the confined process to start within the "
        "warmup timeout (symptom: 'warmup:initialize timed out after 30s' or 'timed out "
        "after 15s waiting for canary handshake'). This is almost always a WSL2 "
        "Windows-drive mount (/mnt/c/...) - move the project (and any venv on it) onto a "
        "native Linux path inside WSL, e.g. ~/mcp-server-exasol, recreate the venv there, "
        "and register that path as the launch_executable instead."
    )


class SessionRequest(BaseModel):
    server_id: str = Field(min_length=1)
    repo_url: str = Field(min_length=1)
    commit_sha: str = Field(min_length=7, max_length=64)
    executable: str = Field(min_length=1)
    args: list[str] = Field(default_factory=list)
    git_token: SecretStr | None = Field(default=None, min_length=1)
    approver: str = Field(default="vedika", min_length=1, max_length=100)


class SessionResponse(BaseModel):
    server_id: str
    commit_sha: str
    profile_path: str
    address: str
    reused: bool


class _Session:
    def __init__(self, process: subprocess.Popen, commit_sha: str, address: str, source_dir: str):
        self.process = process
        self.commit_sha = commit_sha
        self.address = address
        self.source_dir = source_dir


class Runner:
    def __init__(self) -> None:
        self._sessions: dict[str, _Session] = {}
        self._lock = threading.RLock()

    def ensure_session(self, request: SessionRequest) -> SessionResponse:
        if not _SHA.fullmatch(request.commit_sha):
            raise ValueError("commit_sha must be a hexadecimal git commit")
        resolved_exe = shutil.which(request.executable) or request.executable
        if os.path.exists(resolved_exe):
            _preflight_native_fs(resolved_exe, "launch executable")
        with self._lock:
            current = self._sessions.get(request.server_id)
            if current and current.process.poll() is None and current.commit_sha == request.commit_sha:
                profile = self._profile_path(request.server_id, request.commit_sha)
                return SessionResponse(
                    server_id=request.server_id,
                    commit_sha=request.commit_sha,
                    profile_path=str(profile),
                    address=current.address,
                    reused=True,
                )
            self.stop(request.server_id)
            source_dir = self._checkout(
                request.repo_url,
                request.commit_sha,
                request.git_token.get_secret_value() if request.git_token else None,
            )
            profile = self._profile_path(request.server_id, request.commit_sha)
            profile.parent.mkdir(parents=True, exist_ok=True)
            self._observe(source_dir, profile, request)
            address = self._allocate_address(request.server_id)
            process = self._serve(source_dir, profile, address, request)
            self._sessions[request.server_id] = _Session(
                process, request.commit_sha, address, source_dir
            )
            threading.Thread(
                target=self._watch,
                args=(request.server_id, process, source_dir),
                name=f"warden-runner-watch-{request.server_id}",
                daemon=True,
            ).start()
            return SessionResponse(
                server_id=request.server_id,
                commit_sha=request.commit_sha,
                profile_path=str(profile),
                address=address,
                reused=False,
            )

    def stop(self, server_id: str) -> None:
        current = self._sessions.pop(server_id, None)
        if current is None:
            return
        if current.process.poll() is None:
            current.process.terminate()
            try:
                current.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                current.process.kill()
                current.process.wait(timeout=5)
        shutil.rmtree(current.source_dir, ignore_errors=True)

    def _checkout(self, repo_url: str, commit_sha: str, git_token: str | None) -> str:
        source_dir = tempfile.mkdtemp(prefix="warden-runner-")
        askpass = None
        try:
            env = os.environ.copy()
            if git_token:
                askpass = tempfile.NamedTemporaryFile(
                    mode="w", prefix="warden-git-askpass-", delete=False
                )
                askpass.write("#!/bin/sh\ncase \"$1\" in\n*Username*) echo x-access-token;;\n*) echo \"$WARDEN_GIT_TOKEN\";;\nesac\n")
                askpass.close()
                os.chmod(askpass.name, 0o700)
                env["GIT_ASKPASS"] = askpass.name
                env["GIT_TERMINAL_PROMPT"] = "0"
                env["WARDEN_GIT_TOKEN"] = git_token
            _run(
                ["git", "clone", "--no-checkout", _clone_url(repo_url), source_dir],
                env=env,
                timeout=180,
            )
            _run(
                ["git", "-C", source_dir, "fetch", "--depth", "1", "origin", commit_sha],
                env=env,
                timeout=180,
            )
            _run(["git", "-C", source_dir, "checkout", "--detach", "--quiet", commit_sha], timeout=60)
            return source_dir
        except Exception:
            shutil.rmtree(source_dir, ignore_errors=True)
            raise
        finally:
            if askpass:
                try:
                    os.unlink(askpass.name)
                except FileNotFoundError:
                    pass

    def _observe(self, source_dir: str, profile: Path, request: SessionRequest) -> None:
        observe = os.environ.get("WARDEN_OBSERVE_BIN")
        if not observe:
            raise RuntimeError("WARDEN_OBSERVE_BIN is required on the Warden runner")
        command = [observe, "--emit-profile", str(profile), "--", request.executable, *request.args]
        _run(command, cwd=source_dir, timeout=int(os.environ.get("WARDEN_OBSERVE_TIMEOUT", "300")))
        self._stamp_approval(profile, request)

    def _stamp_approval(self, profile: Path, request: SessionRequest) -> None:
        approver = request.approver or os.environ.get("WARDEN_APPROVER") or "vedika"
        try:
            data = json.loads(profile.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise RuntimeError(
                "warden-observe did not write the profile; inspect the observe output above"
            )
        data["approved_by"] = approver
        profile.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        print(f"profile approved_by={approver}: {profile}", flush=True)

    def _serve(self, source_dir: str, profile: Path, address: str, request: SessionRequest) -> subprocess.Popen:
        serve = os.environ.get("WARDEN_SERVE_BIN")
        probe = os.environ.get("WARDEN_PROBE_BIN")
        if not serve or not probe:
            raise RuntimeError("WARDEN_SERVE_BIN and WARDEN_PROBE_BIN are required on the Warden runner")
        telemetry_api = os.environ.get("WARDEN_TELEMETRY_API")
        if not telemetry_api:
            raise RuntimeError(
                "WARDEN_TELEMETRY_API is required on the Warden runner "
                "(e.g. http://127.0.0.1:8000); without it runtime events are not stored"
            )
        session_id = f"{request.server_id}-{request.commit_sha[:12]}"
        command = [
            serve, "-profile", str(profile), "-probe", probe, "-addr", address,
            "-cwd", source_dir, "-session", session_id,
            "-telemetry-api", telemetry_api,
            "-env", f"WARDEN_SERVER_SOURCE={request.repo_url}",
        ]
        request_timeout = os.environ.get("WARDEN_REQUEST_TIMEOUT")
        if request_timeout:
            command += ["-request-timeout", request_timeout]
        command += ["--", request.executable, *request.args]
        return subprocess.Popen(command, cwd=source_dir)

    def _watch(self, server_id: str, process: subprocess.Popen, source_dir: str) -> None:
        exit_code = process.wait()
        with self._lock:
            current = self._sessions.get(server_id)
            if current and current.process is process:
                self._sessions.pop(server_id, None)
        shutil.rmtree(source_dir, ignore_errors=True)
        print(f"warden session exited: server_id={server_id} exit_code={exit_code}", flush=True)

    @staticmethod
    def _profile_path(server_id: str, commit_sha: str) -> Path:
        root = Path(os.environ.get("WARDEN_PROFILE_ROOT", "~/.warden/profiles")).expanduser()
        return root / server_id / f"{commit_sha}.json"

    @staticmethod
    def _allocate_address(server_id: str) -> str:
        base = int(os.environ.get("WARDEN_PORT_BASE", "18000"))
        port = base + int(hashlib.sha256(server_id.encode()).hexdigest()[:6], 16) % 1000
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))
        return f"127.0.0.1:{port}"


def _clone_url(repo_url: str) -> str:
    value = repo_url.strip()
    if value.startswith("git@github.com:"):
        return f"https://github.com/{value.split(':', 1)[1]}"
    if value.startswith("http://") or value.startswith("https://"):
        base = value.removesuffix(".git")
    else:
        base = f"https://github.com/{value.removesuffix('.git')}"
    return base


def _run(
    command: list[str], *, cwd: str | None = None,
    env: dict[str, str] | None = None, timeout: int,
) -> None:
    result = subprocess.run(
        command, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout
    )
    if result.returncode:
        stderr = result.stderr.strip()
        stdout = result.stdout.strip()
        detail = "\n".join(part for part in (stderr, stdout) if part)[-4000:]
        raise RuntimeError(f"command failed ({result.returncode}): {detail}")


runner = Runner()


@app.post("/sessions/{server_id}", response_model=SessionResponse)
def start_session(
    server_id: str,
    request: SessionRequest,
    authorization: str | None = Header(default=None),
) -> SessionResponse:
    expected = os.environ.get("WARDEN_RUNNER_TOKEN")
    if expected and authorization != "Bearer " + expected:
        raise HTTPException(status_code=401, detail="invalid runner credentials")
    if request.server_id != server_id:
        raise HTTPException(status_code=400, detail="server_id path and body do not match")
    try:
        return runner.ensure_session(request)
    except (RuntimeError, OSError, ValueError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.delete("/sessions/{server_id}", status_code=204)
def stop_session(server_id: str, authorization: str | None = Header(default=None)) -> None:
    expected = os.environ.get("WARDEN_RUNNER_TOKEN")
    if expected and authorization != "Bearer " + expected:
        raise HTTPException(status_code=401, detail="invalid runner credentials")
    runner.stop(server_id)
