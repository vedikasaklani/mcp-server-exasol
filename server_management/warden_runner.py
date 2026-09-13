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
import sys
import tempfile
import threading
import time
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, SecretStr

from server_management.services.source_scan import (
    extract_tools,
    scan_package_metadata,
    scan_source,
    verdict_for,
)

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
    env: dict[str, str] = Field(default_factory=dict)
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
            if request.repo_url.strip().lower().startswith("npm:"):
                source_dir = self._install_npm_package(request.repo_url)
                if not request.args:
                    detected = self._npm_entrypoint(source_dir, request.repo_url)
                    if detected is None:
                        shutil.rmtree(source_dir, ignore_errors=True)
                        raise RuntimeError(
                            f"{request.repo_url} declares no bin or main entrypoint; "
                            "set launch_args explicitly"
                        )
                    request = request.model_copy(update={"args": detected})
            else:
                source_dir = self._checkout(
                    request.repo_url,
                    request.commit_sha,
                    request.git_token.get_secret_value() if request.git_token else None,
                )
                self._install_dependencies(source_dir)
            profile = self._profile_path(request.server_id, request.commit_sha)
            profile.parent.mkdir(parents=True, exist_ok=True)
            self._observe(source_dir, profile, request)
            address = self._allocate_address(request.server_id)
            process = self._serve(source_dir, profile, address, request)
            self._wait_until_serving(address, process)
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

    @staticmethod
    def _wait_until_serving(address: str, process: subprocess.Popen) -> None:
        """Block until the gateway actually accepts connections.

        warden-serve has to warm a pool of confined containers before it
        binds, so it is not reachable the instant Popen returns. Reporting
        the session as started before then hands the caller an address that
        refuses connections, and the first tool call after bringing a server
        live fails for no reason the operator can see.
        """
        host, _, port = address.rpartition(":")
        deadline = time.monotonic() + float(
            os.environ.get("WARDEN_SERVE_READY_TIMEOUT", "120")
        )
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(
                    f"warden-serve exited with code {process.returncode} "
                    "before it began serving"
                )
            try:
                with socket.create_connection((host, int(port)), timeout=2):
                    return
            except OSError:
                time.sleep(0.25)
        raise RuntimeError(f"warden-serve did not start serving on {address} in time")

    def lookup(self, server_id: str) -> SessionResponse | None:
        """Report a live session without starting one.

        The runner is the only process that actually knows which gateways
        are up. Without a read-only view of that, a restarted API - or one
        that simply never started this session itself - has no way to reach
        a perfectly healthy gateway, and reports the server as offline.
        """
        with self._lock:
            current = self._sessions.get(server_id)
            if current is None or current.process.poll() is not None:
                return None
            return SessionResponse(
                server_id=server_id,
                commit_sha=current.commit_sha,
                profile_path=str(self._profile_path(server_id, current.commit_sha)),
                address=current.address,
                reused=True,
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

    @staticmethod
    def _install_npm_package(repo_url: str) -> str:
        """Materialise an npm-published MCP server into a source directory.

        Installed unconfined on the host for the same reason a git checkout's
        dependencies are - see sandbox/fetch's package doc. Only the server
        itself runs confined.
        """
        spec = repo_url.strip()[4:]
        source_dir = tempfile.mkdtemp(prefix="warden-runner-npm-")
        try:
            print(
                "installing npm package (UNCONFINED on this host - see "
                "sandbox/fetch's package doc for the tradeoff)",
                flush=True,
            )
            _run(
                ["npm", "install", "--no-audit", "--no-fund", "--prefix", source_dir, spec],
                timeout=900,
            )
            return source_dir
        except Exception:
            shutil.rmtree(source_dir, ignore_errors=True)
            raise

    @staticmethod
    def _npm_package_name(repo_url: str) -> str:
        spec = repo_url.strip()[4:]
        return spec[: spec.rindex("@")] if "@" in spec.lstrip("@") else spec

    @staticmethod
    def _npm_package_dir(source_dir: str, repo_url: str) -> str | None:
        path = Path(source_dir) / "node_modules" / Runner._npm_package_name(repo_url)
        return str(path) if path.is_dir() else None

    @staticmethod
    def _npm_entrypoint(source_dir: str, repo_url: str) -> list[str] | None:
        """The package's own declared executable, as a path under source_dir.

        An npm package already states where its entrypoint is, so requiring
        an operator to rediscover it by reading node_modules is needless -
        and the obvious guess, `npx <pkg>`, cannot work: gVisor loads the
        launch executable by parsing its ELF header, and npx is a script.
        """
        name = Runner._npm_package_name(repo_url)
        pkg_json = Path(source_dir) / "node_modules" / name / "package.json"
        if not pkg_json.is_file():
            return None
        try:
            manifest = json.loads(pkg_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        entry = manifest.get("bin")
        if isinstance(entry, dict):
            entry = next(iter(entry.values()), None)
        if not entry:
            entry = manifest.get("main")
        if not isinstance(entry, str) or not entry:
            return None
        resolved = (Path("node_modules") / name / entry).as_posix()
        if not (Path(source_dir) / resolved).is_file():
            return None
        return [resolved]

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

    @staticmethod
    def _has_npm_script(source_dir: str, name: str) -> bool:
        try:
            with open(os.path.join(source_dir, "package.json"), encoding="utf-8") as f:
                return bool(json.load(f).get("scripts", {}).get(name))
        except (OSError, json.JSONDecodeError):
            return False

    def _install_dependencies(self, source_dir: str) -> None:
        """Install the checked-out server's own declared dependencies
        before profiling or serving it - unconfined on this host, same
        tradeoff cmd/warden-launch's sandbox/fetch package documents and
        warns about for exactly this reason (the install itself runs with
        this host's full privileges; only the detected server process is
        ever sandboxed). Without this, the overwhelming majority of real
        npm- or pip-based MCP servers on GitHub can never even start:
        nothing else in this pipeline runs `npm install`/`pip install`, so
        a plain `node index.js` immediately fails on a missing
        node_modules. Best-effort in scope: only the two common,
        unambiguous cases are handled here (a package.json or a
        requirements.txt at the repo root); anything else needs its
        dependencies vendored into the repo or a launch_executable that
        resolves them itself (a real ELF interpreter such as `node` or
        `python3` with the source file as an argument - NOT a wrapper
        script like `npx`/`npm exec`, which gVisor's confinement layer
        cannot introspect the same way it does a real binary, and which
        needs live network access to a package registry that a confined,
        default-deny network policy will not grant anyway).
        """
        install_timeout = int(os.environ.get("WARDEN_INSTALL_TIMEOUT", "300"))
        if os.path.exists(os.path.join(source_dir, "package.json")):
            print(
                "installing npm dependencies (UNCONFINED on this host - "
                "see sandbox/fetch's package doc for the tradeoff)",
                flush=True,
            )
            cmd = (
                ["npm", "ci"]
                if os.path.exists(os.path.join(source_dir, "package-lock.json"))
                else ["npm", "install"]
            )
            _run(cmd, cwd=source_dir, timeout=install_timeout)
            if self._has_npm_script(source_dir, "build"):
                print("running npm run build (most TypeScript MCP servers need this)", flush=True)
                _run(["npm", "run", "build"], cwd=source_dir, timeout=install_timeout)
        if os.path.exists(os.path.join(source_dir, "requirements.txt")):
            print(
                "installing pip dependencies (UNCONFINED on this host - "
                "see sandbox/fetch's package doc for the tradeoff)",
                flush=True,
            )
            # --user/--break-system-packages target a bare system Python's
            # externally-managed site-packages. Inside an active virtualenv
            # (which is how this runner itself is commonly launched) pip
            # refuses --user outright ("User site-packages are not visible
            # in this virtualenv"), so detect that case and fall back to a
            # plain install into the venv's own site-packages instead.
            in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
            pip_cmd = ["python3", "-m", "pip", "install"]
            if not in_venv:
                pip_cmd += ["--user", "--break-system-packages"]
            pip_cmd += ["-r", "requirements.txt"]
            _run(pip_cmd, cwd=source_dir, timeout=install_timeout)

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
        ]
        request_timeout = os.environ.get("WARDEN_REQUEST_TIMEOUT")
        if request_timeout:
            command += ["-request-timeout", request_timeout]
        for key, value in request.env.items():
            command += ["-env", f"{key}={value}"]
        command += ["--", request.executable, *request.args]
        # WARDEN_SERVER_SOURCE/WARDEN_SERVER_ID are read by warden-serve's own
        # HOST-side process (cmd/warden-serve/main.go, before any confinement
        # happens) to resolve telemetry identity - they must be real process
        # environment variables, not -env (which only injects into the
        # CONFINED GUEST's environment and is invisible to warden-serve
        # itself). Passing WARDEN_SERVER_ID is what makes the trust/telemetry
        # platform's server_id match the one this API uses everywhere else
        # (registration, manifest, dashboard queries) instead of a UUID
        # derived from the source string alone.
        serve_env = os.environ.copy()
        serve_env["WARDEN_SERVER_SOURCE"] = request.repo_url
        serve_env["WARDEN_SERVER_ID"] = request.server_id
        return subprocess.Popen(command, cwd=source_dir, env=serve_env)

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
    """Resolve a stored ``owner/repo`` (or full URL) to something git can clone.

    WARDEN_GIT_BASE_URL redirects the ``owner/repo`` form at a different
    host, which is what GitHub Enterprise, an internal mirror, or a local
    test fixture all need. Full URLs are already unambiguous and pass
    through untouched.
    """
    value = repo_url.strip()
    if value.startswith("http://") or value.startswith("https://"):
        return value.removesuffix(".git")
    if value.startswith("git@github.com:"):
        value = value.split(":", 1)[1]
    path = value.removesuffix(".git")
    return f"{_git_base_for(path)}/{path}"


def _git_base_for(path: str) -> str:
    """Which host an ``owner/repo`` is cloned from.

    WARDEN_GIT_BASE_OWNERS scopes the override to particular owners, which
    is what makes a local fixture usable without also cutting the deployment
    off from real GitHub: an unscoped override silently redirects every
    repository, so genuine servers fail to clone for a reason that looks
    like a network fault. Leave it unset for GitHub Enterprise or a full
    mirror, where redirecting everything is the point.
    """
    base_url = os.environ.get("WARDEN_GIT_BASE_URL", "").rstrip("/")
    if not base_url:
        return "https://github.com"
    owners = [o.strip().lower() for o in os.environ.get("WARDEN_GIT_BASE_OWNERS", "").split(",") if o.strip()]
    if owners and path.split("/", 1)[0].lower() not in owners:
        return "https://github.com"
    return base_url


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


class ScanRequest(BaseModel):
    repo_url: str = Field(min_length=1)
    commit_sha: str = Field(default="", max_length=64)
    git_token: SecretStr | None = Field(default=None, min_length=1)


@app.post("/scan")
def scan_source_endpoint(
    request: ScanRequest,
    authorization: str | None = Header(default=None),
) -> dict:
    """Fetch a source and scan it, without starting a session.

    This lives on the runner because the runner is what already knows how
    to materialise a source - a git checkout at a commit, or an npm package
    at a version - and duplicating that in the API would be a second place
    for the two to disagree about what was scanned.
    """
    expected = os.environ.get("WARDEN_RUNNER_TOKEN")
    if expected and authorization != "Bearer " + expected:
        raise HTTPException(status_code=401, detail="invalid runner credentials")
    source_dir = None
    try:
        if request.repo_url.strip().lower().startswith("npm:"):
            source_dir = Runner._install_npm_package(request.repo_url)
            # npm installs into node_modules, which the scanner skips as
            # third-party code. For an npm source the package *is* the thing
            # being scanned, so point at it directly - otherwise the scan
            # sees only the lockfile and reports nothing about the server.
            scan_root = Runner._npm_package_dir(source_dir, request.repo_url) or source_dir
            findings = scan_source(scan_root)
            return {
                "findings": findings,
                "tool_declarations": extract_tools(scan_root),
                "verdict": verdict_for(findings),
                "package": scan_package_metadata(scan_root),
            }
        else:
            if not _SHA.fullmatch(request.commit_sha):
                raise ValueError("commit_sha must be a hexadecimal git commit")
            source_dir = runner._checkout(
                request.repo_url,
                request.commit_sha,
                request.git_token.get_secret_value() if request.git_token else None,
            )
        findings = scan_source(source_dir)
        return {
            "findings": findings,
            "tool_declarations": extract_tools(source_dir),
            "verdict": verdict_for(findings),
            "package": scan_package_metadata(source_dir),
        }
    except (RuntimeError, OSError, ValueError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    finally:
        if source_dir:
            shutil.rmtree(source_dir, ignore_errors=True)


@app.get("/sessions/{server_id}", response_model=SessionResponse)
def get_session(
    server_id: str,
    authorization: str | None = Header(default=None),
) -> SessionResponse:
    expected = os.environ.get("WARDEN_RUNNER_TOKEN")
    if expected and authorization != "Bearer " + expected:
        raise HTTPException(status_code=401, detail="invalid runner credentials")
    session = runner.lookup(server_id)
    if session is None:
        raise HTTPException(status_code=404, detail="no live session for this server")
    return session


@app.delete("/sessions/{server_id}", status_code=204)
def stop_session(server_id: str, authorization: str | None = Header(default=None)) -> None:
    expected = os.environ.get("WARDEN_RUNNER_TOKEN")
    if expected and authorization != "Bearer " + expected:
        raise HTTPException(status_code=401, detail="invalid runner credentials")
    runner.stop(server_id)
