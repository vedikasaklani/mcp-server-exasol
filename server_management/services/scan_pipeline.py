"""Pipeline for scanning: clone -> Phase 1 (rule-based, deterministic) ->
Phase 2 (Cisco behavioral LLM analysis), unless Phase 1 already FAILed.

Do not remove print lines, they are important for logging.
"""

import asyncio
import json
import os
import re
import shutil
import subprocess
import tempfile

from sqlalchemy import func

from server_management.api.github_auth import get_installation_token
from server_management.database.db_config import session_scope
from server_management.database.db_models import (
    LlmVerdict,
    RuleVerdict,
    ScanRun,
    ScanStatus,
    Server,
)
from server_management.services.onboard_services import (
    record_llm_analysis_result,
    record_rule_analysis_result,
)
from server_management.services.static_analysis import (
    extract_tool_declarations,
    run_semgrep_scan,
    run_semgrep_supply_chain_scan,
)
from server_management.services.sync import (
    sync_latest_manifest_history,
    sync_llm_phase_findings,
    sync_rule_phase_findings,
    sync_scan_run,
)
from server_management.services.warden_session_manager import warden_sessions

FAIL_SEVERITIES = {"CRITICAL", "HIGH"}

# Matches the token embedded in the clone URL's userinfo; used to mask it out
_TOKEN_IN_URL = re.compile(r"x-access-token:[^@\s]*@")


def _sanitize(text: str) -> str:
    """Mask embedded credentials (the x-access-token URL userinfo)."""
    return _TOKEN_IN_URL.sub("x-access-token:***@", text)


def _set_status(scan_run_id: str, status: ScanStatus) -> None:
    with session_scope() as db:
        run = db.get(ScanRun, scan_run_id)
        if run is not None:
            run.status = status
            db.commit()


def clone_repo(owner_repo: str, commit_sha: str, access_token: str) -> str:
    """Clones owner/repo at commit_sha into a fresh temp dir. Caller must
    shutil.rmtree the returned path when done."""
    clone_url = f"https://x-access-token:{access_token}@github.com/{owner_repo}.git"
    workdir = tempfile.mkdtemp(prefix="scan_")
    try:
        subprocess.run(["git", "clone", "--quiet", clone_url, workdir],
                        check=True, capture_output=True, text=True, timeout=120)
        subprocess.run(["git", "-C", workdir, "checkout", "--quiet", commit_sha],
                        check=True, capture_output=True, text=True, timeout=30)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        shutil.rmtree(workdir, ignore_errors=True)
        detail = e.stderr if isinstance(e, subprocess.CalledProcessError) else str(e)
        raise RuntimeError(f"git clone/checkout failed: {_sanitize(detail)}") from e
    return workdir


def _run_cli(command: str, repo_path: str, timeout: int) -> dict:
    mcp_scanner_bin = os.environ.get("MCP_SCANNER_BIN", "mcp-scanner")
    result = subprocess.run(
        [mcp_scanner_bin, command, repo_path, "--format", "raw"],
        capture_output=True, text=True, timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(f"mcp-scanner {command} failed (exit {result.returncode}): {result.stderr.strip()}")
    if "alignment check failed" in result.stderr or "APIError" in result.stderr:
        raise RuntimeError(
            f"mcp-scanner {command} exited 0 but LLM calls failed (check MCP_SCANNER_LLM_API_KEY / "
            f"MCP_SCANNER_LLM_MODEL): {result.stderr[-1500:]}"
        )
    return json.loads(result.stdout)


def run_vulnerable_package_scan(repo_path: str) -> dict:
    """Phase 1: deterministic dependency CVE scan (pip-audit). No API key."""
    return _run_cli("vulnerable-package", repo_path, timeout=120)


def run_behavioral_scan(repo_path: str) -> dict:
    """Phase 2: Cisco's LLM-powered behavioral analyzer"""
    return _run_cli("behavioral", repo_path, timeout=300)


def _extract_findings(raw_result) -> list[dict]:
    if not raw_result:
        return []
    entries = raw_result.get("scan_results", []) if isinstance(raw_result, dict) else raw_result
    findings = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        analyzers = entry.get("findings", {})
        for analyzer_name, f in analyzers.items():
            if isinstance(f, dict) and f.get("total_findings", 0) > 0:
                findings.append({
                    **f,
                    "analyzer": analyzer_name,
                    "tool_name": entry.get("tool_name"),
                })
    return findings


def _verdict_from_findings(findings: list[dict], fail_v, findings_v, pass_v):
    severities = {f.get("severity", "").upper() for f in findings}
    if severities & FAIL_SEVERITIES:
        return fail_v
    return findings_v if findings else pass_v


async def trigger_scan(scan_run_id: str) -> None:
    print(f"scan running... ({scan_run_id})")
    repo_path = None
    try:
        with session_scope() as db:
            run = db.get(ScanRun, scan_run_id)
            server = db.get(Server, run.server_id) if run else None

        if run is None or server is None:
            await scan_fail(scan_run_id, reason="scan run or server not found")
            return

        try:
            access_token = await get_installation_token(server.installation_id)
        except Exception as e:
            await scan_fail(scan_run_id, reason=f"token exchange failed: {e}")
            return

        _set_status(scan_run_id, ScanStatus.PULLING_CODE)
        print("token exchange passed, pulling code now!")
        try:
            repo_path = await asyncio.to_thread(
                clone_repo, server.repo_url, run.commit_sha, access_token)
        except Exception as e:
            await scan_fail(scan_run_id, reason=str(e))
            return

        # Phase 1: rule-based
        _set_status(scan_run_id, ScanStatus.RULE_ANALYSIS_RUNNING)
        try:
            rule_findings = _extract_findings(
                await asyncio.to_thread(run_vulnerable_package_scan, repo_path))
            rule_findings += await asyncio.to_thread(run_semgrep_scan, repo_path)
            try:
                rule_findings += await asyncio.to_thread(
                    run_semgrep_supply_chain_scan, repo_path
                )
            except RuntimeError as e:
                if os.environ.get("SEMGREP_SCA_REQUIRED", "").lower() == "true":
                    raise
                print(f"semgrep-sca unavailable; continuing without it: {e}")
            tool_declarations = await asyncio.to_thread(extract_tool_declarations, repo_path)
        except Exception as e:
            await scan_fail(scan_run_id, reason=f"phase 1 scan failed: {e}")
            return

        rule_verdict = _verdict_from_findings(
            rule_findings, RuleVerdict.FAIL, RuleVerdict.PASS_WITH_FINDINGS, RuleVerdict.PASS
        )

        # The manifest + manifest-history commit happens inside
        # record_rule_analysis_result
        with session_scope() as db:
            try:
                record_rule_analysis_result(
                    db, scan_run_id, verdict=rule_verdict,
                    rule_findings=rule_findings, tool_declarations=tool_declarations,
                )
            except Exception as e:
                await scan_fail(scan_run_id, reason=f"phase 1 recording failed: {e}")
                return
        await asyncio.to_thread(_sync_rule_phase, scan_run_id, run.server_id)
        await scan_pass(scan_run_id, phase="rule", verdict=rule_verdict)

        if rule_verdict == RuleVerdict.FAIL:
            print(f"scan {scan_run_id} REJECTED at phase 1 - phase 2 skipped")
            return

        # Phase 2: Cisco behavioral (LLM)
        _set_status(scan_run_id, ScanStatus.LLM_ANALYSIS_RUNNING)
        try:
            llm_findings = _extract_findings(
                await asyncio.to_thread(run_behavioral_scan, repo_path))
        except Exception as e:
            await scan_fail(scan_run_id, reason=f"phase 2 scan failed: {e}")
            return

        llm_verdict = _verdict_from_findings(
            llm_findings, LlmVerdict.FAIL, LlmVerdict.PASS_WITH_FINDINGS, LlmVerdict.PASS
        )
        with session_scope() as db:
            try:
                record_llm_analysis_result(db, scan_run_id, verdict=llm_verdict, llm_findings=llm_findings)
            except ValueError as e:
                await scan_fail(scan_run_id, reason=f"phase 2 recording rejected: {e}")
                return
            except Exception as e:
                await scan_fail(scan_run_id, reason=f"phase 2 recording failed: {e}")
                return
        await asyncio.to_thread(_sync_llm_phase, scan_run_id)
        await scan_pass(
            scan_run_id, phase="llm", verdict=llm_verdict, git_token=access_token
        )
    except Exception as e:
        # Keep unexpected orchestration or database errors from leaving the
        # persisted scan in a non-terminal running state.
        await scan_fail(scan_run_id, reason=f"unexpected scan error: {e}")

    finally:
        if repo_path:
            shutil.rmtree(repo_path, ignore_errors=True)


def _sync_scan_lifecycle(scan_run_id: str) -> None:
    """Best-effort sync to Exasol's FACT_SCAN_RUN. This
    runs outside the FastAPI layer, and
    it's the only place FAILED status ever gets recorded - without this
    hook, infra-level failures (clone failed, token exchange failed, a
    phase throwing before it ever reaches record_*_analysis_result) were
    invisible in Exasol even though api.py's endpoints cover REJECTED and
    the PASSED transitions. Swallow errors: a down Exasol should never take
    the scan pipeline down with it."""
    with session_scope() as db:
        try:
            sync_scan_run(db, scan_run_id)
        except Exception as e:
            print(f"exasol scan-lifecycle sync failed for {scan_run_id}: {e}")


def _sync_rule_phase(scan_run_id: str, server_id: str) -> None:
    """Best-effort sync for rule findings and the manifest after a commit.
    FACT_SCAN_RUN is left to the scan_pass/scan_fail lifecycle sync."""
    with session_scope() as db:
        try:
            sync_rule_phase_findings(db, scan_run_id)
            sync_latest_manifest_history(db, server_id)
        except Exception as e:
            print(f"exasol rule-phase sync failed for {scan_run_id}: {e}")


def _sync_llm_phase(scan_run_id: str) -> None:
    """Best-effort sync for LLM findings after a commit.
    FACT_SCAN_RUN is left to the scan_pass/scan_fail lifecycle sync."""
    with session_scope() as db:
        try:
            sync_llm_phase_findings(db, scan_run_id)
        except Exception as e:
            print(f"exasol llm-phase sync failed for {scan_run_id}: {e}")


async def scan_pass(
    scan_run_id: str, phase: str, verdict, git_token: str | None = None
) -> None:
    print(f"scan has passed... [{phase}] {scan_run_id}: verdict={verdict}")
    await asyncio.to_thread(_sync_scan_lifecycle, scan_run_id)
    if phase == "llm":
        server_id = _server_id_for_scan(scan_run_id)
        try:
            await asyncio.to_thread(
                warden_sessions.reconcile_server, server_id, git_token
            )
        except Exception as exc:
            print(
                f"warden profile/session startup failed for {server_id}: {exc}",
                flush=True,
            )


def _server_id_for_scan(scan_run_id: str) -> str:
    with session_scope() as db:
        run = db.get(ScanRun, scan_run_id)
        if run is None:
            raise RuntimeError(f"scan run not found: {scan_run_id}")
        return run.server_id


async def scan_fail(scan_run_id: str, reason: str) -> None:
    print(f"scan has failed... {scan_run_id}: {reason}")
    terminal = {ScanStatus.REJECTED, ScanStatus.STATIC_ANALYSIS_PASSED, ScanStatus.FAILED}
    with session_scope() as db:
        run = db.get(ScanRun, scan_run_id)
        if run is not None and run.status not in terminal:
            run.status = ScanStatus.FAILED
            run.finished_at = func.now()
            db.commit()
    await asyncio.to_thread(_sync_scan_lifecycle, scan_run_id)