'''Pipeline for scanning: clone -> Phase 1 (rule-based, deterministic) ->
Phase 2 (Cisco behavioral LLM analysis), unless Phase 1 already FAILed.'''
'''Do not remove print lines, they are important for logging'''

import asyncio
import subprocess
import tempfile
import shutil
import json
import re

from sqlalchemy import func
from server_management.database.db_config import session as SessionLocal
from server_management.database.db_models import Server, ScanRun, ScanStatus, RuleVerdict, LlmVerdict
from server_management.api.github_auth import get_installation_token
from server_management.services.onboard_services import record_rule_analysis_result, record_llm_analysis_result
from server_management.services.static_analysis import extract_tool_declarations, run_semgrep_scan

FAIL_SEVERITIES = {"CRITICAL", "HIGH"}

# Matches the token embedded in the clone URL's userinfo; used to mask it out
_TOKEN_IN_URL = re.compile(r"x-access-token:[^@\s]*@")


def _sanitize(text: str) -> str:
    """Mask embedded credentials (the x-access-token URL userinfo)."""
    return _TOKEN_IN_URL.sub("x-access-token:***@", text)


def _set_status(scan_run_id: str, status: ScanStatus) -> None:
    db = SessionLocal()
    try:
        run = db.get(ScanRun, scan_run_id)
        if run is not None:
            run.status = status
            db.commit()
    finally:
        db.close()


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
    result = subprocess.run(
        ["mcp-scanner", command, repo_path, "--format", "raw"],
        capture_output=True, text=True, timeout=timeout,
    )
    if result.returncode not in (0, 1):  # 1 = "findings present", not a crash
        raise RuntimeError(f"mcp-scanner {command} failed: {result.stderr}")
    return json.loads(result.stdout)


def run_vulnerable_package_scan(repo_path: str) -> dict:
    """Phase 1: deterministic dependency CVE scan (pip-audit). No API key."""
    return _run_cli("vulnerable-package", repo_path, timeout=120)


def run_behavioral_scan(repo_path: str) -> dict:
    """Phase 2: Cisco's LLM-powered behavioral analyzer"""
    return _run_cli("behavioral", repo_path, timeout=300)


def _extract_findings(raw_result) -> list[dict]:
    """to be verified against real mcp-scanner --format raw output - if the
    actual shape differs from this assumption, findings silently come back
    empty and every scan passes, so pin this with a fixture test."""
    if raw_result is None:
        return []
    items = raw_result if isinstance(raw_result, list) else raw_result.get("results", [raw_result])
    findings = []
    for item in items:
        if isinstance(item, dict):
            findings.extend(item.get("findings", []))
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
        db = SessionLocal()
        run = db.get(ScanRun, scan_run_id)
        server = db.get(Server, run.server_id) if run else None
        db.close()

        if run is None or server is None:
            await scan_fail(scan_run_id, reason="scan run or server not found")
            return

        try:
            access_token = await get_installation_token(server.installation_id)
        except Exception as e:
            await scan_fail(scan_run_id, reason=f"token exchange failed: {e}")
            return

        _set_status(scan_run_id, ScanStatus.PULLING_CODE)
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
            tool_declarations = await asyncio.to_thread(extract_tool_declarations, repo_path)
        except Exception as e:
            await scan_fail(scan_run_id, reason=f"phase 1 scan failed: {e}")
            return

        rule_verdict = _verdict_from_findings(
            rule_findings, RuleVerdict.FAIL, RuleVerdict.PASS_WITH_FINDINGS, RuleVerdict.PASS
        )

        # The manifest + manifest-history commit happens inside
        # record_rule_analysis_result
        db = SessionLocal()
        try:
            record_rule_analysis_result(
                db, scan_run_id, verdict=rule_verdict,
                rule_findings=rule_findings, tool_declarations=tool_declarations,
            )
        except Exception as e:
            db.rollback()
            db.close()
            await scan_fail(scan_run_id, reason=f"phase 1 recording failed: {e}")
            return
        db.close()
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
        db = SessionLocal()
        try:
            record_llm_analysis_result(db, scan_run_id, verdict=llm_verdict, llm_findings=llm_findings)
        except ValueError as e:
            db.rollback()
            db.close()
            await scan_fail(scan_run_id, reason=f"phase 2 recording rejected: {e}")
            return
        except Exception as e:
            db.rollback()
            db.close()
            await scan_fail(scan_run_id, reason=f"phase 2 recording failed: {e}")
            return
        db.close()
        await scan_pass(scan_run_id, phase="llm", verdict=llm_verdict)

    finally:
        if repo_path:
            shutil.rmtree(repo_path, ignore_errors=True)


async def scan_pass(scan_run_id: str, phase: str, verdict) -> None:
    print(f"scan has passed... [{phase}] {scan_run_id}: verdict={verdict}")


async def scan_fail(scan_run_id: str, reason: str) -> None:
    print(f"scan has failed... {scan_run_id}: {reason}")
    terminal = {ScanStatus.REJECTED, ScanStatus.STATIC_ANALYSIS_PASSED, ScanStatus.FAILED}
    db = SessionLocal()
    try:
        run = db.get(ScanRun, scan_run_id)
        if run is not None and run.status not in terminal:
            run.status = ScanStatus.FAILED
            run.finished_at = func.now()
            db.commit()
    finally:
        db.close()
