'''Pipeline for scanning: clone -> Phase 1 (rule-based, deterministic) ->
Phase 2 (Cisco behavioral LLM analysis), unless Phase 1 already FAILed.'''
'''Do not remove print lines, they are important for logging'''

import subprocess
import tempfile
import shutil
import json
import re

from server_management.database.db_config import session as SessionLocal
from server_management.database.db_models import Server, ScanRun, ScanStatus, RuleVerdict, LlmVerdict
from server_management.api.github_auth import get_installation_token
from server_management.services.onboard_services import record_rule_analysis_result, record_llm_analysis_result
from server_management.services.static_analysis import extract_tool_declarations, run_semgrep_scan

FAIL_SEVERITIES = {"CRITICAL", "HIGH"}


def normalize_repo(input_str: str) -> str:
    """'owner/repo', a full URL, or a .git URL -> normalized 'owner/repo'."""
    input_str = input_str.strip()
    match = re.search(r"(?:github\.com[:/])?([^/]+)/([^/]+?)(\.git)?/?$", input_str)
    if not match:
        raise ValueError(f"Could not parse repo identifier: {input_str}")
    return f"{match.group(1)}/{match.group(2)}".lower()


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
        raise RuntimeError(f"git clone/checkout failed: {detail}") from e
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
    """to be verified"""
    items = raw_result if isinstance(raw_result, list) else raw_result.get("results", [raw_result])
    findings = []
    for item in items:
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

        try:
            repo_path = clone_repo(server.repo_url, run.commit_sha, access_token)
        except Exception as e:
            await scan_fail(scan_run_id, reason=str(e))
            return

        # Phase 1: rule-based 
        try:
            rule_findings = _extract_findings(run_vulnerable_package_scan(repo_path))
            rule_findings += run_semgrep_scan(repo_path)
            tool_declarations = extract_tool_declarations(repo_path)
        except Exception as e:
            await scan_fail(scan_run_id, reason=f"phase 1 scan failed: {e}")
            return

        rule_verdict = _verdict_from_findings(
            rule_findings, RuleVerdict.FAIL, RuleVerdict.PASS_WITH_FINDINGS, RuleVerdict.PASS
        )

        # Manifest + manifest-history commit happens on every scan,
        db = SessionLocal()
        try:
            record_rule_analysis_result(
                db, scan_run_id, verdict=rule_verdict,
                rule_findings=rule_findings, tool_declarations=tool_declarations,
            )
        finally:
            db.close()
        await scan_pass(scan_run_id, phase="rule", verdict=rule_verdict)

        if rule_verdict == RuleVerdict.FAIL:
            print(f"scan {scan_run_id} REJECTED at phase 1 - phase 2 skipped")
            return

        # Phase 2: Cisco behavioral (LLM) 
        try:
            llm_findings = _extract_findings(run_behavioral_scan(repo_path))
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
            db.close()
            await scan_fail(scan_run_id, reason=f"phase 2 recording rejected: {e}")
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
    db = SessionLocal()
    try:
        run = db.get(ScanRun, scan_run_id)
        if run is not None:
            run.status = ScanStatus.FAILED
            db.commit()
    finally:
        db.close()