import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy import func
from sqlalchemy.orm import Session

from server_management.database.db_models import (
    LlmAnalysisResult,
    LlmVerdict,
    ManifestHistory,
    RuleAnalysisResult,
    RuleFinding,
    RuleVerdict,
    ScanRun,
    ScanStatus,
    Server,
    ServerManifest,
    ToolBehavioralFinding,
    ToolDeclaration,
)

_TERMINAL_SCAN_STATUSES = {
    ScanStatus.REJECTED,
    ScanStatus.COMPLETE,
    ScanStatus.FAILED,
}
_ACTIVE_SCAN_STATUSES = {
    ScanStatus.PULLING_CODE,
    ScanStatus.RULE_ANALYSIS_RUNNING,
    ScanStatus.LLM_ANALYSIS_RUNNING,
}


def mark_interrupted_scans_failed(session: Session) -> int:
    """Close scans orphaned when the process stopped during a scan."""
    updated = (
        session.query(ScanRun)
        .filter(ScanRun.status.in_(_ACTIVE_SCAN_STATUSES))
        .update(
            {
                ScanRun.status: ScanStatus.FAILED,
                ScanRun.finished_at: func.now(),
            },
            synchronize_session=False,
        )
    )
    session.commit()
    return updated


def normalize_repo_url(repo_url: str) -> str:
    """Return a canonical lowercase ``owner/repo`` for GitHub URL variants."""
    value = repo_url.strip()
    if value.startswith("git@github.com:"):
        path = value.removeprefix("git@github.com:")
    else:
        parsed = urlparse(value if "://" in value else f"https://{value}")
        if parsed.hostname != "github.com":
            raise ValueError(f"Could not parse GitHub repo URL: {repo_url}")
        path = parsed.path
    path = path.strip().strip("/")
    if path.lower().endswith(".git"):
        path = path[:-4]
    parts = [part for part in path.split("/") if part]
    if len(parts) != 2 or any(not re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts):
        raise ValueError(f"Could not parse GitHub repo URL: {repo_url}")
    return "/".join(part.lower() for part in parts)

def register_server(session: Session, repo_url: str, installation_id: int,
                     allowed_destinations: list[str],
                     launch_executable: str = "",
                     launch_args: list[str] | None = None) -> Server:
    server = Server(repo_url=normalize_repo_url(repo_url), installation_id=installation_id)
    session.add(server)
    session.flush() 

    session.add(ServerManifest(
        server_id=server.server_id,
        allowed_destinations=allowed_destinations,
        tool_declarations=None,   #unknown until first static analysis pass extracts it
        launch_executable=launch_executable.strip() or None,
        launch_args=launch_args or [],
        version=1,
    ))
    session.add(ManifestHistory(
        server_id=server.server_id, version=1,
        allowed_destinations=allowed_destinations, tool_declarations=None,
        change_reason="registration",
    ))
    session.commit()
    return server


def get_manifest(session: Session, server_id: str) -> ServerManifest | None:
    return session.get(ServerManifest, server_id)


def _iso(value) -> str | None:
    return value.isoformat() if value is not None else None


def _scan_verdict(run: ScanRun) -> str | None:
    if run.llm_result is not None:
        return run.llm_result.verdict.value
    if run.rule_result is not None:
        return run.rule_result.verdict.value
    return None


def _score_placeholder() -> dict:
    # Trust scores are currently calculated in Exasol, not exposed through the
    # operational PostgreSQL API yet.
    return {
        "overall_score": None,
        "security_score": None,
        "operational_score": None,
        "computed_at": None,
    }


def _tools_for_scan(run: ScanRun) -> list[dict]:
    if run.rule_result is None:
        return []
    return [
        {
            "name": tool.name,
            "description": tool.description,
            "parameter_schema": tool.parameter_schema or {},
        }
        for tool in run.rule_result.tool_declarations
    ]


def _tools_from_manifest(manifest: ServerManifest | None) -> list[dict]:
    if manifest is None or not manifest.tool_declarations:
        return []
    return [
        {
            "name": tool["name"],
            "description": tool.get("description"),
            "parameter_schema": tool.get("parameter_schema", {}),
        }
        for tool in manifest.tool_declarations
    ]


def _findings_for_scan(run: ScanRun) -> list[dict]:
    findings = []
    if run.rule_result is not None:
        findings.extend(
            {
                "id": finding.id,
                "phase": "rule",
                "tool_name": None,
                "analyzer": finding.analyzer,
                "severity": finding.severity,
                "message": finding.message,
                "details": finding.details,
                "file": finding.file,
                "line": finding.line,
            }
            for finding in run.rule_result.rule_findings
        )
    if run.llm_result is not None:
        findings.extend(
            {
                "id": finding.id,
                "phase": "llm",
                "tool_name": finding.tool_name,
                "analyzer": finding.analyzer,
                "severity": finding.severity,
                "message": finding.threat_summary,
                "details": {
                    "threat_names": finding.threat_names or [],
                    "mcp_taxonomies": finding.mcp_taxonomies or [],
                    "total_findings": finding.total_findings,
                    "target": finding.target,
                },
                "file": None,
                "line": None,
            }
            for finding in run.llm_result.tool_findings
        )
    return findings


def _scan_summary(run: ScanRun) -> dict:
    return {
        "scan_run_id": run.scan_run_id,
        "commit_sha": run.commit_sha,
        "status": run.status,
        "started_at": _iso(run.started_at),
        "finished_at": _iso(run.finished_at),
        "verdict": _scan_verdict(run),
        "score": _score_placeholder(),
    }


def get_server_dashboard(session: Session, server_id: str) -> dict | None:
    server = session.get(Server, server_id)
    if server is None:
        return None

    latest_scan = (
        session.query(ScanRun)
        .filter(ScanRun.server_id == server_id)
        .order_by(ScanRun.started_at.desc())
        .first()
    )
    manifest = server.manifest
    return {
        "server_id": server.server_id,
        "repo_url": server.repo_url,
        "registered_at": _iso(server.created_at),
        "allowed_destinations": (manifest.allowed_destinations if manifest else []),
        "current_verdict": _scan_verdict(latest_scan) if latest_scan else None,
        "scan_in_progress": bool(
            latest_scan and latest_scan.status not in _TERMINAL_SCAN_STATUSES
        ),
        "latest_scan_id": latest_scan.scan_run_id if latest_scan else None,
        "latest_scan_date": _iso(latest_scan.started_at) if latest_scan else None,
        "commit_sha": latest_scan.commit_sha if latest_scan else None,
        "score": _score_placeholder(),
        "tools": _tools_from_manifest(manifest),
        "findings": _findings_for_scan(latest_scan) if latest_scan else [],
        "warden_profile": {
            "approved_by": manifest.warden_approved_by if manifest else None,
            "approved_at": _iso(manifest.warden_approved_at) if manifest else None,
            "approved_commit": manifest.warden_approved_commit if manifest else None,
        },
    }


def get_server_scan_history(
    session: Session, server_id: str
) -> list[dict] | None:
    if session.get(Server, server_id) is None:
        return None
    runs = (
        session.query(ScanRun)
        .filter(ScanRun.server_id == server_id)
        .order_by(ScanRun.started_at.desc())
        .all()
    )
    return [_scan_summary(run) for run in runs]


def get_server_scan_detail(
    session: Session, server_id: str, scan_id: str
) -> dict | None:
    run = (
        session.query(ScanRun)
        .filter(ScanRun.server_id == server_id, ScanRun.scan_run_id == scan_id)
        .first()
    )
    if run is None:
        return None
    return {
        "scan_id": scan_id,
        "server_id": server_id,
        "repo_url": run.server.repo_url,
        "registered_at": _iso(run.server.created_at),
        "allowed_destinations": (
            run.server.manifest.allowed_destinations
            if run.server.manifest
            else []
        ),
        "current_verdict": _scan_verdict(run),
        "scan_in_progress": run.status not in _TERMINAL_SCAN_STATUSES,
        "latest_scan_id": run.scan_run_id,
        "latest_scan_date": _iso(run.started_at),
        "commit_sha": run.commit_sha,
        "score": _score_placeholder(),
        "tools": _tools_for_scan(run),
        "findings": _findings_for_scan(run),
    }


def get_server_by_repo_and_installation(session:Session, repo_url:str, installation_id:int):
    server = (
        session.query(Server)
        .filter(
            Server.repo_url == normalize_repo_url(repo_url),
            Server.installation_id == installation_id
        )
        .first()
    )
    return server

def update_manifest(session: Session, server_id: str, *,
                     allowed_destinations: list[str] | None = None,
                     tool_declarations: list[dict] | None = None,
                     launch_executable: str | None = None,
                     launch_args: list[str] | None = None,
                     change_reason: str) -> ServerManifest:
    manifest = session.get(ServerManifest, server_id)
    if manifest is None:
        raise ValueError(f"no manifest for server_id={server_id}")

    if allowed_destinations is not None:
        manifest.allowed_destinations = allowed_destinations
    if tool_declarations is not None:
        manifest.tool_declarations = tool_declarations
    if launch_executable is not None:
        manifest.launch_executable = launch_executable.strip() or None
    if launch_args is not None:
        manifest.launch_args = launch_args
    if launch_executable is not None or launch_args is not None:
        manifest.warden_profile_path = None
        manifest.warden_approved_by = None
        manifest.warden_approved_at = None
        manifest.warden_approved_commit = None
    manifest.version += 1

    session.add(ManifestHistory(
        server_id=server_id, version=manifest.version,
        allowed_destinations=manifest.allowed_destinations,
        tool_declarations=manifest.tool_declarations,
        change_reason=change_reason,
    ))
    session.commit()
    return manifest


def approve_warden_profile(
    session: Session,
    server_id: str,
    *,
    profile_path: str,
    approved_by: str,
    commit_sha: str,
) -> ServerManifest:
    manifest = session.get(ServerManifest, server_id)
    if manifest is None:
        raise ValueError(f"no manifest for server_id={server_id}")
    if not approved_by.strip() or not commit_sha.strip():
        raise ValueError("approved_by and commit_sha are required")
    path = Path(profile_path).expanduser()
    if not path.is_file():
        raise ValueError(f"Warden profile does not exist: {path}")
    manifest.warden_profile_path = str(path.resolve())
    manifest.warden_approved_by = approved_by.strip()
    manifest.warden_approved_at = datetime.now(timezone.utc).replace(tzinfo=None)
    manifest.warden_approved_commit = commit_sha.strip()
    manifest.version += 1
    session.add(ManifestHistory(
        server_id=server_id, version=manifest.version,
        allowed_destinations=manifest.allowed_destinations,
        tool_declarations=manifest.tool_declarations,
        change_reason="warden_profile_approved",
    ))
    session.commit()
    return manifest


def create_scan_run(session: Session, server_id: str, commit_sha: str) -> ScanRun:
    run = ScanRun(server_id=server_id, commit_sha=commit_sha, status=ScanStatus.QUEUED)
    session.add(run)
    session.commit()
    return run


# Keys already given a real column on RuleFinding - anything else on the
# finding dict is analyzer-specific and gets kept in `details` rather than
# dropped. "message" and "threat_summary" are coalesced into one column,
# so both are excluded here even though only one of them becomes a column.
_RULE_FINDING_CORE_KEYS = {"rule_id", "file", "line", "message", "threat_summary", "severity", "analyzer", "tool_name"}


def _rule_finding_kwargs(finding: dict) -> dict:
    """Maps a Phase 1 finding dict onto RuleFinding's columns. Handles both
    shapes that land in rule_findings: semgrep's file+line shape, and
    Cisco's threat-based shape (from vulnerable-package, via the same
    envelope Phase 2 uses)."""
    details = {k: v for k, v in finding.items() if k not in _RULE_FINDING_CORE_KEYS}
    return {
        "analyzer": finding.get("analyzer", "unknown"),
        "severity": finding.get("severity", "LOW"),
        "rule_id": finding.get("rule_id"),
        "file": finding.get("file"),
        "line": finding.get("line"),
        "message": finding.get("message") or finding.get("threat_summary"),
        "details": details or None,
    }


def record_rule_analysis_result(
    session: Session, scan_run_id: str, *,
    verdict: RuleVerdict,
    rule_findings: list[dict],
    tool_declarations: list[dict],
) -> ScanRun:
    """
    Phase 1. Commits BEFORE the LLM phase is ever invoked by the caller -
    tool_declarations lands in the live manifest here, so it's durable and
    readable (by this process, a retry, or a completely different worker)
    before record_llm_analysis_result is ever called. This is the fix for
    the earlier bug: the LLM phase no longer depends on an in-memory value
    that hadn't been persisted yet.

    verdict=FAIL short-circuits straight to REJECTED - the LLM phase is
    never run at all, matching 'what if static analysis only fails'.
    """
    session.add(RuleAnalysisResult(
        scan_run_id=scan_run_id, verdict=verdict,
    ))

    run = session.get(ScanRun, scan_run_id)
    if run is None:
        raise ValueError(f"no scan run for scan_run_id={scan_run_id}")

    for finding in rule_findings:
        session.add(RuleFinding(
            scan_run_id=scan_run_id,
            server_id=run.server_id,
            **_rule_finding_kwargs(finding),
        ))

    for declaration in tool_declarations:
        session.add(ToolDeclaration(
            scan_run_id=scan_run_id,
            server_id=run.server_id,
            name=declaration["name"],
            description=declaration.get("description"),
            parameter_schema=declaration.get("parameter_schema", {}),
        ))
    if verdict == RuleVerdict.FAIL:
        run.status = ScanStatus.REJECTED
        run.finished_at = func.now()
    else:
        run.status = ScanStatus.RULE_ANALYSIS_PASSED
        # persisted here, not deferred - this is the line that fixes the bug
        update_manifest(session, run.server_id,
                         tool_declarations=tool_declarations,
                         change_reason="static_analysis_update")

    session.commit()
    return run


def get_tool_declarations_for_llm_phase(session: Session, server_id: str) -> list[dict]:
    """LLM phase reads as input is written by record_rule_analysis_result"""
    manifest = session.get(ServerManifest, server_id)
    if manifest is None or not manifest.tool_declarations:
        raise ValueError(
            f"no tool_declarations available for server_id={server_id} - "
            "rule phase must complete and persist before the LLM phase runs"
        )
    return manifest.tool_declarations


def record_llm_analysis_result(
    session: Session, scan_run_id: str, *,
    verdict: LlmVerdict,
    llm_findings: list[dict],
) -> ScanRun:
    """
    Phase 2. Only valid to call once a RuleAnalysisResult with verdict != FAIL
    already exists for this scan_run"""
    run = session.get(ScanRun, scan_run_id)
    if run is None:
        raise ValueError(f"no scan run for scan_run_id={scan_run_id}")
    

    session.add(LlmAnalysisResult(
        scan_run_id=scan_run_id, verdict=verdict,
    ))
    for finding in llm_findings:
        session.add(ToolBehavioralFinding(
            scan_run_id=scan_run_id,
            tool_name=finding.get("tool_name") or finding.get("tool") or finding.get("target", "unknown"),
            analyzer=finding.get("analyzer", "behavioral_analyzer"),
            severity=finding.get("severity", "LOW"),
            threat_summary=finding.get("threat_summary"),
            threat_names=finding.get("threat_names", []),
            mcp_taxonomies=finding.get("mcp_taxonomies", []),
            total_findings=finding.get("total_findings", 0),
            target=finding.get("target"),
        ))

    if verdict == LlmVerdict.FAIL:
        run.status = ScanStatus.REJECTED
        run.finished_at = func.now()
    else:
        run.status = ScanStatus.STATIC_ANALYSIS_PASSED

    session.commit()
    return run