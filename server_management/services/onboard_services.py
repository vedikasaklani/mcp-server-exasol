import re

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


def normalize_repo_url(repo_url: str) -> str:
    """Extract 'owner/repo' from any GitHub URL format the user might type."""
    match = re.search(r"github\.com[:/]([^/]+/[^/]+?)(\.git)?/?$", repo_url.strip())
    if not match:
        raise ValueError(f"Could not parse GitHub repo URL: {repo_url}")
    return match.group(1).lower()

def register_server(session: Session, repo_url: str, installation_id: int,
                     allowed_destinations: list[str]) -> Server:
    server = Server(repo_url=normalize_repo_url(repo_url), installation_id=installation_id)
    session.add(server)
    session.flush() 

    session.add(ServerManifest(
        server_id=server.server_id,
        allowed_destinations=allowed_destinations,
        tool_declarations=None,   #unknown until first static analysis pass extracts it
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
                     change_reason: str) -> ServerManifest:
    manifest = session.get(ServerManifest, server_id)
    if manifest is None:
        raise ValueError(f"no manifest for server_id={server_id}")

    if allowed_destinations is not None:
        manifest.allowed_destinations = allowed_destinations
    if tool_declarations is not None:
        manifest.tool_declarations = tool_declarations
    manifest.version += 1

    session.add(ManifestHistory(
        server_id=server_id, version=manifest.version,
        allowed_destinations=manifest.allowed_destinations,
        tool_declarations=manifest.tool_declarations,
        change_reason=change_reason,
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