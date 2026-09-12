"""
models.py - 
OLTP-shaped: registration data, manifest current-state + versioned history,
scan run lifecycle.
"""

from __future__ import annotations

import enum
import uuid

from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

def gen_id() -> str:
    return str(uuid.uuid4())


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    PULLING_CODE = "pulling_code"
    RULE_ANALYSIS_RUNNING = "rule_analysis_running"       # SAST + tool-declaration extraction
    RULE_ANALYSIS_PASSED = "rule_analysis_passed"         # tool_declarations saved
    LLM_ANALYSIS_RUNNING = "llm_analysis_running"         # LLM reads persisted tool_declarations 
    REJECTED = "rejected"                       # either phase fails, container never built
    STATIC_ANALYSIS_PASSED = "static_analysis_passed"     # both phases done, can build
    BUILDING_CONTAINER = "building_container"
    SANDBOX_RUNNING = "sandbox_running"
    SCORING = "scoring"
    COMPLETE = "complete"
    FAILED = "failed"                           # infra/timeout failure


class RuleVerdict(str, enum.Enum):
    PASS = "pass"
    PASS_WITH_FINDINGS = "pass_with_findings"
    FAIL = "fail"                                


class LlmVerdict(str, enum.Enum):
    PASS = "pass"                               # implementation matches declared intent
    PASS_WITH_FINDINGS = "pass_with_findings"    # minor mismatches, not disqualifying
    FAIL = "fail"                                # high-confidence intent mismatch


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"



class Server(Base):
    """information registered by the user"""
    __tablename__ = "servers"

    server_id = Column(String, primary_key=True, default=gen_id)
    repo_url = Column(String, nullable=False, unique=True)
    installation_id = Column(Integer, nullable=False)     
    created_at = Column(DateTime, server_default=func.now())

    manifest = relationship("ServerManifest", back_populates="server", uselist=False)
    scan_runs = relationship("ScanRun", back_populates="server")


class ServerManifest(Base):
    """Current-state manifest only"""
    __tablename__ = "server_manifests"

    server_id = Column(String, ForeignKey("servers.server_id"), primary_key=True)
    allowed_destinations = Column(JSON, nullable=False, default=list)   # operator-declared at registration
    tool_declarations = Column(JSON, nullable=True)                     # NOT set at registration populated by static analysis 
    launch_executable = Column(String, nullable=True)
    launch_args = Column(JSON, nullable=False, default=list)
    warden_profile_path = Column(String, nullable=True)
    warden_approved_by = Column(String, nullable=True)
    warden_approved_at = Column(DateTime, nullable=True)
    warden_approved_commit = Column(String, nullable=True)
                                                                         
    version = Column(Integer, nullable=False, default=1)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    server = relationship("Server", back_populates="manifest")


class ManifestHistory(Base):
    __tablename__ = "manifest_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    server_id = Column(String, ForeignKey("servers.server_id"), nullable=False)
    version = Column(Integer, nullable=False)
    allowed_destinations = Column(JSON, nullable=False)
    tool_declarations = Column(JSON, nullable=True)
    changed_at = Column(DateTime, server_default=func.now())
    change_reason = Column(String, nullable=True)   # "registration" | "static_analysis_update" | "operator_edit"


class ScanRun(Base):
    """One row per push-triggered scan job."""
    __tablename__ = "scan_runs"

    scan_run_id = Column(String, primary_key=True, default=gen_id)
    server_id = Column(String, ForeignKey("servers.server_id"), nullable=False)
    commit_sha = Column(String, nullable=False)
    status = Column(SAEnum(ScanStatus), nullable=False, default=ScanStatus.QUEUED)
    started_at = Column(DateTime, server_default=func.now())
    finished_at = Column(DateTime, nullable=True)
    
    server = relationship("Server", back_populates="scan_runs")
    rule_result = relationship("RuleAnalysisResult", back_populates="scan_run", uselist=False)
    llm_result = relationship("LlmAnalysisResult", back_populates="scan_run", uselist=False)


class RuleAnalysisResult(Base):
    """Phase 1 output - deterministic SAST + mechanical extraction of tool
    declarations from the MCP server's own code (name/description/schema)"""
    __tablename__ = "rule_analysis_results"

    scan_run_id = Column(String, ForeignKey("scan_runs.scan_run_id"), primary_key=True)
    verdict = Column(SAEnum(RuleVerdict), nullable=False)
    rule_findings = relationship("RuleFinding", back_populates="rule_result", cascade="all, delete-orphan")
    tool_declarations = relationship("ToolDeclaration", back_populates="rule_result", cascade="all, delete-orphan")
    reviewed_at = Column(DateTime, server_default=func.now())

    scan_run = relationship("ScanRun", back_populates="rule_result")


class RuleFinding(Base):
    """Normalizes rule_findings the same way
    ToolBehavioralFinding normalizes llm_findings.
    """
    __tablename__ = "rule_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_run_id = Column(String, ForeignKey("rule_analysis_results.scan_run_id"), nullable=False, index=True)
    server_id = Column(String, ForeignKey("servers.server_id"), nullable=False, index=True)  # denormalized 
    analyzer = Column(String, nullable=False)     # "semgrep_sast" | "semgrep_supply_chain" | cisco's vulnerable-package analyzer key
    severity = Column(String, nullable=False, index=True)
    rule_id = Column(String, nullable=True)        # semgrep check_id - null for Cisco's threat-shaped findings
    file = Column(String, nullable=True)           # null for Cisco's threat-shaped findings (function/package-level, not file+line)
    line = Column(Integer, nullable=True)
    message = Column(Text, nullable=True)          # semgrep's message, or Cisco's threat_summary - coalesced at insert time
    details = Column(JSON, nullable=True)          # analyzer-specific extras: cve/package/ecosystem/reachable/fix_versions (SCA), threat_names/mcp_taxonomies/total_findings (Cisco)

    rule_result = relationship("RuleAnalysisResult", back_populates="rule_findings")


class ToolDeclaration(Base):
    """One row per declared tool, per scan."""
    __tablename__ = "tool_declarations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_run_id = Column(String, ForeignKey("rule_analysis_results.scan_run_id"), nullable=False, index=True)
    server_id = Column(String, ForeignKey("servers.server_id"), nullable=False, index=True)  # denormalized - lets you query "all tools for server X" without joining through scan_runs
    name = Column(String, nullable=False, index=True)
    description = Column(Text)
    parameter_schema = Column(JSON, nullable=False, default=dict)  # kept as JSON - schema shape is inherently nested/variable; not worth exploding into columns

    rule_result = relationship("RuleAnalysisResult", back_populates="tool_declarations")
    behavioral_findings = relationship("ToolBehavioralFinding", back_populates="tool_declaration")

class LlmAnalysisResult(Base):
    """Phase 2 output - semantic comparison of implementation against the
    tool_declarations"""
    __tablename__ = "llm_analysis_results"

    scan_run_id = Column(String, ForeignKey("scan_runs.scan_run_id"), primary_key=True)
    verdict = Column(SAEnum(LlmVerdict), nullable=False)
    tool_findings = relationship("ToolBehavioralFinding", back_populates="llm_result", cascade="all, delete-orphan")
    reviewed_at = Column(DateTime, server_default=func.now())

    scan_run = relationship("ScanRun", back_populates="llm_result")

class ToolBehavioralFinding(Base):
    __tablename__ = "tool_behavioral_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_run_id = Column(String, ForeignKey("llm_analysis_results.scan_run_id"), nullable=False, index=True)
    tool_declaration_id = Column(Integer, ForeignKey("tool_declarations.id"), nullable=True, index=True)
    tool_name = Column(String, nullable=False) 
    analyzer = Column(String, nullable=False, default="behavioral_analyzer")
    severity = Column(String, nullable=False, index=True)
    threat_summary = Column(Text)
    threat_names = Column(JSON, default=list)
    mcp_taxonomies = Column(JSON, default=list)
    total_findings = Column(Integer, default=0)
    target = Column(String, nullable=True)

    llm_result = relationship("LlmAnalysisResult", back_populates="tool_findings")
    tool_declaration = relationship("ToolDeclaration", back_populates="behavioral_findings")