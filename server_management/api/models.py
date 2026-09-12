from pydantic import BaseModel, Field
from server_management.database.db_models import ScanStatus, LlmVerdict, RuleVerdict

class RegisterServerRequest(BaseModel):
    repo_url: str
    installation_id: int
    allowed_destinations: list[str]


class ServerResponse(BaseModel):
    server_id: str
    repo_url: str
    installation_id: int


class ManifestResponse(BaseModel):
    server_id: str
    allowed_destinations: list[str]
    tool_declarations: list[dict] | None
    version: int


class UpdateManifestRequest(BaseModel):
    allowed_destinations: list[str]


class CreateScanRunRequest(BaseModel):
    server_id: str
    commit_sha: str


class ScanRunResponse(BaseModel):
    scan_run_id: str
    server_id: str
    commit_sha: str
    status: ScanStatus


class RuleAnalysisResultRequest(BaseModel):
    verdict: RuleVerdict
    rule_findings: list[dict] = Field(default_factory=list)
    tool_declarations: list[dict] = Field(default_factory=list)     


class LlmAnalysisResultRequest(BaseModel):
    verdict: LlmVerdict
    llm_findings: list[dict] = Field(default_factory=list)
    suspicious_branches: list[dict] = Field(default_factory=list)


class ToolDeclarationsResponse(BaseModel):
    tool_declarations: list[dict]


class ServerScoreResponse(BaseModel):
    overall_score: float | None = None
    security_score: float | None = None
    operational_score: float | None = None
    computed_at: str | None = None


class ServerToolResponse(BaseModel):
    name: str
    description: str | None = None
    parameter_schema: dict


class ServerFindingResponse(BaseModel):
    id: int
    phase: str
    tool_name: str | None = None
    analyzer: str
    severity: str
    message: str | None = None
    details: dict | None = None
    file: str | None = None
    line: int | None = None


class ServerOverviewResponse(BaseModel):
    server_id: str
    repo_url: str
    registered_at: str | None
    allowed_destinations: list[str]
    current_verdict: str | None
    scan_in_progress: bool
    latest_scan_id: str | None
    latest_scan_date: str | None
    commit_sha: str | None
    score: ServerScoreResponse
    tools: list[ServerToolResponse]
    findings: list[ServerFindingResponse]


class ServerScanHistoryItemResponse(BaseModel):
    scan_run_id: str
    commit_sha: str
    status: ScanStatus
    started_at: str | None
    finished_at: str | None
    verdict: str | None
    score: ServerScoreResponse


class ServerScanHistoryResponse(BaseModel):
    server_id: str
    scans: list[ServerScanHistoryItemResponse]


class ServerScanDetailResponse(ServerOverviewResponse):
    scan_id: str
