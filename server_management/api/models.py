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
