from pydantic import BaseModel
from typing import Optional, Literal, List
from datetime import datetime


class SBOMComponent(BaseModel):
    component_id: str
    name: str
    version: str
    ecosystem: str
    is_direct: bool
    depends_on: list[str] = []
    manifest_file: str
    manifest_line: Optional[int] = None


class SBOM(BaseModel):
    repo_url: str
    scanned_at: datetime
    components: list[SBOMComponent]


class Vulnerability(BaseModel):
    vuln_id: str
    cve_id: str
    component_id: str
    severity: Literal["low", "medium", "high", "critical"]
    cvss_score: float
    description: str
    fixed_version: str
    references: list[str] = []
    priority_score: float = 0.0
    is_malicious_package: bool = False


class VulnerabilityItem(BaseModel):
    cve_id: str
    package_name: str
    current_version: str
    fixed_version: str
    severity: str
    description: str


class ReachabilityResult(BaseModel):
    vuln_id: Optional[str] = None
    vulnerability: Optional[VulnerabilityItem] = None
    reachable: Optional[bool] = None
    is_reachable: Optional[bool] = None
    confidence: Optional[float] = None
    evidence: Optional[str] = None
    method: Optional[Literal["import-check", "taint", "call-graph"]] = None
    detected_imports: List[str] = []
    matched_files: List[str] = []
    evidence_snippet: Optional[str] = None


class Patch(BaseModel):
    vuln_id: str
    patch_type: Literal["version-bump", "code-fix"]
    diff: str
    rationale: str
    confidence: float
    target_files: list[str]


class PatchResult(BaseModel):
    cve_id: str
    package_name: str
    is_reachable: bool
    target_file: str
    original_content: str
    patched_content: str
    patch_diff: str
    explanation_markdown: str
    requires_human_approval: bool


class PRResult(BaseModel):
    vuln_id: str
    pr_url: Optional[str] = None
    branch_name: str
    test_pass_before: bool
    test_pass_after: bool
    risk_score: float
    status: Literal["draft", "open", "needs-approval", "rejected"]


class AuditEvent(BaseModel):
    event_id: str
    agent: str
    action: str
    input_ref: str
    output_ref: str
    reasoning: str
    timestamp: datetime


class PipelineResult(BaseModel):
    sbom: SBOM
    vulnerabilities: list[Vulnerability]
    reachability_results: list[ReachabilityResult]
    patches: list[Patch]
    pr_results: list[PRResult]
    audit_log: list[AuditEvent]