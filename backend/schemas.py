from pydantic import BaseModel
from typing import List, Optional

class VulnerabilityItem(BaseModel):
    cve_id: str
    package_name: str
    current_version: str
    fixed_version: str
    severity: str
    description: str

class ReachabilityResult(BaseModel):
    vulnerability: VulnerabilityItem
    is_reachable: bool
    detected_imports: List[str]
    matched_files: List[str]
    evidence_snippet: Optional[str] = None

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