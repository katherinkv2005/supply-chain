from backend.schemas import VulnerabilityItem, PatchResult
from .reachability import check_reachability
from .patch_generator import generate_patch

def process_vulnerability(repo_path: str, vuln: VulnerabilityItem) -> PatchResult:
    """
    Executes Alan's AST reachability check followed by Razik's Claude patch generator.
    """
    reachability_res = check_reachability(repo_path, vuln)
    patch_res = generate_patch(reachability_res, repo_path)
    return patch_res