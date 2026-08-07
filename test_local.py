import os
from dotenv import load_dotenv

load_dotenv()

from backend.schemas import VulnerabilityItem
from backend.reachability_patch.service import process_vulnerability

vuln = VulnerabilityItem(
    cve_id="CVE-2020-14343",
    package_name="pyyaml",
    current_version="5.3.1",
    fixed_version="5.4",
    severity="HIGH",
    description="Arbitrary code execution in PyYAML load method."
)

print("=== TESTING MODULE ===")
res = process_vulnerability(".", vuln)

print(f"CVE: {res.cve_id}")
print(f"Is Reachable: {res.is_reachable}")
print(f"Target File: {res.target_file}")
print("\n--- ORIGINAL CONTENT ---")
print(res.original_content)
print("\n--- PATCHED CONTENT ---")
print(res.patched_content)
print("\n--- PATCH DIFF ---")
print(res.patch_diff)
print("\n--- EXPLANATION MARKDOWN ---")
print(res.explanation_markdown)