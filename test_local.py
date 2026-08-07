import os
from dotenv import load_dotenv

load_dotenv()

from backend.schemas import VulnerabilityItem
from backend.reachability_patch.service import process_vulnerability

vuln = VulnerabilityItem(
    cve_id="GHSA-xqr8-7jwr-rhp7",
    package_name="certifi",
    current_version="2018.11.29",
    fixed_version="2023.7.22",
    severity="High",
    description="certifi vulnerability found in real scan"
)

print("=== TESTING MODULE ===")
res = process_vulnerability("backend/scan_sbom/real_target_repo", vuln)

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