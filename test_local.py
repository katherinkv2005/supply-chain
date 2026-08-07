"""
Manual smoke-test for the reachability_patch stage in isolation.

NOTE: This script intentionally does NOT write to
backend/reachability_patch/patch_output.json anymore. That file is owned
by run_reachability_pipeline.py (the real Pair 2 -> Pair 3 connector) and
is consumed as a LIST by validate_release/validator.py. Writing a single
dict here previously overwrote that list and silently broke Pair 4.

Use this file only to sanity-check one CVE by hand; use
run_reachability_pipeline.py to actually feed the real pipeline.
"""

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

print("=== TESTING MODULE (manual, isolated — does not affect the real pipeline) ===")
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