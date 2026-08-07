import json
import os
from dotenv import load_dotenv

load_dotenv()

from backend.schemas import VulnerabilityItem
from backend.reachability_patch.service import process_vulnerability

PRIORITIZED_FILE = "backend/vuln_intel/vuln_prioritization/output/prioritized_vulnerabilities.json"
REPO_PATH = "backend/scan_sbom/real_target_repo"
OUTPUT_FILE = "backend/reachability_patch/patch_output.json"

TOP_N = 15  # how many top vulnerabilities to process

with open(PRIORITIZED_FILE, "r") as f:
    data = json.load(f)

vulnerabilities = data.get("prioritized_vulnerabilities", [])[:TOP_N]

results = []

for v in vulnerabilities:
    vuln = VulnerabilityItem(
        cve_id=v.get("cve_id", "UNKNOWN"),
        package_name=v.get("package", "unknown"),
        current_version=v.get("installed_version", "unknown"),
        fixed_version=v.get("fixed_version", "unknown"),
        severity=v.get("severity", "UNKNOWN"),
        description=v.get("description", "")
    )

    print(f"\n=== Processing {vuln.cve_id} ({vuln.package_name}) ===")
    result = process_vulnerability(REPO_PATH, vuln)

    print(f"Reachable: {result.is_reachable}")

    results.append({
        "cve_id": result.cve_id,
        "package_name": result.package_name,
        "is_reachable": result.is_reachable,
        "target_file": result.target_file,
        "original_content": result.original_content,
        "patched_content": result.patched_content,
        "patch_diff": result.patch_diff,
        "explanation_markdown": result.explanation_markdown,
        "requires_human_approval": result.requires_human_approval
    })

with open(OUTPUT_FILE, "w") as f:
    json.dump(results, f, indent=2)

reachable_count = sum(1 for r in results if r["is_reachable"])
print(f"\n[SUMMARY] Processed {len(results)} vulnerabilities — {reachable_count} reachable, {len(results) - reachable_count} filtered as unreachable.")
print(f"[SAVED] All results written to {OUTPUT_FILE}")