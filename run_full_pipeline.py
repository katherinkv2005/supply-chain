import subprocess
import sys
import os
import json
import uuid
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, ".")

from backend.scan_sbom.scan import scan_repo, export_cyclonedx
from backend.schemas import VulnerabilityItem
from backend.reachability_patch.service import process_vulnerability


def clone_repo(repo_url: str) -> Path:
    scan_id = str(uuid.uuid4())[:8]
    dest = Path(f"backend/scan_sbom/scan_{scan_id}")
    subprocess.run(["git", "clone", repo_url, str(dest)], check=True)
    return dest


def run_full_pipeline(repo_url: str):
    print(f"[1/5] Cloning {repo_url}...")
    repo_path = clone_repo(repo_url)

    print("[2/5] Generating SBOM...")
    sbom = scan_repo(str(repo_path))
    export_cyclonedx(sbom, "backend/scan_sbom/cyclonedx_sbom.json")

    print("[3/5] Scanning for CVEs...")
    subprocess.run([
        sys.executable, "backend/vuln_intel/src/run_scan.py",
        "--sbom", "backend/scan_sbom/cyclonedx_sbom.json"
    ], check=True)

    print("[4/5] Prioritizing...")
    subprocess.run([
        sys.executable,
        "backend/vuln_intel/vuln_prioritization/src/prioritizer.py"
    ], check=True)

    print("[5/5] Checking reachability + generating patches...")
    with open("backend/vuln_intel/vuln_prioritization/output/prioritized_vulnerabilities.json") as f:
        data = json.load(f)

    results = []
    for v in data.get("prioritized_vulnerabilities", [])[:15]:
        vuln = VulnerabilityItem(
            cve_id=v.get("cve_id", "UNKNOWN"),
            package_name=v.get("package", "unknown"),
            current_version=v.get("installed_version", "unknown"),
            fixed_version=v.get("fixed_version", "unknown"),
            severity=v.get("severity", "UNKNOWN"),
            description=v.get("description", "")
        )
        result = process_vulnerability(str(repo_path), vuln)
        results.append(result.model_dump())

    with open("backend/reachability_patch/patch_output.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[DONE] Pipeline complete for {repo_url}")
    return repo_path


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else input("GitHub repo URL: ")
    run_full_pipeline(url)