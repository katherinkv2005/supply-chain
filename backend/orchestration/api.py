from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sys, json, subprocess
sys.path.insert(0, ".")
from run_full_pipeline import run_full_pipeline

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    repo_url: str

@app.post("/scan")
def scan(req: ScanRequest):
    repo_path = run_full_pipeline(req.repo_url)

    with open("backend/reachability_patch/patch_output.json") as f:
        patches = json.load(f)

    with open("backend/vuln_intel/output/vulnerabilities.json") as f:
        vuln_data = json.load(f)

    reachable = [p for p in patches if p.get("is_reachable")]
    unreachable = [p for p in patches if not p.get("is_reachable")]

    release_results = []
    try:
        subprocess.run(
            [sys.executable, "backend/validate_release/main.py"],
            capture_output=True, text=True, timeout=120
        )
        with open("backend/validate_release/release_results.json") as f:
            release_results = json.load(f)
    except Exception as e:
        print(f"[API] release step error: {e}")

    return {
        "repo_url": req.repo_url,
        "total_vulnerabilities": vuln_data.get("metadata", {}).get("total_vulnerabilities", 0),
        "severity_breakdown": vuln_data.get("metadata", {}).get("severity_summary", {}),
        "reachable_count": len(reachable),
        "unreachable_count": len(unreachable),
        "reachable": reachable,
        "unreachable": unreachable,
        "release_results": release_results
    }