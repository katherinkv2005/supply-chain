import subprocess
import json
import sys
import os
from datetime import datetime


sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from schemas import SBOM, SBOMComponent


def scan_repo(repo_path: str) -> SBOM:
    result = subprocess.run(
        ["grype", f"dir:{repo_path}", "-o", "json"],
        capture_output=True, text=True
    )
    data = json.loads(result.stdout)

    components = {}
    for match in data.get("matches", []):
        pkg = match["artifact"]
        cid = f'{pkg["name"]}=={pkg["version"]}'
        if cid not in components:
            locations = pkg.get("locations", [{}])
            components[cid] = SBOMComponent(
                component_id=cid,
                name=pkg["name"],
                version=pkg["version"],
                ecosystem=pkg.get("type", "unknown"),
                is_direct=True,
                depends_on=[],
                manifest_file=locations[0].get("path", "unknown") if locations else "unknown",
            )

    return SBOM(
        repo_url=repo_path,
        scanned_at=datetime.utcnow(),
        components=list(components.values())
    )
def export_cyclonedx(sbom: SBOM, output_path: str = "cyclonedx_sbom.json"):
    """Convert our SBOM object into a minimal valid CycloneDX JSON file."""
    cyclonedx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": c.name,
                "version": c.version,
                "purl": f"pkg:{c.ecosystem}/{c.name}@{c.version}"
            }
            for c in sbom.components
        ]
    }
    with open(output_path, "w") as f:
        json.dump(cyclonedx, f, indent=2)
    return output_path

if __name__ == "__main__":
    sbom = scan_repo("./real_target_repo")
    output = sbom.model_dump_json(indent=2)
    print(output)
    with open("sbom_output.json", "w") as f:
        f.write(output)
    export_cyclonedx(sbom, "cyclonedx_sbom.json")