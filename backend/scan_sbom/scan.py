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


if __name__ == "__main__":
    sbom = scan_repo("./real_target_repo")
    print(sbom.model_dump_json(indent=2))

