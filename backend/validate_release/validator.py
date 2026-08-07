import json
import re
from pathlib import Path


def apply_patch(repo_path: Path, patch_file="backend/reachability_patch/patch_output.json"):
    """
    Applies real, reachable patches produced by the reachability_patch stage.
    """
    with open(patch_file, "r") as f:
        data = json.load(f)

    patches = data if isinstance(data, list) else [data]

    applied = []

    for patch in patches:
        if not patch.get("is_reachable"):
            print(f"[SKIP] {patch.get('cve_id')} ({patch.get('package_name')}) "
                  f"is not reachable — no patch applied.")
            continue

        target = repo_path / patch["target_file"]
        if not target.exists():
            print(f"[ERROR] Target file not found: {target}")
            continue

        text = target.read_text()

        # Case-insensitive match: package names in requirements.txt are
        # often capitalized differently than how they're recorded in
        # scan/CVE data (e.g. "Flask" vs "flask").
        pattern = re.compile(re.escape(patch["original_content"]), re.IGNORECASE)
        match = pattern.search(text)

        if not match:
            print(f"[ERROR] Original content not found in {target} "
                  f"for {patch.get('cve_id')} — already patched or mismatched.")
            continue

        # Replace preserving the actual matched text's position, but
        # substituting in the new version string.
        text = pattern.sub(patch["patched_content"], text, count=1)
        target.write_text(text)
        print(f"[APPLIED] {patch['cve_id']}: "
              f"{match.group(0)} -> {patch['patched_content']}")
        applied.append(patch)

    return applied