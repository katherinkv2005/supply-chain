import json
import subprocess
from dummy_data import REPO_PATH
from validator import apply_patch
from test_runner import run_tests
from report_generator import generate_report
from github_pr import (
    create_branch,
    commit_changes,
    push_branch,
    create_pull_request
)


def reset_repo_to_clean_state(repo_path):
    """
    Resets the local repo back to exactly what's on GitHub's main branch.
    This makes every run idempotent -- no more 'already patched' failures
    from a previous run's leftover local changes.
    """
    print("[RESET] Syncing local repo with GitHub main...")
    subprocess.run(["git", "fetch", "origin"], cwd=repo_path, capture_output=True)
    subprocess.run(["git", "checkout", "main"], cwd=repo_path, capture_output=True)
    subprocess.run(["git", "reset", "--hard", "origin/main"], cwd=repo_path, capture_output=True)
    print("[RESET] Done.\n")


print("Starting Validation...\n")

reset_repo_to_clean_state(REPO_PATH)

release_results = []

applied_patches = apply_patch(REPO_PATH)

if not applied_patches:
    print("No reachable patches were applied. Nothing to validate or release.")
    with open("backend/validate_release/release_results.json", "w") as f:
        json.dump([], f, indent=2)
    exit()

print(f"\n{len(applied_patches)} patch(es) applied successfully.\n")

print("Running tests...\n")
result = run_tests(REPO_PATH)
print(result["stdout"])

for patch in applied_patches:
    patch_id = patch["cve_id"]
    entry = {"cve_id": patch_id, "package_name": patch["package_name"], "pr_url": None, "status": "failed"}

    if result["passed"]:
        print(f"Validation Successful for {patch_id}\n")
        generate_report("PASS", patch_id, result["stdout"])

        branch_name = f"fix/{patch_id.replace(':', '-').lower()}"

        branch = create_branch(branch_name)
        print(branch)

        commit = commit_changes(
            message=f"Automatic Security Patch: {patch_id}",
            file_path=patch["target_file"],
            repo_local_path=REPO_PATH,
            branch_name=branch_name
        )
        print(commit)

        push = push_branch(branch_name)
        print(push)

        pr = create_pull_request(
            branch_name=branch_name,
            title=f"Security fix: {patch['package_name']} — {patch_id}",
            body=patch["explanation_markdown"]
        )
        print(pr)

        if pr.get("status") == "success":
            entry["pr_url"] = pr.get("url")
            entry["status"] = "success"
    else:
        print(f"Validation Failed for {patch_id}")
        generate_report("FAIL", patch_id, result["stdout"])

    release_results.append(entry)

with open("backend/validate_release/release_results.json", "w") as f:
    json.dump(release_results, f, indent=2)

print(f"\n[SAVED] Release results written to backend/validate_release/release_results.json")