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

print("Starting Validation...\n")

applied_patches = apply_patch(REPO_PATH)

if not applied_patches:
    print("No reachable patches were applied. Nothing to validate or release.")
    exit()

print(f"\n{len(applied_patches)} patch(es) applied successfully.\n")

print("Running tests...\n")
result = run_tests(REPO_PATH)
print(result["stdout"])

for patch in applied_patches:
    patch_id = patch["cve_id"]

    if result["passed"]:
        print(f"Validation Successful for {patch_id}\n")
        generate_report("PASS", patch_id, result["stdout"])

        branch_name = f"fix/{patch_id.replace(':', '-')}"
        branch = create_branch(branch_name)
        print(branch)

        commit = commit_changes(f"Automatic Security Patch: {patch_id}")
        print(commit)

        push = push_branch(branch_name)
        print(push)

        pr = create_pull_request()
        print(pr)
    else:
        print(f"Validation Failed for {patch_id}")
        generate_report("FAIL", patch_id, result["stdout"])