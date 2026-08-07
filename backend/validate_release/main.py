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
    else:
        print(f"Validation Failed for {patch_id}")
        generate_report("FAIL", patch_id, result["stdout"])