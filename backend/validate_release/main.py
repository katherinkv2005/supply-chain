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

status = apply_patch(REPO_PATH)

if not status:
    print("Patch could not be applied.")
    exit()

print("Patch applied successfully.\n")

print("Running tests...\n")

result = run_tests(REPO_PATH)

print(result["stdout"])

if result["passed"]:
    print("Validation Successful")
else:
    print("Validation Failed")

if result["passed"]:

    print("Validation Successful")

    generate_report(
        "PASS",
        "PATCH-001",
        result["stdout"]
    )

else:

    print("Validation Failed")

    generate_report(
        "FAIL",
        "PATCH-001",
        result["stdout"]
    )
if result["passed"]:

    print("Validation Successful")

    print("\n------ Starting Amal's Work ------")

    # Step 1: Create Branch
    branch = create_branch("fix/PATCH-001")
    print(branch)

    # Step 2: Commit Changes
    commit = commit_changes("Automatic Security Patch")
    print(commit)

    # Step 3: Push Branch
    push = push_branch("fix/PATCH-001")
    print(push)

    # Step 4: Create Pull Request
    pr = create_pull_request()
    print(pr)

else:
    print("Validation Failed")