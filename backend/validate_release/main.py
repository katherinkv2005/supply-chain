from dummy_data import REPO_PATH
from validator import apply_patch
from test_runner import run_tests
from report_generator import generate_report
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