import subprocess
from pathlib import Path

def run_tests(repo_path):

    result = subprocess.run(
        ["pytest"],
        cwd=repo_path,
        capture_output=True,
        text=True
    )

    # Save the test results in this folder
    output_file = Path(__file__).parent / "test_results.txt"

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(result.stdout)

    return {
        "passed": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr
    }