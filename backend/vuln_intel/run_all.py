import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Sidharth's vulnerability scanner
SCANNER = (
    PROJECT_ROOT
    / "backend"
    / "vuln_intel"
    / "src"
    / "run_scan.py"
)

# Amal's vulnerability prioritization
PRIORITIZER = (
    PROJECT_ROOT
    / "backend"
    / "vuln_intel"
    / "vuln_prioritization"
    / "src"
    / "prioritizer.py"
)


def run_script(script):
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=PROJECT_ROOT
    )

    return result.returncode == 0


def main():

    # Run Sidharth's scanner
    if not SCANNER.exists():
        print("[ERROR] Vulnerability scanner not found.")
        return 1

    if not run_script(SCANNER):
        print("[ERROR] Vulnerability scan failed.")
        return 1

    # Run Amal's prioritization
    if not PRIORITIZER.exists():
        print("[ERROR] Vulnerability prioritizer not found.")
        return 1

    if not run_script(PRIORITIZER):
        print("[ERROR] Vulnerability prioritization failed.")
        return 1

    print("[SUCCESS] Vulnerability intelligence pipeline completed.")

    return 0


if __name__ == "__main__":
    sys.exit(main())