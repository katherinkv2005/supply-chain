import json
from pathlib import Path


# ============================================================
# FIND PROJECT ROOT
# ============================================================

# prioritizer.py location:
#
# supply-chain/
#   backend/
#     vuln_intel/
#       vuln_prioritization/
#         src/
#           prioritizer.py
#
# parents[0] = src
# parents[1] = vuln_prioritization
# parents[2] = vuln_intel
# parents[3] = backend
# parents[4] = supply-chain

PROJECT_ROOT = Path(__file__).resolve().parents[4]


# ============================================================
# INPUT / OUTPUT FILES
# ============================================================

# Sidharth's vulnerability scanner output
INPUT_FILE = (
    PROJECT_ROOT
    / "backend"
    / "vuln_intel"
    / "output"
    / "vulnerabilities.json"
)

# Amal's prioritization output
OUTPUT_FILE = (
    PROJECT_ROOT
    / "backend"
    / "vuln_intel"
    / "vuln_prioritization"
    / "output"
    / "prioritized_vulnerabilities.json"
)


# ============================================================
# SEVERITY SCORES
# ============================================================

SEVERITY_SCORE = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


# ============================================================
# GET SEVERITY SCORE
# ============================================================

def get_severity_score(severity):
    if not severity:
        return 0

    return SEVERITY_SCORE.get(
        str(severity).upper(),
        0
    )


# ============================================================
# GET CVSS SCORE
# ============================================================

def get_cvss_score(vulnerability):
    value = vulnerability.get("cvss_score")

    if value is None:
        return 0.0

    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0


# ============================================================
# GET DEPENDENCY SCORE
# ============================================================

def get_dependency_score(vulnerability):
    dependency_type = str(
        vulnerability.get("dependency_type", "")
    ).lower()

    if dependency_type == "direct":
        return 1

    return 0


# ============================================================
# CALCULATE RISK SCORE
# ============================================================

def calculate_risk_score(vulnerability):

    severity_score = get_severity_score(
        vulnerability.get("severity")
    )

    cvss_score = get_cvss_score(
        vulnerability
    )

    dependency_score = get_dependency_score(
        vulnerability
    )

    return (
        severity_score * 10
        + cvss_score
        + dependency_score
    )


# ============================================================
# CREATE REASON
# ============================================================

def create_reason(vulnerability):

    severity = vulnerability.get(
        "severity",
        "Unknown"
    )

    cvss = vulnerability.get(
        "cvss_score"
    )

    dependency_type = vulnerability.get(
        "dependency_type",
        "unknown"
    )

    if cvss is not None:
        reason = (
            f"{severity} severity "
            f"with CVSS {cvss}"
        )
    else:
        reason = (
            f"{severity} severity "
            f"with no CVSS score"
        )

    if str(dependency_type).lower() == "direct":
        reason += "; direct dependency"

    return reason


# ============================================================
# PRIORITIZE VULNERABILITIES
# ============================================================

def prioritize(vulnerabilities):

    ranked = []

    for vulnerability in vulnerabilities:

        item = dict(vulnerability)

        # Calculate risk
        item["risk_score"] = calculate_risk_score(
            vulnerability
        )

        # Add explanation
        item["reason"] = create_reason(
            vulnerability
        )

        ranked.append(item)

    # Sort:
    # 1. Severity
    # 2. CVSS
    # 3. Dependency type
    ranked.sort(
        key=lambda item: (
            get_severity_score(
                item.get("severity")
            ),
            get_cvss_score(item),
            get_dependency_score(item),
        ),
        reverse=True
    )

    # Add priority numbers
    for index, vulnerability in enumerate(
        ranked,
        start=1
    ):
        vulnerability["priority"] = index

    return ranked


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("  Vulnerability Prioritization Module")
    print("=" * 60)

    print(f"[INFO] Input : {INPUT_FILE}")
    print(f"[INFO] Output: {OUTPUT_FILE}")

    # --------------------------------------------------------
    # Check input
    # --------------------------------------------------------

    if not INPUT_FILE.exists():

        print(
            "[ERROR] Vulnerability scanner output "
            "was not found."
        )

        print(
            f"[ERROR] Expected file: {INPUT_FILE}"
        )

        return 1

    # --------------------------------------------------------
    # Read vulnerability scanner output
    # --------------------------------------------------------

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        data = json.load(file)

    vulnerabilities = data.get(
        "vulnerabilities",
        []
    )

    print(
        f"[INFO] Vulnerabilities received: "
        f"{len(vulnerabilities)}"
    )

    # --------------------------------------------------------
    # Prioritize
    # --------------------------------------------------------

    prioritized = prioritize(
        vulnerabilities
    )

    # --------------------------------------------------------
    # Prepare output
    # --------------------------------------------------------

    output = {
        "metadata": {
            "total_vulnerabilities": len(
                prioritized
            ),
            "prioritization_method":
                "Severity + CVSS + dependency type"
        },
        "prioritized_vulnerabilities":
            prioritized
    }

    # Create output directory
    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Save output
    # --------------------------------------------------------

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            output,
            file,
            indent=2
        )

    # --------------------------------------------------------
    # Display results
    # --------------------------------------------------------

    print(
        f"[INFO] Vulnerabilities prioritized: "
        f"{len(prioritized)}"
    )

    print("\nTop 10 vulnerabilities:")

    for vulnerability in prioritized[:10]:

        print(
            f"{vulnerability['priority']}. "
            f"{vulnerability.get('cve_id', 'N/A')} | "
            f"{vulnerability.get('package', 'N/A')} | "
            f"{vulnerability.get('severity', 'N/A')} | "
            f"CVSS: "
            f"{vulnerability.get('cvss_score', 'N/A')} | "
            f"Risk: "
            f"{vulnerability['risk_score']}"
        )

    print(
        "\n[SUCCESS] Prioritization completed."
    )

    print(
        f"[SUCCESS] Output saved to: "
        f"{OUTPUT_FILE}"
    )

    return 0


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":
    raise SystemExit(main())