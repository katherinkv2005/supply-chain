import json
from pathlib import Path


# Find the project root
PROJECT_ROOT = Path(__file__).resolve().parents[3]

# Sidharth's output = our input
INPUT_FILE = (
    PROJECT_ROOT
    / "backend"
    / "vuln_intel"
    / "output"
    / "vulnerabilities.json"
)

# Amal's output
OUTPUT_FILE = (
    PROJECT_ROOT
    / "backend"
    / "vuln_prioritization"
    / "output"
    / "prioritized_vulnerabilities.json"
)


SEVERITY_SCORE = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


def get_severity_score(severity):
    if not severity:
        return 0

    return SEVERITY_SCORE.get(
        str(severity).upper(),
        0
    )


def get_cvss_score(vulnerability):
    value = vulnerability.get("cvss_score")

    if value is None:
        return 0.0

    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0


def get_dependency_score(vulnerability):
    dependency_type = str(
        vulnerability.get("dependency_type", "")
    ).lower()

    if dependency_type == "direct":
        return 1

    return 0


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


def prioritize(vulnerabilities):

    ranked = []

    for vulnerability in vulnerabilities:

        item = dict(vulnerability)

        item["risk_score"] = (
            calculate_risk_score(
                vulnerability
            )
        )

        item["reason"] = create_reason(
            vulnerability
        )

        ranked.append(item)

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

    for index, vulnerability in enumerate(
        ranked,
        start=1
    ):
        vulnerability["priority"] = index

    return ranked


def main():

    print("=" * 60)
    print("  Vulnerability Prioritization Module")
    print("=" * 60)

    print(f"[INFO] Input : {INPUT_FILE}")
    print(f"[INFO] Output: {OUTPUT_FILE}")

    if not INPUT_FILE.exists():

        print(
            "[ERROR] Sidharth's vulnerability "
            "output was not found."
        )

        return 1

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

    prioritized = prioritize(
        vulnerabilities
    )

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

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

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

    print("\n[SUCCESS] Prioritization completed.")

    print(
        f"[SUCCESS] Output saved to: "
        f"{OUTPUT_FILE}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())