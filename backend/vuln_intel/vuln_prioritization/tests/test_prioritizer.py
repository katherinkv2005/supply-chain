from backend.vuln_prioritization.src.prioritizer import (
    get_severity_score,
    get_cvss_score,
    calculate_risk_score,
    prioritize,
)


def test_severity_order():
    assert get_severity_score("Critical") > get_severity_score("High")
    assert get_severity_score("High") > get_severity_score("Medium")
    assert get_severity_score("Medium") > get_severity_score("Low")


def test_cvss_score():
    vulnerability = {
        "cvss_score": 9.8
    }

    assert get_cvss_score(vulnerability) == 9.8


def test_risk_score():
    vulnerability = {
        "severity": "Critical",
        "cvss_score": 9.8,
        "dependency_type": "direct",
    }

    assert calculate_risk_score(vulnerability) == 50.8


def test_prioritization_order():
    vulnerabilities = [
        {
            "cve_id": "TEST-LOW",
            "package": "test",
            "severity": "Low",
            "cvss_score": 3.0,
            "dependency_type": "direct",
        },
        {
            "cve_id": "TEST-CRITICAL",
            "package": "test",
            "severity": "Critical",
            "cvss_score": 9.8,
            "dependency_type": "direct",
        },
        {
            "cve_id": "TEST-HIGH",
            "package": "test",
            "severity": "High",
            "cvss_score": 8.5,
            "dependency_type": "direct",
        },
    ]

    result = prioritize(vulnerabilities)

    assert result[0]["cve_id"] == "TEST-CRITICAL"
    assert result[1]["cve_id"] == "TEST-HIGH"
    assert result[2]["cve_id"] == "TEST-LOW"


def test_priority_numbers():
    vulnerabilities = [
        {
            "cve_id": "A",
            "severity": "High",
            "cvss_score": 8.0,
            "dependency_type": "direct",
        },
        {
            "cve_id": "B",
            "severity": "Low",
            "cvss_score": 2.0,
            "dependency_type": "transitive",
        },
    ]

    result = prioritize(vulnerabilities)

    assert result[0]["priority"] == 1
    assert result[1]["priority"] == 2