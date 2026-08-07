"""
run_scan.py
-----------
Main entry point for Sidharth's Vulnerability Detection / CVE Intelligence module.

Complete workflow:
  1. Read SBOM from input/
  2. Run Grype via grype_scanner.py
  3. Parse output via vulnerability_parser.py
  4. Write clean JSON to output/vulnerabilities.json
  5. Print a summary table to the terminal

Usage
-----
    # Default: uses input/sample_sbom.json
    python src/run_scan.py

    # Custom SBOM path (e.g. when real SBOM is available from another team member)
    python src/run_scan.py --sbom path/to/real_sbom.json

    # Custom output path
    python src/run_scan.py --output path/to/results.json
"""

import argparse
import json
import sys
from pathlib import Path

# Force line-buffered output — ensures every print() flushes immediately
# even when stdout is not a TTY (e.g. redirected, piped, or task runner).
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

# ---------------------------------------------------------------------------
# Path resolution — works regardless of working directory
# ---------------------------------------------------------------------------

MODULE_ROOT = Path(__file__).parent.parent   # backend/vuln_intel/
DEFAULT_SBOM = MODULE_ROOT / "input" / "sample_sbom.json"
DEFAULT_OUTPUT = MODULE_ROOT / "output" / "vulnerabilities.json"

# ---------------------------------------------------------------------------
# Import sibling modules
# ---------------------------------------------------------------------------

sys.path.insert(0, str(Path(__file__).parent))

# pyrefly: ignore[missing-import]
from grype_scanner import (
    GrypeNotInstalledError,
    GrypeScanError,
    InvalidSBOMError,
    run_grype_scan,
)
# pyrefly: ignore[missing-import]
from vulnerability_parser import parse_grype_output


# ---------------------------------------------------------------------------
# Terminal formatting helpers
# ---------------------------------------------------------------------------

# ANSI colour codes (gracefully disabled on terminals that don't support them)
_RESET = "\033[0m"
_BOLD  = "\033[1m"
_RED   = "\033[91m"
_YELLOW = "\033[93m"
_GREEN = "\033[92m"
_CYAN  = "\033[96m"
_GREY  = "\033[90m"

SEVERITY_COLOUR = {
    "CRITICAL":   _RED,
    "HIGH":       _RED,
    "MEDIUM":     _YELLOW,
    "LOW":        _CYAN,
    "NEGLIGIBLE": _GREY,
    "UNKNOWN":    _GREY,
}


def _coloured(text: str, colour: str) -> str:
    """Wrap text in an ANSI colour code if stdout is a TTY."""
    if sys.stdout.isatty():
        return f"{colour}{text}{_RESET}"
    return text


def _print_summary_table(vulnerabilities: list[dict]) -> None:
    """Print a concise summary table to stdout."""
    if not vulnerabilities:
        print("\n" + _coloured("✓ No vulnerabilities found.", _GREEN))
        return

    print(
        "\n"
        + _coloured("─" * 90, _GREY)
        + "\n"
        + _coloured(
            f"{'CVE ID':<25} {'PACKAGE':<20} {'VERSION':<12} {'SEVERITY':<12} {'CVSS':>5}  {'FIXED IN':<15}",
            _BOLD,
        )
        + "\n"
        + _coloured("─" * 90, _GREY)
    )

    for v in vulnerabilities:
        sev = (v.get("severity") or "UNKNOWN").upper()
        colour = SEVERITY_COLOUR.get(sev, _RESET)
        cve = (v.get("cve_id") or "N/A")[:24]
        pkg = (v.get("package") or "N/A")[:19]
        ver = (v.get("installed_version") or "N/A")[:11]
        fixed = (v.get("fixed_version") or "none")[:14]
        score = v.get("cvss_score")
        score_str = f"{score:.1f}" if score is not None else " N/A"

        print(
            f"{cve:<25} {pkg:<20} {ver:<12} "
            + _coloured(f"{sev:<12}", colour)
            + f" {score_str:>5}  {fixed:<15}"
        )

    print(_coloured("─" * 90, _GREY))


def _print_severity_summary(severity_summary: dict) -> None:
    """Print a severity breakdown."""
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"]
    print("\nSeverity breakdown:")
    for sev in order:
        count = severity_summary.get(sev, 0)
        if count:
            colour = SEVERITY_COLOUR.get(sev, _RESET)
            print(f"  {_coloured(f'{sev:<12}', colour)} {count}")


# ---------------------------------------------------------------------------
# Core workflow
# ---------------------------------------------------------------------------

def run(sbom_path: Path, output_path: Path) -> int:
    """
    Execute the full scan workflow.

    Returns
    -------
    int
        Exit code: 0 = success, 1 = error.
    """
    print(f"\n{'='*60}")
    print("  Vulnerability Detection / CVE Intelligence Module")
    print(f"{'='*60}\n")
    print(f"[INFO] SBOM input : {sbom_path}")
    print(f"[INFO] Output     : {output_path}\n")

    # --- Step 1: Run Grype ---
    try:
        grype_json = run_grype_scan(sbom_path)
    except GrypeNotInstalledError as e:
        print(f"\n{e}", file=sys.stderr)
        print(
            "\nQuick install guide:\n"
            "  Linux/Mac : curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin\n"
            "  Windows   : scoop install grype   OR   choco install grype\n"
            "  All platforms: https://github.com/anchore/grype/releases",
            file=sys.stderr,
        )
        return 1
    except InvalidSBOMError as e:
        print(f"\n{e}", file=sys.stderr)
        return 1
    except GrypeScanError as e:
        print(f"\n{e}", file=sys.stderr)
        return 1

    # --- Step 2: Parse Grype output ---
    try:
        result = parse_grype_output(grype_json)
    except ValueError as e:
        print(f"\n{e}", file=sys.stderr)
        return 1

    # --- Step 3: Write output file ---
    print("[INFO] Saving results...")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"[INFO] Output saved successfully: {output_path}")

    # --- Step 4: Print summary ---
    vulnerabilities = result.get("vulnerabilities", [])
    metadata = result.get("metadata", {})

    _print_summary_table(vulnerabilities)
    _print_severity_summary(metadata.get("severity_summary", {}))

    total = metadata.get("total_vulnerabilities", 0)
    print(f"\n[INFO] Total vulnerabilities : {total}")
    print(f"[INFO] Scan timestamp        : {metadata.get('scan_timestamp')}")
    print(f"[INFO] Grype version         : {metadata.get('grype_version')}")
    print(f"\n[SUCCESS] Results written to: {output_path}\n")

    return 0



# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Vulnerability Detection / CVE Intelligence Module\n"
            "Runs Grype on a CycloneDX SBOM and outputs a clean vulnerabilities.json."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python src/run_scan.py\n"
            "  python src/run_scan.py --sbom input/my_sbom.json\n"
            "  python src/run_scan.py --sbom input/real_sbom.json --output output/results.json\n"
        ),
    )
    parser.add_argument(
        "--sbom",
        type=Path,
        default=DEFAULT_SBOM,
        metavar="PATH",
        help=f"Path to CycloneDX SBOM JSON file (default: {DEFAULT_SBOM})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        metavar="PATH",
        help=f"Path for output vulnerabilities.json (default: {DEFAULT_OUTPUT})",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    sys.exit(run(args.sbom, args.output))