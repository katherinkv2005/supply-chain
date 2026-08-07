"""
grype_scanner.py
----------------
Runs Grype against a CycloneDX SBOM file and returns the raw JSON output.

Responsibility: ONLY detect known CVEs in the dependency list.
This module does NOT:
  - Determine reachability / exploitability  (handled by separate module)
  - Generate patches or modify source code
  - Store results in any database

Integration contract:
  INPUT  → path to a CycloneDX SBOM JSON file
  OUTPUT → raw Grype JSON dict (passed to vulnerability_parser.py)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path


# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------

def _no_update_env() -> dict[str, str]:
    """
    Return a copy of the current environment with GRYPE_DB_AUTO_UPDATE=false.

    Without this, EVERY grype command (including `grype version`) tries to
    check/download the CVE database on startup, causing an indefinite hang
    when the DB is not yet present.

    We only allow auto-update during the explicit `ensure_grype_db()` step.
    """
    env = dict(os.environ)
    env["GRYPE_DB_AUTO_UPDATE"] = "false"
    return env


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class GrypeNotInstalledError(RuntimeError):
    """Raised when Grype binary is not found."""


class GrypeScanError(RuntimeError):
    """Raised when Grype exits with a non-zero return code or times out."""


class InvalidSBOMError(ValueError):
    """Raised when the SBOM file is missing, empty, or not valid JSON."""


# ---------------------------------------------------------------------------
# Locate Grype binary  (PATH first, then WinGet fallback)
# ---------------------------------------------------------------------------

def _find_grype() -> str | None:
    """
    Return the full path to the grype binary, or None if not found.

    Search order:
      1. Standard PATH
      2. WinGet packages dir  (Windows: works before shell restart after winget install)
      3. Other common Windows locations (Scoop, Chocolatey)
    """
    on_path = shutil.which("grype")
    if on_path:
        return on_path

    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if local_app_data:
        winget_base = Path(local_app_data) / "Microsoft" / "WinGet" / "Packages"
        for candidate in winget_base.glob("Anchore.Grype_*"):
            exe = candidate / "grype.exe"
            if exe.exists():
                return str(exe)

    for p in [
        Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "grype" / "grype.exe",
        Path(os.environ.get("USERPROFILE", "")) / "scoop" / "shims" / "grype.exe",
        Path("C:/ProgramData/chocolatey/bin/grype.exe"),
    ]:
        if p.exists():
            return str(p)

    return None


# ---------------------------------------------------------------------------
# Internal helper: run a subprocess and stream stderr to console
# ---------------------------------------------------------------------------

def _run_with_streaming_stderr(
    cmd: list[str],
    timeout: int = 900,
    label: str = "Grype",
    extra_env: dict[str, str] | None = None,
) -> tuple[int, str, list[str]]:
    """
    Run *cmd*, stream stderr lines to stdout in real-time, and return
    (returncode, stdout_text, stderr_lines).

    Streaming stderr is critical because:
    - Grype prints CVE DB download progress to stderr
    - Without streaming, the terminal appears to hang with no feedback
    """
    env = dict(os.environ)
    env["GODEBUG"] = "netdns=go"
    if extra_env:
        env.update(extra_env)

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
    )


    stderr_lines: list[str] = []
    stdout_chunks: list[str] = []

    def _drain_stderr() -> None:
        """Read stderr line-by-line and echo to terminal."""
        if process.stderr is not None:
            for raw_line in process.stderr:
                line = raw_line.rstrip()
                if line:
                    print(f"[{label}] {line}", flush=True)
                    stderr_lines.append(line)
            try:
                process.stderr.close()
            except Exception:
                pass

    def _drain_stdout() -> None:
        """Read all of stdout on its own thread (do NOT do this on the main
        thread — a blocking read() there would defeat process.wait(timeout=...)
        below if Grype stalls before closing stdout)."""
        if process.stdout is not None:
            try:
                stdout_chunks.append(process.stdout.read())
            except Exception:
                pass
            try:
                process.stdout.close()
            except Exception:
                pass

    stderr_thread = threading.Thread(target=_drain_stderr, daemon=True)
    stdout_thread = threading.Thread(target=_drain_stdout, daemon=True)
    stderr_thread.start()
    stdout_thread.start()

    try:
        # This is now the ONLY blocking call on the main thread, so the
        # timeout is actually enforced regardless of which pipe stalls.
        process.wait(timeout=timeout)

    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=5)
        except Exception:
            pass
        stderr_thread.join(timeout=3)
        stdout_thread.join(timeout=3)
        raise GrypeScanError(
            f"[ERROR] Grype scan timed out after {timeout // 60} minutes.\n"
            "This usually means the CVE database is still downloading.\n"
            "Run:  grype db update\n"
            "Then retry."
        )
    finally:
        stderr_thread.join(timeout=5)
        stdout_thread.join(timeout=5)

    stdout_data = "".join(stdout_chunks)
    return process.returncode, stdout_data, stderr_lines



# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_grype_installed() -> tuple[str, str]:
    """
    Verify that Grype is available.

    Returns
    -------
    tuple[str, str]
        (full path to grype binary, version string)

    Raises
    ------
    GrypeNotInstalledError
    """
    grype_path = _find_grype()
    if grype_path is None:
        raise GrypeNotInstalledError(
            "[ERROR] Grype is not installed or not on PATH.\n"
            "Install options:\n"
            "  Windows : winget install Anchore.Grype\n"
            "  Linux/Mac: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin\n"
            "  All platforms: https://github.com/anchore/grype/releases"
        )

    result = subprocess.run(
        [grype_path, "version"],
        capture_output=True,
        text=True,
        timeout=30,
        env=_no_update_env(),   # prevent DB download hang on version check
    )
    if result.returncode != 0:
        raise GrypeNotInstalledError(
            f"[ERROR] `grype version` failed:\n{result.stderr.strip()}"
        )

    version_line = next(
        (line for line in result.stdout.splitlines() if line.strip()),
        "unknown version",
    )
    return grype_path, version_line


def _download_db_direct() -> bool:
    """Fallback direct Python HTTP downloader for Anchore Grype DB archive."""
    import tarfile
    import urllib.request

    try:
        print("[INFO] Trying direct HTTP database download...", flush=True)
        url = "https://toolbox-data.anchore.io/grype/databases/listing.json"
        req = urllib.request.Request(url, headers={"User-Agent": "grype/0.116.1"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            listing = json.loads(resp.read().decode("utf-8"))

        db_entry = None
        schema_ver = None
        for s in ["5", "4", "3"]:
            if s in listing.get("available", {}):
                db_entry = listing["available"][s][0]
                schema_ver = s
                break

        if not db_entry or not schema_ver:
            return False

        tar_url = db_entry["url"]
        local_app_data = os.environ.get("LOCALAPPDATA", "")
        if not local_app_data:
            return False

        target_dirs = [
            Path(local_app_data) / "cache" / "grype" / "db" / schema_ver,
            Path(local_app_data) / "grype" / "db" / schema_ver,
        ]

        temp_tar = Path(local_app_data) / "cache" / "grype" / "temp_db.tar.gz"
        temp_tar.parent.mkdir(parents=True, exist_ok=True)

        dl_req = urllib.request.Request(tar_url, headers={"User-Agent": "grype/0.116.1"})
        with urllib.request.urlopen(dl_req, timeout=600) as resp, open(temp_tar, "wb") as out_f:
            total_size = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            chunk_size = 1024 * 1024
            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                out_f.write(chunk)
                downloaded += len(chunk)
                if total_size > 0:
                    pct = (downloaded / total_size) * 100
                    mb = downloaded / (1024 * 1024)
                    print(f"\r[INFO] Direct Download: {mb:.1f} MB / {total_size/(1024*1024):.1f} MB ({pct:.1f}%)", end="", flush=True)

        print("\n[INFO] Extracting database archive...", flush=True)
        for target_dir in target_dirs:
            target_dir.mkdir(parents=True, exist_ok=True)
            with tarfile.open(temp_tar, "r:gz") as tar:
                tar.extractall(path=target_dir)

        if temp_tar.exists():
            temp_tar.unlink()

        return True
    except Exception as exc:
        print(f"\n[WARNING] Direct HTTP database download failed: {exc}", flush=True)
        return False


def ensure_grype_db(grype_path: str, max_retries: int = 3) -> None:
    """
    Check if the Grype CVE database exists. If not, download it now
    with real-time progress shown in the terminal and automatic retries.

    Raises
    ------
    GrypeScanError
        If all database download attempts fail.
    """
    # Quick DB status check — use no-update env so it returns instantly
    status_result = subprocess.run(
        [grype_path, "db", "status"],
        capture_output=True,
        text=True,
        timeout=15,
        env=_no_update_env(),
    )

    db_ok = (
        status_result.returncode == 0
        and "invalid" not in status_result.stdout.lower()
        and "does not exist" not in status_result.stderr.lower()
    )
    if db_ok:
        print("[INFO] Grype CVE database is present and valid.", flush=True)
        return

    print("[INFO] Grype CVE database not found or invalid. Downloading now...", flush=True)
    print("[INFO] This is a one-time download (~200 MB). Please wait...", flush=True)

    last_error_lines: list[str] = []
    for attempt in range(1, max_retries + 1):
        if attempt > 1:
            print(f"[INFO] Retrying CVE database download (attempt {attempt}/{max_retries})...", flush=True)

        returncode, _, stderr_lines = _run_with_streaming_stderr(
            [grype_path, "-v", "db", "update"],
            timeout=900,
            label="GRYPE-DB",
        )

        if returncode == 0:
            print("[INFO] Grype CVE database downloaded successfully.", flush=True)
            return

        last_error_lines = stderr_lines

    # If grype db update command failed, attempt direct HTTP download fallback
    if _download_db_direct():
        print("[INFO] Grype CVE database installed via direct HTTP fallback.", flush=True)
        return

    raise GrypeScanError(
        f"[ERROR] Grype DB download failed after {max_retries} attempts.\n"
        + "\n".join(last_error_lines[-10:])
    )




def validate_sbom(sbom_path: Path) -> dict:
    """
    Load and minimally validate a CycloneDX SBOM JSON file.

    Raises
    ------
    InvalidSBOMError
        If the file is missing, empty, or not valid JSON.
    """
    sbom_path = Path(sbom_path)

    if not sbom_path.exists():
        raise InvalidSBOMError(
            f"[ERROR] SBOM file not found: {sbom_path}\n"
            "Provide a valid CycloneDX JSON file."
        )

    if sbom_path.stat().st_size == 0:
        raise InvalidSBOMError(f"[ERROR] SBOM file is empty: {sbom_path}")

    try:
        sbom_data = json.loads(sbom_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InvalidSBOMError(
            f"[ERROR] SBOM file is not valid JSON: {sbom_path}\nDetail: {exc}"
        ) from exc

    if "components" not in sbom_data and "dependencies" not in sbom_data:
        raise InvalidSBOMError(
            f"[ERROR] SBOM does not contain 'components' or 'dependencies'.\n"
            f"File: {sbom_path}\nExpected CycloneDX 1.4 JSON format."
        )

    components = sbom_data.get("components", sbom_data.get("dependencies", []))
    if not components:
        print(
            "[WARNING] SBOM contains zero components. "
            "Grype will run but will likely find no vulnerabilities.",
            file=sys.stderr,
        )

    return sbom_data


def run_grype_scan(sbom_path: Path) -> dict:
    """
    Execute Grype against a CycloneDX SBOM and return parsed JSON output.

    Steps:
      1. Locate and verify Grype binary
      2. Validate the SBOM file
      3. Ensure the CVE database is present (download if missing)
      4. Run Grype, streaming stderr to the terminal
      5. Parse and return JSON output

    Parameters
    ----------
    sbom_path : Path
        Path to the CycloneDX SBOM JSON file.

    Returns
    -------
    dict
        Parsed Grype JSON output.

    Raises
    ------
    GrypeNotInstalledError, InvalidSBOMError, GrypeScanError
    """
    sbom_path = Path(sbom_path).resolve()

    # Step 1: Find Grype
    grype_bin, version = check_grype_installed()
    print(f"[INFO] Grype found: {version.strip()}")
    print(f"[INFO] Grype binary: {grype_bin}")

    # Step 2: Validate SBOM
    validate_sbom(sbom_path)
    print(f"[INFO] SBOM validated: {sbom_path}")

    # Step 3: Ensure DB exists (download if needed, with live progress)
    ensure_grype_db(grype_bin)

    # Step 4: Run Grype scan
    # Note: NO --quiet flag so stderr (progress, warnings) streams to terminal
    grype_cmd = [grype_bin, f"sbom:{sbom_path}", "-o", "json"]
    print(f"[INFO] Command: {' '.join(str(c) for c in grype_cmd)}")
    print("[INFO] Starting Grype scan...")
    print("[INFO] Waiting for Grype...")

    returncode, stdout_data, stderr_lines = _run_with_streaming_stderr(
        grype_cmd,
        timeout=900,
        label="GRYPE",
        extra_env=_no_update_env(),  # DB already ensured above; prevent re-check hang
    )

    print(f"[INFO] Grype return code: {returncode}")

    if returncode != 0:
        stderr_snippet = "\n".join(stderr_lines[-20:])
        raise GrypeScanError(
            f"[ERROR] Grype scan failed\n"
            f"[ERROR] Return code: {returncode}\n"
            f"[ERROR] stderr:\n{stderr_snippet}\n"
            "Common causes:\n"
            "  • CVE DB corrupted → run: grype db update\n"
            "  • Network issue during DB fetch\n"
            "  • SBOM format not supported by this Grype version"
        )

    print("[INFO] Grype scan completed")

    # Step 5: Parse JSON
    stdout_data = stdout_data.strip()
    if not stdout_data:
        raise GrypeScanError(
            "[ERROR] Grype produced no stdout output.\n"
            f"Stderr had {len(stderr_lines)} line(s):\n"
            + "\n".join(stderr_lines[-10:])
        )

    try:
        grype_json = json.loads(stdout_data)
    except json.JSONDecodeError as exc:
        raise GrypeScanError(
            f"[ERROR] Grype output is not valid JSON: {exc}\n"
            f"stdout (first 500 chars): {stdout_data[:500]}"
        ) from exc

    match_count = len(grype_json.get("matches", []))
    print(f"[INFO] Vulnerabilities found: {match_count}")

    return grype_json


# ---------------------------------------------------------------------------
# CLI convenience — run scanner standalone
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Run Grype scan on a CycloneDX SBOM and print raw JSON."
    )
    parser.add_argument(
        "sbom_path",
        nargs="?",
        default=str(Path(__file__).parent.parent / "input" / "sample_sbom.json"),
        help="Path to CycloneDX SBOM JSON (default: input/sample_sbom.json)",
    )
    args = parser.parse_args()

    try:
        result = run_grype_scan(Path(args.sbom_path))
        print(json.dumps(result, indent=2))
    except (GrypeNotInstalledError, InvalidSBOMError, GrypeScanError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)