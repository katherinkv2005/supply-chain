"""
Resumable Python downloader + Grype local importer for Anchore Grype v6 vulnerability database.
1. Downloads the latest v6 database archive (.tar.zst) over IPv4 with HTTP Range resuming.
2. Calls `grype db import <archive.tar.zst>` locally (zero network calls in Grype).
"""
import json
import os
import shutil
import socket
import sys
import time
import urllib.request
import subprocess
from pathlib import Path

# Force IPv4 DNS resolution globally in Python
_orig_getaddrinfo = socket.getaddrinfo
def _getaddrinfo_ipv4(host, port, family=0, type=0, proto=0, flags=0):
    return _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
socket.getaddrinfo = _getaddrinfo_ipv4

def download_and_import_db():
    print("[INFO] Fetching Grype v6 database metadata (IPv4 forced)...", flush=True)
    url = "https://grype.anchore.io/databases/v6/latest.json"
    req = urllib.request.Request(url, headers={"User-Agent": "grype/0.116.1"})
    
    with urllib.request.urlopen(req, timeout=30) as resp:
        meta = json.loads(resp.read().decode("utf-8"))
        
    db_filename = meta["path"]
    built = meta.get("built", "unknown")
    tar_url = f"https://grype.anchore.io/databases/v6/{db_filename}"
    
    print(f"[INFO] Found schema v6 DB built on {built}", flush=True)
    print(f"[INFO] Download URL: {tar_url}", flush=True)
    
    local_app_data = os.environ.get("LOCALAPPDATA", r"C:\Users\Sidharth s\AppData\Local")
    temp_dir = Path(local_app_data) / "cache" / "grype"
    temp_dir.mkdir(parents=True, exist_ok=True)
    
    # Replace colons for Windows filename compatibility
    safe_filename = db_filename.replace(":", "_")
    temp_archive = temp_dir / safe_filename
    
    # Check total size
    head_req = urllib.request.Request(tar_url, headers={"User-Agent": "grype/0.116.1"}, method="HEAD")
    total_size = 0
    try:
        with urllib.request.urlopen(head_req, timeout=30) as head_resp:
            total_size = int(head_resp.headers.get("Content-Length", 0))
    except Exception:
        pass
        
    print(f"[INFO] Target archive size: {total_size / (1024*1024):.1f} MB", flush=True)

    max_retries = 20
    attempt = 0
    chunk_size = 1024 * 1024
    
    while attempt < max_retries:
        downloaded = temp_archive.stat().st_size if temp_archive.exists() else 0
        if total_size > 0 and downloaded >= total_size:
            print(f"\n[INFO] Download completed! ({downloaded / (1024*1024):.1f} MB)", flush=True)
            break
            
        headers = {"User-Agent": "grype/0.116.1"}
        if downloaded > 0:
            headers["Range"] = f"bytes={downloaded}-"
            print(f"\n[INFO] Resuming download from byte {downloaded} ({downloaded/(1024*1024):.1f} MB)...", flush=True)
        else:
            print("[INFO] Starting database download...", flush=True)

        dl_req = urllib.request.Request(tar_url, headers=headers)
        
        try:
            with urllib.request.urlopen(dl_req, timeout=60) as resp, open(temp_archive, "ab" if downloaded > 0 else "wb") as out_f:
                if total_size == 0 and resp.headers.get("Content-Length"):
                    total_size = int(resp.headers.get("Content-Length")) + downloaded

                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    out_f.write(chunk)
                    out_f.flush()
                    downloaded += len(chunk)
                    
                    if total_size > 0:
                        pct = (downloaded / total_size) * 100
                        mb = downloaded / (1024 * 1024)
                        print(f"\r[INFO] Progress: {mb:.1f} MB / {total_size/(1024*1024):.1f} MB ({pct:.1f}%)", end="", flush=True)

        except (urllib.error.URLError, ConnectionResetError, TimeoutError, OSError) as exc:
            attempt += 1
            print(f"\n[WARNING] Connection interrupted ({exc}). Retrying in 2s (attempt {attempt}/{max_retries})...", flush=True)
            time.sleep(2)

    if not temp_archive.exists() or temp_archive.stat().st_size == 0:
        raise RuntimeError("Download failed completely")

    print("\n[INFO] Archive downloaded. Importing into Grype via `grype db import`...", flush=True)
    
    # Locate grype binary
    grype_bin = shutil.which("grype")
    if not grype_bin:
        winget_path = Path(local_app_data) / "Microsoft" / "WinGet" / "Packages"
        for candidate in winget_path.glob("Anchore.Grype_*"):
            exe = candidate / "grype.exe"
            if exe.exists():
                grype_bin = str(exe)
                break

    if not grype_bin:
        raise RuntimeError("Grype binary not found")

    res = subprocess.run([grype_bin, "db", "import", str(temp_archive)], capture_output=True, text=True)
    print(f"[INFO] `grype db import` exit code: {res.returncode}")
    print(f"[INFO] stdout:\n{res.stdout.strip()}")
    if res.stderr.strip():
        print(f"[INFO] stderr:\n{res.stderr.strip()}")

    if res.returncode == 0:
        print("[SUCCESS] Grype vulnerability database imported successfully!", flush=True)
        if temp_archive.exists():
            temp_archive.unlink()

if __name__ == "__main__":
    download_and_import_db()
