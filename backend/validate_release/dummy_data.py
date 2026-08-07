from pathlib import Path

REPO_PATH = Path("demo_repo")

DUMMY_PATCH = {
    "patch_id": "PATCH-001",
    "branch_name": "fix/PATCH-001",
    "commit_message": "Upgrade vulnerable dependency",
    "title": "Fix vulnerable dependency",
    "body": "Automatic security patch"
}