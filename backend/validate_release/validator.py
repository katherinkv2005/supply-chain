from pathlib import Path


def apply_patch(repo_path: Path):
    """
    Dummy patch application.

    Later this can use:
    git apply patch.diff
    """

    req = repo_path / "requirements.txt"

    if not req.exists():
        return False

    text = req.read_text()

    text = text.replace(
        "flask==2.2.2",
        "flask==2.3.3"
    )

    req.write_text(text)

    print("Patch Applied")

    return True
    