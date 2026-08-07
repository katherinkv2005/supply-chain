import os
from pathlib import Path
from github import Github, GithubException
from dotenv import load_dotenv

load_dotenv()

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_REPO = os.environ.get("GITHUB_REPO")

_client = None
_repo = None


def _get_repo():
    global _client, _repo
    if _repo is None:
        if not GITHUB_TOKEN or not GITHUB_REPO:
            raise ValueError("GITHUB_TOKEN and GITHUB_REPO must be set in .env")
        _client = Github(GITHUB_TOKEN)
        _repo = _client.get_repo(GITHUB_REPO)
    return _repo


def create_branch(branch_name):
    repo = _get_repo()
    try:
        base = repo.get_branch(repo.default_branch)
        repo.create_git_ref(ref=f"refs/heads/{branch_name}", sha=base.commit.sha)
        print(f"[GITHUB] Created branch: {branch_name}")
        return {"status": "success", "branch": branch_name}
    except GithubException as e:
        if e.status == 422:
            print(f"[GITHUB] Branch '{branch_name}' already exists — reusing it.")
            return {"status": "success", "branch": branch_name}
        print(f"[GITHUB] Failed to create branch: {e}")
        return {"status": "error", "message": str(e)}


def commit_changes(message, file_path=None, repo_local_path=None, branch_name=None):
    repo = _get_repo()
    try:
        local_file = Path(repo_local_path) / file_path
        new_content = local_file.read_text(encoding="utf-8")

        existing = repo.get_contents(file_path, ref=branch_name)
        repo.update_file(
            path=file_path,
            message=message,
            content=new_content,
            sha=existing.sha,
            branch=branch_name,
        )
        print(f"[GITHUB] Committed change to {file_path} on {branch_name}")
        return {"status": "success", "commit": message}
    except GithubException as e:
        print(f"[GITHUB] Commit failed: {e}")
        return {"status": "error", "message": str(e)}


def push_branch(branch_name):
    print(f"[GITHUB] Branch '{branch_name}' is live on GitHub.")
    return {"status": "success"}


def create_pull_request(branch_name, title, body):
    repo = _get_repo()
    try:
        pr = repo.create_pull(
            title=title,
            body=body,
            head=branch_name,
            base=repo.default_branch,
        )
        print(f"[GITHUB] Pull request created: {pr.html_url}")
        return {"status": "success", "url": pr.html_url}
    except GithubException as e:
        print(f"[GITHUB] PR creation failed: {e}")
        return {"status": "error", "message": str(e)}