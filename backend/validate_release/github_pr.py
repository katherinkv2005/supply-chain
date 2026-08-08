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
        # If a PR already exists for this branch, fetch and return it
        # instead of failing -- this makes repeated runs idempotent.
        if e.status == 422:
            existing = repo.get_pulls(state="open", head=f"{repo.owner.login}:{branch_name}")
            for p in existing:
                print(f"[GITHUB] PR already exists, reusing: {p.html_url}")
                return {"status": "success", "url": p.html_url}
        print(f"[GITHUB] PR creation failed: {e}")
        return {"status": "error", "message": str(e)}