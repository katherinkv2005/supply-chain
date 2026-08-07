from github import Github
from git import Repo


def create_pr(
    token,
    repo_name,
    repo_path,
    branch,
    title,
    body
):

    repo = Repo(repo_path)

    repo.git.checkout("-b", branch)

    repo.git.add(A=True)

    repo.index.commit(title)

    origin = repo.remote(name="origin")

    origin.push(branch)

    g = Github(token)

    gh_repo = g.get_repo(repo_name)

    pr = gh_repo.create_pull(
        title=title,
        body=body,
        base="main",
        head=branch
    )

    return pr.html_url