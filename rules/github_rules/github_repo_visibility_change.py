def rule(event):
    return event.get("action") == "repo.access"


def title(event):
    repo_access_link = f"https://github.com/{event.get('repo','<UNKNOWN_REPO>')}/settings/access"
    return (
        f"Repository [{event.get('repo', '<UNKNOWN_REPO>')}] visibility changed. "
        f"View current visibility here: {repo_access_link}"
    )
