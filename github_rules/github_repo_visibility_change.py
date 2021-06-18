def rule(event):
    if event.get("action") == "repo.access":
        # TODO: find out what the new access it
        return True
    return False


def title(event):
    repo_access_link = f"https://github.com/{event.get('repo','<UNKNOWN_REPO>')}/settings/access"
    return (
        f"Repository [{event.get('repo', '<UNKNOWN_REPO>')}] visibility changed. "
        f"View current visibility here: {repo_access_link}"
    )
