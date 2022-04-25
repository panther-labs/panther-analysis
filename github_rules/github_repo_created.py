def rule(event):
    return event.get("action") == "repo.create"


def title(event):
    return f"Repository [{event.get('repo', '<UNKNOWN_REPO>')}] created."
