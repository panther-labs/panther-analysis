from global_filter_github import filter_include_event


def rule(event):
    if not filter_include_event(event):
        return False
    return event.get("action") == "repo.create"


def title(event):
    return f"Repository [{event.get('repo', '<UNKNOWN_REPO>')}] created."
