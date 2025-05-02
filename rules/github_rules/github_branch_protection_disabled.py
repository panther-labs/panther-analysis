from global_filter_github import filter_include_event


def rule(event):
    if not filter_include_event(event):
        return False
    return event.get("action") == "protected_branch.destroy"


def title(event):
    return (
        f"A branch protection was removed from the repository [{event.get('repo', '<UNKNOWN_REPO>')}] by [{event.get('actor', '<UNKNOWN_ACTOR>')}]"
    )
