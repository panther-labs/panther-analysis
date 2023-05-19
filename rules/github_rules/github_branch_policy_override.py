from global_filter_github import filter_include_event


def rule(event):
    if not filter_include_event(event):
        return False
    return event.get("action") == "protected_branch.policy_override"


def title(event):
    return (
        f"A branch protection requirement in the repository"
        f" [{event.get('repo', '<UNKNOWN_REPO>')}]"
        f" was overridden by user [{event.udm('actor_user')}]"
    )
