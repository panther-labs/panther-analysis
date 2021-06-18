def rule(event):
    return event.get("action") == "protected_branch.policy_override"


def title(event):
    return (
        f"A branch protection requirement in the repository [{event.get('repo', '<UNKNOWN_REPO>')}] "
        f"was overridden by user [{event.udm('actor_user')}]"
    )
