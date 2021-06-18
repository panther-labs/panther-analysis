def rule(event):
    if not event.get("action").startswith("team"):
        return False
    return (
        event.get("action") == "team.add_member"
        or event.get("action") == "team.add_repository"
        or event.get("action") == "team.change_parent_team"
        or event.get("action") == "team.create"
        or event.get("action") == "team.destroy"
        or event.get("action") == "team.remove_member"
        or event.get("action") == "team.remove_repository"
    )


def title(event):
    action = event.get("action")
    if action.endswith(".create"):
        action = "created team"
    elif action.endswith(".destroy"):
        action = "deleted team"
    elif action.endswith(".add_member"):
        action = f"added member {event.get('user')} to team"
    elif action.endswith(".remove_member"):
        action = f"removed member {event.get('user')} from team"
    elif action.endswith(".add_repository"):
        action = f"added repository {event.get('repo')} to team"
    elif action.endswith(".remove_repository"):
        action = f"removed repository {event.get('repo')} from team"
    elif action.endswith(".change_parent_team"):
        action = "changed parent team for team"
    return (
        f"GitHub.Audit: User [{event.udm('actor_user')}] {action} "
        f"[{event.get('data', {}).get('team', '<UNKNOWN_TEAM>')}]"
    )
