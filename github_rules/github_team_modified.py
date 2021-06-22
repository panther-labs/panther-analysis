from panther_base_helpers import deep_get


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
    action_mappings = {
        "create": "created team",
        "destroy": "deleted team",
        "add_member": f"added member [{event.get('user')}] to team",
        "remove_member": f"removed member [{event.get('user')}] from team",
        "add_repository": f"added repository [{event.get('repo')}] to team",
        "removed_repository": f"removed repository [{event.get('repo')}] from team",
        "change_parent_team": "changed parent team for team"
    }
    action_key = event.get("action").split(".")[1]
    action = action_mappings.get(action_key, event.get("action"))
    return (
        f"GitHub.Audit: User [{event.udm('actor_user')}] {action} "
        f"[{deep_get(event, 'data', 'team')}]"
    )
