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
    team_name = event.get("team") if "team" in event else "<MISSING_TEAM>"
    return f"GitHub.Audit: [{team_name}] has been modified"
