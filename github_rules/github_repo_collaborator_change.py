def rule(event):
    return event.get("action") == "repo.add_member" or event.get("action") == "repo.remove_member"


def title(event):
    repo_link = f"https://github.com/{event.get('repo','<UNKNOWN_REPO>')}/settings/access"
    action = "added to"
    if event.get("action") == "repo.remove_member":
        action = "removed from"
    return (
        f"Repository  collaborator [{event.get('user', '<UNKNOWN_USER>')}] {action} "
        f"repository {event.get('repo', '<UNKNOWN_REPO>')}. "
        f"View current collaborators here: {repo_link}"
    )


def severity(event):
    if event.get("action") == "repo.remove_member":
        return "INFO"
    return "MEDIUM"
