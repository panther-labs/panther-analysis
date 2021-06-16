def rule(event):
    return event.get("action") == "repo.add_member" or event.get("action") == "repo.remove_member"

def title(event):
    action = "added"
    if event.get("action") == "repo.remove_member":
        action = "removed"
    return (
      f"Repository  collaborator [{event.get('user', '<UNKNOWN_USER>')}] {action}."
    )

def severity(event):
    if event.get("action") == "repo.remove_member":
        return "INFO"
    return "MEDIUM"
