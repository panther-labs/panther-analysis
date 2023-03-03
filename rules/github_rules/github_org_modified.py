from global_filter_github import filter_include_event

def rule(event):
    if not filter_include_event(event):
        return False
    return event.get("action") == "org.add_member" or event.get("action") == "org.remove_member"


def title(event):
    action = event.get("action")
    if event.get("action") == "org.add_member":
        action = "added"
    elif event.get("action") == "org.remove_member":
        action = "removed"
    return (
        f"GitHub.Audit: User [{event.udm('actor_user')}] {action} "
        f"{event.get('user', '<UNKNOWN_USER>')} to org [{event.get('org','<UNKNOWN_ORG>')}]"
    )
