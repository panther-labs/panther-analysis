def rule(event):
    return event.get("action").startswith("hook.")


def title(event):
    action = "modified"
    if event.get("action").endswith("destroy"):
        action = "deleted"
    elif event.get("action").endswith("create"):
        action = "created"
    return f"web hook {action} in repository [{event.get('repo','<UNKNOWN_REPO>')}]"


def severity(event):
    if event.get("action").endswith("create"):
        return "MEDIUM"
    return "INFO"
