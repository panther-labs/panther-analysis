def rule(event):
    if event.deep_get("action", default="") in [
        "org.remove_outside_collaborator",
        "project.update_user_permission",
    ]:
        return True
    return False
