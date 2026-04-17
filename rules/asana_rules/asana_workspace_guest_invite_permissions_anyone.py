def rule(event):
    return (
        event.get("event_type") == "workspace_guest_invite_permissions_changed"
        and event.deep_get("details", "new_value") == "anyone"
    )


def title(event):
    workspace = event.deep_get("resource", "name", default="<WORKSPACE_NOT_FOUND>")
    actor = event.deep_get("actor", "email", default="<ACTOR_NOT_FOUND>")
    return (
        f"Asana Workspace [{workspace}] guest invite permissions "
        f"changed to anyone by [{actor}]."
    )
