from panther_base_helpers import deep_get


def rule(event):
    return (
        event.get("event_type") == "workspace_guest_invite_permissions_changed"
        and deep_get(event, "details", "new_value") == "anyone"
    )


def title(event):
    workspace = deep_get(event, "resource", "name", default="<WORKSPACE_NOT_FOUND>")
    actor = deep_get(event, "actor", "email", default="<ACTOR_NOT_FOUND>")
    return (
        f"Asana Workspace [{workspace}] guest invite permissions "
        f"changed to anyone by [{actor}]."
    )
