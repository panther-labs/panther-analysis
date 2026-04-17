def rule(event):
    return event.get("event_type") == "workspace_form_link_authentication_required_disabled"


def title(event):
    workspace = event.deep_get("resource", "name", default="<WORKSPACE_NOT_FOUND>")
    actor = event.deep_get("actor", "email", default="<ACTOR_NOT_FOUND>")
    return (
        f"Asana Workspace [{workspace}] Form Link Auth Requirement " f" was disabled by [{actor}]."
    )
