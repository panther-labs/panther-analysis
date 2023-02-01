from panther_base_helpers import deep_get


def rule(event):
    return event.get("event_type") == "workspace_form_link_authentication_required_disabled"


def title(event):
    workspace = deep_get(event, "resource", "name", default="<WORKSPACE_NOT_FOUND>")
    actor = deep_get(event, "actor", "email", default="<ACTOR_NOT_FOUND>")
    return (
        f"Asana Workspace [{workspace}] Form Link Auth Requirement " f" was disabled by [{actor}]."
    )
