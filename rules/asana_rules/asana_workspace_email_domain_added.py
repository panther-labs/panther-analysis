from panther_base_helpers import deep_get


def rule(event):
    return event.get("event_type") == "workspace_associated_email_domain_added"


def title(event):
    workspace = deep_get(event, "resource", "name", default="<WORKSPACE_NOT_FOUND>")
    domain = deep_get(event, "details", "new_value", default="<DOMAIN_NOT_FOUND>")
    actor = deep_get(event, "actor", "email", default="<ACTOR_NOT_FOUND>")
    return f"Asana new email domain [{domain}] added to Workspace [{workspace}] " f"by [{actor}]."
