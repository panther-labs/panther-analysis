def rule(event):
    return event.get("event_type") == "workspace_associated_email_domain_added"


def title(event):
    workspace = event.deep_get("resource", "name", default="<WORKSPACE_NOT_FOUND>")
    domain = event.deep_get("details", "new_value", default="<DOMAIN_NOT_FOUND>")
    actor = event.deep_get("actor", "email", default="<ACTOR_NOT_FOUND>")
    return f"Asana new email domain [{domain}] added to Workspace [{workspace}] by [{actor}]."
