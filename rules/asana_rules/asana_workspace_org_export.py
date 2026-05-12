def rule(event):
    return event.get("event_type", "<NO_EVENT_TYPE_FOUND>") == "workspace_export_started"


def title(event):
    actor_email = event.deep_get("actor", "email", default="<ACTOR_NOT_FOUND>")
    context_type = event.deep_get("context", "context_type", default="<CONTEXT_TYPE_NOT_FOUND>")
    return f"Asana user [{actor_email}] started a [{context_type}] export for your organization."
