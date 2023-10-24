from panther_base_helpers import deep_get


def rule(event):
    return event.get("event_type", "<NO_EVENT_TYPE_FOUND>") == "workspace_export_started"


def title(event):
    actor_email = deep_get(event, "actor", "email", default="<ACTOR_NOT_FOUND>")
    context_type = deep_get(event, "context", "context_type", default="<CONTEXT_TYPE_NOT_FOUND>")
    return f"Asana user [{actor_email}] started a [{context_type}] export for your organization."
