from panther_base_helpers import deep_get


def rule(event):
    return (
        event.get("event_type") == "workspace_default_session_duration_changed"
        and deep_get(event, "details", "new_value") == "never"
    )


def title(event):
    workspace = deep_get(event, "resource", "name", default="<WORKSPACE_NOT_FOUND>")
    actor = deep_get(event, "actor", "email", default="<ACTOR_NOT_FOUND>")
    return (
        f"Asana workspace [{workspace}]'s default session duration "
        f"has been set to never expire by [{actor}]."
    )
