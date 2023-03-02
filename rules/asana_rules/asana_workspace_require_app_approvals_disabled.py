from panther_base_helpers import deep_get


def rule(event):
    new_val = deep_get(event, "details", "new_value", default="<NEW_VAL_NOT_FOUND>")
    return all(
        [
            event.get("event_type", "<NO_EVENT_TYPE_FOUND>")
            == "workspace_require_app_approvals_of_type_changed",
            new_val == "off",
        ]
    )


def title(event):
    actor_email = deep_get(event, "actor", "email", default="<ACTOR_NOT_FOUND>")
    context = deep_get(event, "context", "context_type", default="<APP_CONTEXT_NOT_FOUND>")
    return (
        f"Asana user [{actor_email}] disabled application approval requirements "
        f"for [{context}] type applications."
    )
