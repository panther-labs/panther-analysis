from panther_base_helpers import deep_get


def rule(event):
    new_val = deep_get(event, "details", "new_value", default="<NEW_VAL_NOT_FOUND>")
    return all(
        [
            event.get("event_type", "<NO_EVENT_TYPE_FOUND>")
            == "workspace_password_requirements_changed",
            new_val == "simple",
        ]
    )


def title(event):
    actor_email = deep_get(event, "actor", "email", default="<ACTOR_NOT_FOUND>")
    new_value = deep_get(event, "details", "new_value", default="<NEW_VAL_NOT_FOUND>")
    old_value = deep_get(event, "details", "old_value", default="<OLD_VAL_NOT_FOUND>")
    return (
        f"Asana user [{actor_email}] changed your organization's password requirements "
        f"from [{old_value}] to [{new_value}]."
    )
