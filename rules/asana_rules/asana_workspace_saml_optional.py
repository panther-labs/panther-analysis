def rule(event):
    old_val = event.deep_get("details", "old_value", default="<OLD_VAL_NOT_FOUND>")
    new_val = event.deep_get("details", "new_value", default="<NEW_VAL_NOT_FOUND>")
    return all(
        [
            event.get("event_type", "<NO_EVENT_TYPE_FOUND>") == "workspace_saml_settings_changed",
            old_val == "required",
            new_val == "optional",
        ]
    )


def title(event):
    actor_email = event.deep_get("actor", "email", default="<ACTOR_NOT_FOUND>")
    return f"Asana user [{actor_email}] made SAML optional for your organization."
