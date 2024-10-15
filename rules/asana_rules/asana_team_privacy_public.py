def rule(event):
    return (
        event.get("event_type") == "team_privacy_settings_changed"
        and event.deep_get("details", "new_value") == "public"
    )


def title(event):
    team = event.deep_get("resource", "name", default="<TEAM_NOT_FOUND>")
    actor = event.deep_get("actor", "email", default="<ACTOR_NOT_FOUND>")
    return f"Asana team [{team}] has been made public to the org by [{actor}]."
