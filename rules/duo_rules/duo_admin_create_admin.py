from panther_duo_helpers import deserialize_administrator_log_event_description, duo_alert_context


def rule(event):
    return event.get("action") == "admin_create"


def title(event):
    event_description = deserialize_administrator_log_event_description(event)
    return (
        f"Duo: [{event.get('username', '<username_not_found>')}] "
        "created a new admin account: "
        f"[{event_description.get('name', '<name_not_found>')}] "
        f"[{event_description.get('email', '<email_not_found>')}]."
    )


def alert_context(event):
    return duo_alert_context(event)
