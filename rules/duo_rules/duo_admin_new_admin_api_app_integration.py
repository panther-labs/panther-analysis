from panther_duo_helpers import (
    deserialize_administrator_log_event_description,
    duo_alert_context,
)


def rule(event):
    if event.get("action") == "integration_create":
        description = deserialize_administrator_log_event_description(event)
        integration_type = description.get("type")
        return integration_type == "Admin API"
    return False


def title(event):
    return (
        f"Duo: [{event.get('username', '<username_not_found>')}] "
        "created a new Admin API integration "
        f"to [{event.get('object', '<object_not_found>')}]"
    )


def alert_context(event):
    return duo_alert_context(event)
