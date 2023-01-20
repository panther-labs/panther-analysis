from panther_duo_helpers import (
    deserialize_administrator_log_event_description,
    duo_alert_context,
)


def rule(event):
    if event.get("action") == "user_update":
        description = deserialize_administrator_log_event_description(event)
        if "status" in description:
            return description.get("status") == "Bypass"
    return False


def title(event):
    return (
        f"Duo: [{event.get('username', '<username_not_found>')}] "
        f"updated account [{event.get('object', '<object_not_found>')}] "
        "to not require two-factor authentication."
    )


def alert_context(event):
    return duo_alert_context(event)
