from panther_duo_helpers import deserialize_administrator_log_event_description


def rule(event):
    event_description = deserialize_administrator_log_event_description(event)

    return (
        event.get("action") == "admin_2fa_error"
        and "fraudulent" in event_description.get("error", "").lower()
    )


def title(event):
    event_description = deserialize_administrator_log_event_description(event)
    admin_username = event.get("username", "Unknown")
    user_email = event_description.get("email", "Unknown")

    return f"Duo Admin [{admin_username}] denied due to an anomalous 2FA push for [{user_email}]"


def alert_context(event):
    event_description = deserialize_administrator_log_event_description(event)

    return {
        "reason": event_description.get("error", ""),
        "reporting_admin": event.get("username", ""),
        "user": event_description.get("email", ""),
        "ip_address": event_description.get("ip_address", ""),
    }
