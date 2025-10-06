import json

from panther_auth0_helpers import auth0_alert_context, is_auth0_config_event
from panther_detection_helpers.caching import add_to_string_set

# Determine how many push notifications must be sent before triggering an alert.
PUSH_FATIGUE_THRESHOLD = 5

RULE_ID = "Auth0.PushNotification.Fatigue"
WITHIN_TIMEFRAME_MINUTES = 1


def rule(event):

    data_type = event.deep_get("data", "type", default="<NO_DATA_TYPE_FOUND>")
    if data_type != "gd_send_pn":
        return False
    user = event.deep_get(
        "data", "details", "request", "auth", "user", "email", default="<NO_USER_FOUND>"
    )
    key = f"{RULE_ID}-{user}"
    unique_alerts = add_to_string_set(key, WITHIN_TIMEFRAME_MINUTES * 60)

    if isinstance(unique_alerts, str):
        unique_alerts = json.loads(unique_alerts)
    if len(unique_alerts) >= PUSH_FATIGUE_THRESHOLD:
        return all(
            [
                unique_alerts,
                is_auth0_config_event(event),
            ]
        )
    return False


def title(event):
    user = event.deep_get(
        "data", "details", "request", "auth", "user", "email", default="<NO_USER_FOUND>"
    )
    return (
        f"Auth0 User [{user}] has received an excessive number of MFA push notifications,"
        f"possible MFA fatigue detected"
    )


def alert_context(event):
    return auth0_alert_context(event)
