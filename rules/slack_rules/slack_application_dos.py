from datetime import datetime, timedelta
from json import dumps

from panther_base_helpers import deep_get, slack_alert_context
from panther_oss_helpers import get_string_set, put_string_set, set_key_expiration

DENIAL_OF_SERVICE_ACTIONS = [
    "bulk_session_reset_by_admin",
    "user_session_invalidated",
    "user_session_reset_by_admin",
]


def rule(event):
    # Only evaluate actions that could be used for a DoS
    if event.get("action") not in DENIAL_OF_SERVICE_ACTIONS:
        return False

    # Generate a unique cache key for each user
    user_key = gen_key(event)

    # Retrieve prior entries from the cache, if any
    last_reset = get_string_set(user_key)

    # Store the reset info for future use
    store_reset_info(user_key, event)

    # If this is the first reset for the user, don't alert
    if not last_reset:
        return False

    return True


def alert_context(event):
    return slack_alert_context(event)


def gen_key(event):
    return f"Slack.AuditLogs.ApplicationDoS{deep_get(event, 'entity', 'user', 'name')}"


def store_reset_info(key, event):
    # Map the user to the most recent reset
    put_string_set(
        key,
        [
            dumps(
                {
                    "time": event.get("p_event_time"),
                }
            )
        ],
    )
    # Expire the entry after 24 hours
    set_key_expiration(key, int((datetime.now() + timedelta(days=1)).timestamp()))
