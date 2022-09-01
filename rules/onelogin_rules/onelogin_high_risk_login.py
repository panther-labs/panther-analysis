import time

from panther_oss_helpers import (
    get_counter,
    increment_counter,
    reset_counter,
    set_key_expiration,
)

THRESH_TTL = 600


def rule(event):

    # Filter events down to successful and failed login events
    if not event.get("user_id") or event.get("event_type_id") not in [5, 6]:
        return False

    event_key = get_key(event)
    # check risk associated with this event
    if event.get("risk_score", 0) > 50:
        # a failed authentication attempt with high risk score
        if event.get("event_type_id") == 6:
            # update a counter for this user's failed login attempts with a high risk score
            increment_counter(event_key)
            set_key_expiration(event_key, time.time() + THRESH_TTL)

    # Trigger alert if this user recently
    # failed a high risk login
    if event.get("event_type_id") == 5:
        if get_counter(event_key) > 0:
            reset_counter(event_key)
            return True
    return False


def get_key(event):
    return __name__ + ":" + event.get("user_name", "<UNKNOWN_USER>")


def title(event):
    return (
        f"A user [{event.get('user_name', '<UNKNOWN_USER>')}] successfully logged in "
        f"after a failed high risk login event"
    )
