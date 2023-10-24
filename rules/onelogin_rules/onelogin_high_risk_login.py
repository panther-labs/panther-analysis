from datetime import timedelta

from panther_detection_helpers.caching import (
    get_counter,
    increment_counter,
    reset_counter,
)

THRESH_TTL = timedelta(minutes=10).total_seconds()


def rule(event):
    # Filter events down to successful and failed login events
    if not event.get("user_id") or str(event.get("event_type_id")) not in ["5", "6"]:
        return False

    event_key = get_key(event)
    # check risk associated with this event
    if event.get("risk_score", 0) > 50:
        # a failed authentication attempt with high risk score
        if str(event.get("event_type_id")) == "6":
            # update a counter for this user's failed login attempts with a high risk score
            increment_counter(event_key, event.event_time_epoch() + THRESH_TTL)

    # Trigger alert if this user recently
    # failed a high risk login
    if str(event.get("event_type_id")) == "5":
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
