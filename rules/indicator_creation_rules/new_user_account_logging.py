from datetime import timedelta

import panther_event_type_helpers as event_type
from panther_detection_helpers.caching import put_string_set
from panther_oss_helpers import resolve_timestamp_string

# Days an account is considered new
TTL = timedelta(days=3)


def rule(event):
    if event.udm("event_type") != event_type.USER_ACCOUNT_CREATED:
        return False

    user_event_id = f"new_user_{event.get('p_row_id')}"
    new_user = event.udm("user")
    new_account = event.udm("user_account_id") or "<UNKNOWN_ACCOUNT>"
    event_time = resolve_timestamp_string(event.get("p_event_time"))
    expiry_time = event_time + TTL

    if new_user:
        put_string_set(
            new_user + "-" + str(new_account), [user_event_id], expiry_time.strftime("%s")
        )
    return True


def title(event):
    return f"A new user account was created - [{event.udm('user') or '<UNKNOWN_USER>'}]"
