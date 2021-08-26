'''
Monitors for account creation and adds an entry to the KVStore for the user. This depends on the
event_type of ACCOUNT_CREATED to be in the data model for the log source and will work in tandem
with a helper function that checks for the the userid in the KV store.
'''
from datetime import (
    datetime,
    timedelta,
)
from panther_oss_helpers import (
    put_string_set,
    set_key_expiration,
)

# Days an account is considered new
TTL = timedelta(days=3)
PANTHER_TIME_FORMAT = "%Y-%m-%d %H:%M:%S.%f"


def rule(event):

    if event.udm("event_type") != event_type.ACCOUNT_CREATED:
        return False

    event_id = f'new_user_{event.get("p_row_id")}'
    new_user = event.get("user_name")
    event_time = datetime.strptime(event.get("p_event_time"), PANTHER_TIME_FORMAT)
    expiry_time = event_time + TTL

    put_string_set(new_user, event_id)

    set_key_expiration(keyid, expiry_time.strftime("%s"))
    return True

def severity(_):
    return "INFO"

def title():
    return f"A new user account was created - (event.get(user_name))"

