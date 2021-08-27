from datetime import (
    datetime,
    timedelta,
)
from panther_oss_helpers import (
    put_string_set,
    set_key_expiration,
)
import panther_event_type_helpers as event_type

# Days an account is considered new
TTL = timedelta(days=3)
PANTHER_TIME_FORMAT = "%Y-%m-%d %H:%M:%S.%f"


def rule(event):

    if event.udm("event_type") != event_type.ACCOUNT_CREATED:
        return False

    event_id = f'new_user_{event.get("p_row_id")}'
    new_user = event.udm("user_name")
    event_time = datetime.strptime(event.get("p_event_time"), PANTHER_TIME_FORMAT)
    expiry_time = event_time + TTL

    put_string_set(new_user, event_id)

    set_key_expiration(new_user, expiry_time.strftime("%s"))
    return True

def title(event):
    return f"A new user account was created - [{event.udm('user_name')}]"
