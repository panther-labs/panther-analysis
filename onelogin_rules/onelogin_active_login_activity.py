import time
from panther_oss_helpers import get_string_set, put_string_set, set_key_expiration, add_to_string_set  # pylint: disable=import-error,line-too-long

THRESH = 2
THRESH_TTL = 43200  # 1/2 day


def rule(event):
    # Pre-filter: event_type_id = 5 is login events.
    if event.get('event_type_id') != 5 or not event.get(
            'ipaddr') or not event.get('user_id'):
        return False
    # This track multiple successful logins for different accounts from the same ip address
    # First, keep a list of unique usernames that have logged in from this ip address
    event_key = get_key(event)
    usernames = get_string_set(event_key)
    if not usernames:
        # store this as the first user login from this ip address
        put_string_set(event_key, [event.get('user_id')])
        set_key_expiration(event_key, int(time.time()) + THRESH_TTL)
        return False
    # add a new username if this is a unique user from this ip address
    if event.get('user_id') not in usernames:
        usernames = add_to_string_set(event_key, event.get('user_id'))
    return len(usernames) > THRESH


def get_key(event):
    return '{}-UniqueUserLoginEvents'.format(event.get('ipaddr',
                                                       '<UNKNOWN_IP>'))


def title(event):
    # (Optional) Return a string which will be shown as the alert title.
    return 'Unusual logins in OneLogin for multiple users from ip [{}]'.format(
        event.get('ipaddr', '<UNKNOWN_IP>'))
