import time
from panther_base_helpers import is_ip_in_network
from panther_oss_helpers import get_string_set, put_string_set, set_key_expiration, add_to_string_set  # pylint: disable=line-too-long

THRESH = 2
THRESH_TTL = 43200  # 1/2 day

# Safelist for IP Subnets to ignore in this ruleset
# Each entry in the list should be in CIDR notation
# This should include any source ip addresses
# that are shared among users such as:
# proxy servers, the public corporate ip space,
# scanner ips etc
SHARED_IP_SPACE = [
    '192.168.0.0/16',
]


def rule(event):
    # Pre-filter: event_type_id = 5 is login events.
    if event.get('event_type_id') != 5 or not event.get(
            'ipaddr') or not event.get('user_id'):
        return False
    # We expect to see multiple user logins from these shared, common ip addresses
    if is_ip_in_network(event.get('ipaddr'), SHARED_IP_SPACE):
        return False
    # This tracks multiple successful logins for different accounts from the same ip address
    # First, keep a list of unique user ids that have logged in from this ip address
    event_key = get_key(event)
    user_ids = get_string_set(event_key)
    # the user id of the user that has just logged in
    user_id = str(event.get('user_id'))
    if not user_ids:
        # store this as the first user login from this ip address
        put_string_set(event_key, [user_id])
        set_key_expiration(event_key, int(time.time()) + THRESH_TTL)
        return False
    # add a new username if this is a unique user from this ip address
    if user_id not in user_ids:
        user_ids = add_to_string_set(event_key, user_id)
        set_key_expiration(event_key, int(time.time()) + THRESH_TTL)
    return len(user_ids) > THRESH


def get_key(event):
    return __name__ + ':' + event.get('ipaddr', '<UNKNOWN_IP>')


def title(event):
    return 'Unusual logins in OneLogin for multiple users from ip [{}]'.format(
        event.get('ipaddr', '<UNKNOWN_IP>'))
