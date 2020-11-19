import json
import requests
import panther_event_type_helpers as event_type
from panther_oss_helpers import get_string_set, put_string_set
FINGERPRINT_THRESHOLD = 3

def rule(event):
    # Pre-filter to save compute time where possible. event_type_id = 5 is login events.
    if not event.udm('event_type') or event.udm('event_type') != event_type.SUCCESSFUL_LOGIN:
        return False
    # we use udm 'actor_user' field as a key
    if not event.udm('actor_user'):
        return False

    # Lookup geo-ip data via API call
    url = 'https://ipinfo.io/' + event.udm('source_ip') + '/geo'

    # Skip API call if this is a unit test
    if __name__ == 'PolicyApiTestingPolicy':
        resp = lambda: None
        setattr(resp, 'status_code', 200)
        setattr(resp, 'text', event['api_data'])
    else:
        # This response looks like the following:
        # {‘ip': '8.8.8.8', 'city': 'Mountain View', 'region': 'California', 'country': 'US',
        # 'loc': '37.4056,-122.0775', 'postal': '94043', 'timezone': 'America/Los_Angeles'}
        resp = requests.get(url)

    if resp.status_code != 200:
        # Could raise an exception here for ops team to look into
        return False
    login_info = json.loads(resp.text)
    # The idea is to create a fingerprint of this login, and then keep track of all the fingerprints
    # for a given user's logins. In this way, we can detect unusual logins.
    login_tuple = login_info.get('region', '<REGION>') + ":" + login_info.get(
        'city', '<CITY>')

    # Lookup & store persistent data
    event_key = get_key(event)
    last_login_info = get_string_set(event_key)
    if not last_login_info:
        # Store this as the first login if we've never seen this user login before
        put_string_set(event_key, [json.dumps({login_tuple: 1})])
        return False
    last_login_info = json.loads(last_login_info.pop())

    last_login_info[login_tuple] = last_login_info.get(login_tuple, 0) + 1
    put_string_set(event_key, [json.dumps(last_login_info)])

    # Here we are checking if this login's fingerprint is one of the top three most common
    # fingerprints for this user. If it is not, we fire an alert.
    tuple_count = last_login_info[login_tuple]
    higher_tuples = 0
    for tcount in last_login_info.values():
        if tcount > tuple_count:
            higher_tuples += 1
        if higher_tuples >= FINGERPRINT_THRESHOLD:
            return True

    return False


def get_key(event):
    # Use the name so that test data doesn't interfere with live data
    return __name__ + ':' + str(event.udm('actor_user'))


def title(event):
    # (Optional) Return a string which will be shown as the alert title.
    return '{}: Unusual logins detected for user [{}]'.format(
        event.get('p_log_type'), event.udm('actor_user'))
