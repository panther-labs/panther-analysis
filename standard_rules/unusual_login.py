import datetime
import json
import requests
import panther_event_type_helpers as event_type
from panther_oss_helpers import get_string_set, put_string_set
FINGERPRINT_THRESHOLD = 5


def rule(event):
    # Pre-filter to save compute time where possible.
    if event.udm('event_type') != event_type.SUCCESSFUL_LOGIN:
        return False
    # we use udm 'actor_user' field as a key
    if not event.udm('actor_user'):
        return False

    if not event.udm('source_ip'):
        # source_ip field is required to perform the api call
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
        raise Exception("API call failed: GET {} returned {}".format(
            url, resp.status_code))
    login_info = json.loads(resp.text)
    # The idea is to create a fingerprint of this login, and then keep track of all the fingerprints
    # for a given user's logins. In this way, we can detect unusual logins.
    login_tuple = login_info.get('region', '<REGION>') + ":" + login_info.get(
        'city', '<CITY>')

    # Lookup & store persistent data
    event_key = get_key(event)
    last_login_info = get_string_set(event_key)
    fingerprint_timestamp = datetime.datetime.now()
    if not last_login_info:
        # Store this as the first login if we've never seen this user login before
        put_string_set(event_key,
                       [json.dumps({login_tuple: fingerprint_timestamp})])
        return False
    last_login_info = json.loads(last_login_info.pop())

    # update the timestamp associated with this fingerprint
    last_login_info[login_tuple] = fingerprint_timestamp
    put_string_set(event_key, [json.dumps(last_login_info)])

    # fire an alert when number of unique, recent fingerprints is greater than a threshold
    if len(last_login_info) > FINGERPRINT_THRESHOLD:
        oldest = login_tuple
        for fp_tuple, fp_time in last_login_info.items():
            if fp_time < oldest:
                oldest = fp_tuple
        # remove oldest login tuple
        last_login_info.pop(oldest)
        put_string_set(event_key, [json.dumps(last_login_info)])
        return True
    return False


def get_key(event):
    # Use the name so that test data doesn't interfere with live data
    return __name__ + ':' + str(event.udm('actor_user'))


def title(event):
    return '{}: Unusual logins detected for user [{}]'.format(
        event.get('p_log_type'), event.udm('actor_user'))
