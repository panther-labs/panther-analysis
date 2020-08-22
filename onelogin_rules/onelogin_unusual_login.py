import requests
import json
from panther_oss_helpers import get_string_set, put_string_set

def rule(event):
    # Pre-filter to save compute time where possible
    if event.get('event_type_id') != 5 or event.get('ipaddr') is None:
        return False

    # Lookup geo-ip data via API call
    url = 'https://ipinfo.io/' + event['ipaddr'] + '/geo'
    
    # Skip API call if this is a unit test
    if __name__ == 'PolicyApiTestingPolicy':
        resp = lambda: None
        setattr(resp, 'status_code', 200)
        setattr(resp, 'text', event['api_data'])
    else:
        resp = requests.get(url)

    if resp.status_code != 200:
        # Could raise an exception here for ops team to look into
        return False
    login_info = json.loads(resp.text)
    login_tuple = login_info.get('region', '<REGION>') + ":" + login_info.get('city', '<CITY>')
    
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
    
    tuple_count = last_login_info[login_tuple]
    higher_tuples = 0
    for tcount in last_login_info.values():
        if tcount > tuple_count:
            higher_tuples += 1
        if higher_tuples == 3:
            return True
    
    return False


def get_key(event):
    # Use the name so that test data doesn't interfere with live data
    return __name__ + ':' + str(event.get('user_id', '<UNKNOWN_USER>'))


def title(event):
	# (Optional) Return a string which will be shown as the alert title.
	return 'Unusual logins in OneLogin for user [{}]'.format(event.get('user_name', '<UNKNOWN_USER>'))
