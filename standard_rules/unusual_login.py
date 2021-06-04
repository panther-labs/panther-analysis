import datetime
import json

import panther_event_type_helpers as event_type
from panther_oss_helpers import get_string_set, put_string_set, geoinfo_from_ip

FINGERPRINT_THRESHOLD = 5
FINGERPRINT = {}
GEO_INFO = {}


def rule(event):
    # Pre-filter to save compute time where possible.
    if event.udm("event_type") != event_type.SUCCESSFUL_LOGIN:
        return False

    # we use udm 'actor_user' field as a ddb and 'source_ip' in the api call
    if not event.udm("actor_user") or not event.udm("source_ip"):
        return False

    # Lookup geo-ip data via API call
    GEO_INFO = geoinfo_from_ip(event.udm("source_ip"))

    # Unit tests with defined mocks for geoinfo_from_ip
    if isinstance(GEO_INFO, str):
        GEO_INFO = json.loads(GEO_INFO)

    # The idea is to create a fingerprint of this login, and then keep track of all the fingerprints
    # for a given user's logins. In this way, we can detect unusual logins.
    login_geo = GEO_INFO.get("region", "<REGION>") + ":" + GEO_INFO.get("city", "<CITY>")
    FINGERPRINT[event.get("p_row_id")] = login_geo

    # Lookup & store persistent data
    event_key = get_key(event)
    last_login_info = get_string_set(event_key)
    # Unit tests with defined mocks for get_string_set
    if isinstance(last_login_info, str):
        last_login_info = {last_login_info}
    login_timestamp = str(datetime.datetime.now())
    if not last_login_info:
        # Store this as the first login if we've never seen this user login before
        put_string_set(event_key, [json.dumps({login_geo: login_timestamp})])
        return False
    last_login_info = json.loads(last_login_info.pop())

    # update the timestamp associated with this fingerprint
    last_login_info[login_geo] = login_timestamp
    # exclude from unit test
    if "mock" not in event:
        put_string_set(event_key, [json.dumps(last_login_info)])

    # fire an alert when number of unique, recent fingerprints is greater than a threshold
    if len(last_login_info) > FINGERPRINT_THRESHOLD:
        oldest = login_timestamp
        for fp_geo, fp_time in last_login_info.items():
            if fp_time < oldest:
                oldest = fp_geo
        # remove oldest login tuple
        last_login_info.pop(oldest)
        # exclude from unit test
        if "mock" not in event:
            put_string_set(event_key, [json.dumps(last_login_info)])
        return True
    return False


def get_key(event):
    # Use the name so that test data doesn't interfere with live data
    return __name__ + ":" + str(event.udm("actor_user"))


def title(event):
    return (
        f"{event.get('p_log_type')}: Unusual access for user"
        f" [{event.get('user_name', '<UNKNOWN_USER>')}]"
        f" from {GEO_INFO.get('city')}, {GEO_INFO.get('region')} in {GEO_INFO.get('country')}"
    )
