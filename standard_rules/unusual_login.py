import ast
import datetime
import json

import panther_event_type_helpers as event_type
from panther_oss_helpers import geoinfo_from_ip, get_string_set, put_string_set

FINGERPRINT_THRESHOLD = 5
FINGERPRINT = {}
GEO_INFO = {}


def rule(event):
    global GEO_INFO  # pylint: disable=global-statement
    # Pre-filter to save compute time where possible.
    if event.udm("event_type") != event_type.SUCCESSFUL_LOGIN:
        return False

    # we use udm 'actor_user' field as a ddb and 'source_ip' in the api call
    if not event.udm("actor_user") or not event.udm("source_ip"):
        return False

    # Lookup geo-ip data via API call
    GEO_INFO = geoinfo_from_ip(event.udm("source_ip"))

    # Note: as of Panther 1.19, mocking returns all mocked objects in a string
    # previous_logins must be converted back to a dict to mimic the API call
    if isinstance(GEO_INFO, str):
        GEO_INFO = json.loads(GEO_INFO)

    # Lookup & store persistent data
    event_key = str(event.udm("actor_user"))
    previous_logins = get_string_set(event_key)
    # Note: as of Panther 1.19, mocking returns all mocked objects in a string
    # previous_logins must be converted back to a set to mimic the API call
    if isinstance(previous_logins, str):
        print("previous_logins is a mocked string:")
        print(previous_logins)
        previous_logins = ast.literal_eval(previous_logins)
        print("new type of previous_logins is:", type(previous_logins))
    new_login_geo = (
        f"{GEO_INFO.get('region', '<UNKNOWN_REGION>')}"
        ":"
        f"{GEO_INFO.get('city', '<UNKNOWN_CITY>')}"
    )
    new_login_fingerprint = json.dumps({new_login_geo: str(datetime.datetime.now())})

    previous_logins.add(new_login_fingerprint)
    # exclude Dynamo API call from unit test
    if "mock" not in event:
        put_string_set(event_key, list(previous_logins))

    # fire an alert when number of unique, recent fingerprints is greater than a threshold
    if len(previous_logins) > FINGERPRINT_THRESHOLD:
        oldest = json.loads(new_login_fingerprint)[new_login_geo]
        for login in previous_logins:
            for fp_time in json.loads(login).values():
                print(fp_time)
                if fp_time < oldest:  # this would always be true, as every timestamp of
                    # every login except the newest one would be less than
                    # the newest one
                    oldest = fp_time
                    oldest_login = login
        previous_logins.remove(oldest_login)
        print("Updated previous_logins:")
        print(previous_logins)
        # exclude Dynamo API call from unit test
        if "mock" not in event:
            put_string_set(event_key, list(previous_logins))
        return True
    return False


def title(event):
    return (
        f"{event.get('p_log_type')}: Unusual access for user"
        f" [{event.udm('actor_user')}]"
        f" from {GEO_INFO.get('city')}, {GEO_INFO.get('region')} in {GEO_INFO.get('country')}"
    )
