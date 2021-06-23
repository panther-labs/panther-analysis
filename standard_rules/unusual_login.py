import ast
import json

import panther_event_type_helpers as event_type
from panther_oss_helpers import geoinfo_from_ip, get_string_set, put_string_set

# number of unique geolocation city:region combinations retained in the
# panther-kv-table in Dynamo to suppress alerts
GEO_HISTORY_LENGTH = 5
FINGERPRINT = {}
GEO_INFO = {}


def rule(event):
    # GEO_INFO is mocked as a string in unit tests and redeclared as a dict
    global GEO_INFO  # pylint: disable=global-statement
    # Pre-filter to save compute time where possible.
    if event.udm("event_type") != event_type.SUCCESSFUL_LOGIN:
        return False

    # we use udm 'actor_user' field as a ddb and 'source_ip' in the api call
    if not event.udm("actor_user") or not event.udm("source_ip"):
        return False

    # Lookup geo-ip data via API call
    # Mocked during unit testing
    GEO_INFO = geoinfo_from_ip(event.udm("source_ip"))

    # As of Panther 1.19, mocking returns all mocked objects in a string
    # GEO_INFO must be converted back to a dict to mimic the API call
    if isinstance(GEO_INFO, str):
        GEO_INFO = json.loads(GEO_INFO)

    # Look up history of unique geolocations
    event_key = get_key(event)
    # Mocked during unit testing
    previous_geo_logins = get_string_set(event_key)

    # As of Panther 1.19, mocking returns all mocked objects in a string
    # previous_geo_logins must be converted back to a set to mimic the API call
    if isinstance(previous_geo_logins, str):
        print("previous_geo_logins is a mocked string:")
        print(previous_geo_logins)
        previous_geo_logins = ast.literal_eval(previous_geo_logins)
        print("new type of previous_geo_logins is:", type(previous_geo_logins))

    new_login_geo = (
        f"{GEO_INFO.get('region', '<UNKNOWN_REGION>')}"
        ":"
        f"{GEO_INFO.get('city', '<UNKNOWN_CITY>')}"
    )
    new_login_timestamp = event.get("p_event_time", "")

    # convert set of single string to dictionary
    previous_geo_logins = json.loads(previous_geo_logins.pop())

    # don't alert if the geo is already in the history
    if previous_geo_logins.get(new_login_geo):
        # update timestamp of the existing geo in the history
        previous_geo_logins[new_login_geo] = new_login_timestamp
        # exclude Dynamo API call from unit test
        if "mock" not in event:
            # write the dictionary of geolocs:timestamps back to Dynamo
            put_string_set(event_key, [json.dumps(previous_geo_logins)])
        return False

    # fire an alert when there are more unique geolocs:timestamps in the login history
    # add a new geo to the dictionary
    updated_geo_logins = previous_geo_logins
    updated_geo_logins[new_login_geo] = new_login_timestamp

    # remove the oldest geo from the history if the updated dict exceeds the
    # specified history length
    if len(updated_geo_logins) > GEO_HISTORY_LENGTH:
        oldest = updated_geo_logins[new_login_geo]
        for geo, time in updated_geo_logins.items():
            if time < oldest:
                oldest = time
                oldest_login = geo
        updated_geo_logins.pop(oldest_login)
        print("updated_geo_logins:")
        print(updated_geo_logins)

    # exclude Dynamo API call from unit test
    if "mock" not in event:
        put_string_set(event_key, [json.dumps(updated_geo_logins)])

    return True


def get_key(event):
    # Use the name to deconflict with other rules that may also use actor_user
    return __name__ + ":" + str(event.udm("actor_user"))


def title(event):
    return (
        f"{event.get('p_log_type')}: New access location for user"
        f" [{event.udm('actor_user')}]"
        f" from {GEO_INFO.get('city')}, {GEO_INFO.get('region')} in {GEO_INFO.get('country')}"
    )
