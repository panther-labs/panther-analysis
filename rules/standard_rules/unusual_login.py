import ast
import json
import logging

import panther_event_type_helpers as event_type
from panther_oss_helpers import (
    add_parse_delay,
    geoinfo_from_ip,
    get_string_set,
    put_string_set,
)

# number of unique geolocation city:region combinations retained in the
# panther-kv-table in Dynamo to suppress alerts
GEO_HISTORY_LENGTH = 5
GEO_INFO = {}
GEO_HISTORY = {}


def rule(event):
    # pylint: disable=too-complex
    # unique key for global dictionary
    log = event.get("p_row_id")

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
    GEO_INFO[log] = geoinfo_from_ip(event.udm("source_ip"))

    # As of Panther 1.19, mocking returns all mocked objects in a string
    # GEO_INFO must be converted back to a dict to mimic the API call
    if isinstance(GEO_INFO[log], str):
        GEO_INFO[log] = json.loads(GEO_INFO[log])

    # Look up history of unique geolocations
    event_key = get_key(event)
    # Mocked during unit testing
    previous_geo_logins = get_string_set(event_key)

    # As of Panther 1.19, mocking returns all mocked objects in a string
    # previous_geo_logins must be converted back to a set to mimic the API call
    if isinstance(previous_geo_logins, str):
        logging.debug("previous_geo_logins is a mocked string:")
        logging.debug(previous_geo_logins)
        if previous_geo_logins:
            previous_geo_logins = ast.literal_eval(previous_geo_logins)
        else:
            previous_geo_logins = set()
        logging.debug("new type of previous_geo_logins should be 'set':")
        logging.debug(type(previous_geo_logins))

    new_login_geo = (
        f"{GEO_INFO[log].get('region', '<UNKNOWN_REGION>')}"
        ":"
        f"{GEO_INFO[log].get('city', '<UNKNOWN_CITY>')}"
    )
    new_login_timestamp = event.get("p_event_time", "")

    # convert set of single string to dictionary
    if previous_geo_logins:
        previous_geo_logins = json.loads(previous_geo_logins.pop())
    else:
        previous_geo_logins = {}
    logging.debug("new type of previous_geo_logins should be 'dict':")
    logging.debug(type(previous_geo_logins))

    # don't alert if the geo is already in the history
    if previous_geo_logins.get(new_login_geo):
        # update timestamp of the existing geo in the history
        previous_geo_logins[new_login_geo] = new_login_timestamp

        # write the dictionary of geolocs:timestamps back to Dynamo
        # Mocked during unit testing
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
        logging.debug("updated_geo_logins before removing oldest entry:")
        logging.debug(updated_geo_logins)
        updated_geo_logins.pop(oldest_login)
        logging.debug("updated_geo_logins after removing oldest entry:")
        logging.debug(updated_geo_logins)

    # Mocked during unit testing
    put_string_set(event_key, [json.dumps(updated_geo_logins)])

    global GEO_HISTORY  # pylint: disable=global-statement
    GEO_HISTORY[log] = updated_geo_logins
    logging.debug("GEO_HISTORY in main rule:\n%s", json.dumps(GEO_HISTORY[log]))
    return True


def get_key(event) -> str:
    # Use the name to deconflict with other rules that may also use actor_user
    return __name__ + ":" + str(event.udm("actor_user"))


def title(event):
    log = event.get("p_row_id")
    return (
        f"{event.get('p_log_type')}: New access location for user"
        f" [{event.udm('actor_user')}]"
        f" from {GEO_INFO[log].get('city')}, {GEO_INFO[log].get('region')}"
        f" in {GEO_INFO[log].get('country')}"
        f" (not in last [{GEO_HISTORY_LENGTH}] login locations)"
    )


def alert_context(event):
    log = event.get("p_row_id")
    context = {}
    context["ip"] = event.udm("source_ip")
    context["reverse_lookup"] = GEO_INFO[log].get("hostname", "No reverse lookup hostname")
    context["ip_org"] = GEO_INFO[log].get("org", "No organization listed")
    if GEO_HISTORY[log]:
        context["geoHistory"] = f"{json.dumps(GEO_HISTORY[log])}"
    context = add_parse_delay(event, context)
    return context
