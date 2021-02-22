from datetime import datetime, timedelta
from json import dumps, loads
from math import asin, cos, radians, sin, sqrt

from panther_base_helpers import deep_get, okta_alert_context
from panther_oss_helpers import get_string_set, put_string_set, set_key_expiration

PANTHER_TIME_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
EVENT_CITY_TRACKING = {}


def rule(event):
    # Only evaluate successful logins
    if (
        event.get("eventType") != "user.session.start"
        or deep_get(event, "outcome", "result") == "FAILURE"
    ):
        return False

    # Generate a unique cache key for each user
    login_key = gen_key(event)
    # Retrieve the prior login info from the cache, if any
    last_login = get_string_set(login_key)
    # If we haven't seen this user login recently, store this login for future use and don't alert
    if not last_login:
        store_login_info(login_key, event)
        return False

    # Load the last login from the cache into an object we can compare
    old_login_stats = loads(last_login.pop())
    new_login_stats = {
        "city": deep_get(event, "client", "geographicalContext", "city"),
        "lon": deep_get(event, "client", "geographicalContext", "geolocation", "lon"),
        "lat": deep_get(event, "client", "geographicalContext", "geolocation", "lat"),
    }

    distance = haversine_distance(old_login_stats, new_login_stats)
    old_time = datetime.strptime(old_login_stats["time"][:26], PANTHER_TIME_FORMAT)
    new_time = datetime.strptime(event.get("p_event_time")[:26], PANTHER_TIME_FORMAT)
    time_delta = (new_time - old_time).total_seconds() / 3600  # seconds in an hour

    # Don't let time_delta be 0 (divide by zero error below)
    time_delta = time_delta or 0.0001
    # Calculate speed in Kilometers / Hour
    speed = distance / time_delta

    # Calculation is complete, so store the most recent login for the next check
    store_login_info(login_key, event)
    EVENT_CITY_TRACKING[event.get("p_row_id")] = {
        "new_city": new_login_stats.get("city", "<UNKNOWN_NEW_CITY>"),
        "old_city": old_login_stats.get("city", "<UNKNOWN_OLD_CITY>"),
    }

    return speed > 900  # Boeing 747 cruising speed


def gen_key(event):
    return "Okta.Login.GeographicallyImprobable{}".format(deep_get(event, "actor", "alternateId"))


# Taken from stack overflow user Michael0x2a: https://stackoverflow.com/a/19412565/6645635
def haversine_distance(grid_one, grid_two):
    # approximate radius of earth in km
    radius = 6371.0

    # Convert the grid elements to radians
    lon1, lat1, lon2, lat2 = map(
        radians, [grid_one["lon"], grid_one["lat"], grid_two["lon"], grid_two["lat"]]
    )

    dlat = lat2 - lat1
    dlon = lon2 - lon1

    distance_a = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
    distance_c = 2 * asin(sqrt(distance_a))

    return radius * distance_c


def store_login_info(key, event):
    # Map the user to the lon/lat and time of the most recent login
    put_string_set(
        key,
        [
            dumps(
                {
                    "city": deep_get(event, "client", "geographicalContext", "city"),
                    "lon": deep_get(event, "client", "geographicalContext", "geolocation", "lon"),
                    "lat": deep_get(event, "client", "geographicalContext", "geolocation", "lat"),
                    "time": event.get("p_event_time"),
                }
            )
        ],
    )
    # Expire the entry after a week so the table doesn't fill up with past users
    set_key_expiration(key, str((datetime.now() + timedelta(days=7)).timestamp()))


def title(event):
    # (Optional) Return a string which will be shown as the alert title.
    return "Geographically improbably login for user [{}] from [{}] to [{}]".format(
        deep_get(event, "actor", "alternateId"),
        deep_get(
            EVENT_CITY_TRACKING.get(event.get("p_row_id")), "old_city", default="<NOT_STORED>"
        ),  # For compatibility
        deep_get(
            EVENT_CITY_TRACKING.get(event.get("p_row_id")), "new_city", default="<UNKNOWN_NEW_CITY>"
        ),
    )


def dedup(event):
    # (Optional) Return a string which will de-duplicate similar alerts.
    return deep_get(event, "actor", "alternateId")


def alert_context(event):
    context = okta_alert_context(event)
    context["old_city"] = deep_get(
        EVENT_CITY_TRACKING.get(event.get("p_row_id")), "old_city", default="<NOT_STORED>"
    )
    context["new_city"] = deep_get(
        EVENT_CITY_TRACKING.get(event.get("p_row_id")), "new_city", default="<UNKNOWN_NEW_CITY>"
    )
    return context
