from datetime import datetime, timedelta
from json import dumps, loads
from math import asin, cos, sin, sqrt
from panther_base_helpers import deep_get, aws_rule_context
from panther_ipinfo_helpers import get_ipinfo_location
from panther_oss_helpers import get_dictionary, put_dictionary

PANTHER_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

AUTH_EVENTS = [
    "CreateToken",
    "RegisterClient",
    "StartDeviceAuthorization",
    "Authenticate",
    "Federate",
]


def rule(event):
    global PREVIOUS_EVENT_DATA, CURRENT_EVENT_DATA # pylint: disable=global-statement

    if event.get("eventName") not in AUTH_EVENTS:
        return False

    key = get_key(event)
    key_exp_time = int((datetime.now() + timedelta(days=7)).timestamp())

    CURRENT_EVENT_DATA = get_source_ip_location(event)
    CURRENT_EVENT_DATA["time"] = event.get("p_event_time")

    PREVIOUS_EVENT_DATA = get_dictionary(key)

    if not PREVIOUS_EVENT_DATA:
        put_dictionary(key, CURRENT_EVENT_DATA, key_exp_time)
        return False

    # Handle Unit Test Mocks
    if isinstance(PREVIOUS_EVENT_DATA, str):
        PREVIOUS_EVENT_DATA = loads(PREVIOUS_EVENT_DATA)

    distance = haversine_distance(
        float(PREVIOUS_EVENT_DATA["lat"]),
        float(CURRENT_EVENT_DATA["lat"]),
        float(PREVIOUS_EVENT_DATA["lng"]),
        float(CURRENT_EVENT_DATA["lng"]),
    )

    # Cast timestamps at datetime objects
    old_time = datetime.strptime(PREVIOUS_EVENT_DATA["time"][:26], PANTHER_TIME_FORMAT)
    new_time = datetime.strptime(CURRENT_EVENT_DATA["time"][:26], PANTHER_TIME_FORMAT)

    # Calculate the number of seconds between old and new times
    time_delta = (new_time - old_time).total_seconds() / 3600  # seconds in an hour

    # Check for instantaneous travel, which is defined as time_delta = 0 AND distance > 0
    # If instantaneous travel occurs, immediately alert
    if not time_delta and distance:
        return True
    if not time_delta and not distance:
        return False

    # Calculate speed in Kilometers / Hour
    speed = distance / time_delta

    put_dictionary(key, CURRENT_EVENT_DATA, key_exp_time)

    return speed > 125


def title(event):
    return (
        f"User [{deep_get(event, 'userIdentity', 'principalId')}] "
        f"performed a [{event.get('eventName')}] "
        f"action in AWS account [{event.get('recipientAccountId')}]."
    )


def alert_context(event):
    context = aws_rule_context(event)
    context["Previous Event"] = PREVIOUS_EVENT_DATA
    context["Current Event"] = CURRENT_EVENT_DATA
    return context


# Taken from stack overflow user Michael0x2a: https://stackoverflow.com/a/19412565/6645635
def haversine_distance(previous_lat, current_lat, previous_long, current_long):
    # approximate radius of earth in km
    radius = 6371.0

    distance_lat = current_lat - previous_lat
    distance_long = current_long - previous_long

    distance_a = (
        sin(distance_lat / 2) ** 2
        + cos(previous_lat) * cos(current_lat) * sin(distance_long / 2) ** 2
    )
    distance_c = 2 * asin(sqrt(distance_a))

    return radius * distance_c


def get_source_ip_location(event):
    return dict(get_ipinfo_location(event).ipinfo_location["sourceIPAddress"])


def get_key(event) -> str:
    return __name__ + ":" + deep_get(event, "userIdentity", "principalId")
