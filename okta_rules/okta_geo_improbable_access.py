from datetime import datetime, timedelta
from json import dumps, loads
from math import sin, cos, sqrt, atan2, radians
from panther_oss_helpers import get_string_set, put_string_set, set_key_expiration
PANTHER_TIME_FORMAT = '%Y-%m-%d %H:%M:%S.%f'


def rule(event):
    # We only want to evaluate user logins
    if event['eventType'] != 'user.session.start':
        return False

    # Generate a unique key for each user
    login_key = gen_key(event)

    # Retrieve the prior login info, if any
    last_login = get_string_set(login_key)

    # If we haven't seen this user login recently, store this login for future
    # use and don't alert
    if not last_login:
        store_login_info(login_key, event)
        return False

    # Load the last login into an object we can compare
    old_login_stats = loads(last_login.pop())
    new_login_stats = {
        'lon': event['client']['geographicalContext']['geolocation']['lon'],
        'lat': event['client']['geographicalContext']['geolocation']['lat'],
    }

    distance = haversine_distance(old_login_stats, new_login_stats)
    old_time = datetime.strptime(old_login_stats['time'][:26],
                                 PANTHER_TIME_FORMAT)
    new_time = datetime.strptime(event['p_event_time'][:26],
                                 PANTHER_TIME_FORMAT)
    time_delta = (new_time -
                  old_time).total_seconds() / 3600  # seconds in an hour

    # Don't let time_delta be 0 (divide by zero error below)
    time_delta = time_delta or .0001

    # Calculate speed in Kilometers / Hour
    speed = distance / time_delta

    # Calculation is complete, so store the most recent login for the next check
    store_login_info(login_key, event)

    return speed > 900  # Boeing 747 cruising speed


def gen_key(event):
    return 'Okta.Login.GeographicallyImprobable' + event['actor']['alternateId']


# Taken from stack overflow user Michael0x2a: https://stackoverflow.com/a/19412565/6645635
def haversine_distance(grid_one, grid_two):
    # approximate radius of earth in km
    radius = 6373.0
    dlat = radians(grid_two['lat']) - radians(grid_one['lat'])
    dlon = radians(grid_two['lon']) - radians(grid_one['lon'])

    distance_a = sin(dlat / 2)**2 + cos(grid_one['lat']) * cos(
        grid_two['lat']) * sin(dlon / 2)**2
    distance_c = 2 * atan2(sqrt(distance_a), sqrt(1 - distance_a))

    return radius * distance_c


def store_login_info(key, event):
    # Map the user to the lon/lat and time of the most recent login
    put_string_set(key, [
        dumps({
            'lon': event['client']['geographicalContext']['geolocation']['lon'],
            'lat': event['client']['geographicalContext']['geolocation']['lat'],
            'time': event['p_event_time']
        })
    ])
    # Expire the entry after a week so the table doesn't fill up with past users
    set_key_expiration(key, str(
        (datetime.now() + timedelta(days=7)).timestamp()))


def title(event):
    # (Optional) Return a string which will be shown as the alert title.
    return 'Geographically improbably login for user [{}] in [{}]'.format(
        event['actor']['alternateId'],
        event['client']['geographicalContext']['city'])


def dedup(event):
    # (Optional) Return a string which will de-duplicate similar alerts.
    return event['actor']['alternateId']
