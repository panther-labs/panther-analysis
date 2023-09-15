from global_filter_notion import filter_include_event
from panther_notion_helpers import notion_alert_context
from panther_oss_helpers import get_string_set, put_string_set, set_key_expiration
from panther_ipinfo_helpers import IPInfoLocation

import time

# How long (in seconds) to keep previous login locations in cached memory
DEFAULT_CACHE_PERIOD = 2419200

def rule(event):
    if not filter_include_event(event):
        return False
    
    # Only focused on login events
    if event.deep_walk('type') != 'user.login':
        return False
    
    # Get the user's location, via IPInfo
    global ipinfo_loc
    ipinfo_loc = IPInfoLocation(event)
    path_to_ip = 'ip_address'
    city = ipinfo_loc.city(path_to_ip)
    region = ipinfo_loc.region(path_to_ip)
    country = ipinfo_loc.country(path_to_ip)
    loc_string = '_'.join((city, region, country))

    # Store the login location. The premise is to create a new entry for each combimation of user
    # and location, and then have those records persist for some length of time (4 weeks by 
    # default).
    user = event.deep_walk('actor', 'id')
    cache_key = f"{user} {loc_string}"
    # Check if this key already exists
    if get_string_set(cache_key):
        # User has logged in from this location recently. Let's refresh this login key.
        set_key_expiration(cache_key, time.time()+DEFAULT_CACHE_PERIOD)
        return False # No need to alert - user has logged in from here before.
    else:
        # This is a location the user hasn't recently used
        put_string_set(cache_key, ["arbitrary value"])
        set_key_expiration(cache_key, time.time()+DEFAULT_CACHE_PERIOD)
        return True


def title(event):
    path_to_ip = 'ip_address'
    city = ipinfo_loc.city(path_to_ip)
    region = ipinfo_loc.region(path_to_ip)
    country = ipinfo_loc.country(path_to_ip)

    user_email = event.deep_walk('actor', 'person', 'email', default='UNKNWON_EMAIL')
    return f'[{user_email}] logged in from a new location: {city}, {region}, {country}.'


def alert_context(event):
    path_to_ip = 'ip_address'
    city = ipinfo_loc.city(path_to_ip)
    region = ipinfo_loc.region(path_to_ip)
    country = ipinfo_loc.country(path_to_ip)
    user_email = user_email = event.deep_walk('actor', 'person', 'email', default='UNKNWON_EMAIL')

    context = notion_alert_context(event)
    context['user_email'] = user_email
    context['location'] = {
        'city': city,
        'region': region,
        'country': country
    }

    return context