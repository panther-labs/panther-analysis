import time
from global_filter_notion import filter_include_event
from panther_notion_helpers import notion_alert_context
from panther_oss_helpers import get_string_set, put_string_set, set_key_expiration
from panther_ipinfo_helpers import IPInfoLocation

# How long (in seconds) to keep previous login locations in cached memory
DEFAULT_CACHE_PERIOD = 2419200


def rule(event):
    if not filter_include_event(event):
        return False

    # Only focused on login events
    if event.deep_walk("event", "type") != "user.login":
        return False

    # Get the user's location, via IPInfo
    # pylint: disable=global-variable-undefined
    global IPINFO_LOC
    IPINFO_LOC = IPInfoLocation(event)
    path_to_ip = "event.ip_address"
    city = IPINFO_LOC.city(path_to_ip)
    region = IPINFO_LOC.region(path_to_ip)
    country = IPINFO_LOC.country(path_to_ip)
    loc_string = "_".join((city, region, country))

    # Store the login location. The premise is to create a new entry for each combimation of user
    # and location, and then have those records persist for some length of time (4 weeks by
    # default).
    user = event.deep_walk("event", "actor", "id")
    cache_key = f"{user} {loc_string}"
    # Check if this key already exists
    if get_string_set(cache_key):
        # User has logged in from this location recently. Let's refresh this login key.
        set_key_expiration(cache_key, time.time() + DEFAULT_CACHE_PERIOD)
        return False  # No need to alert - user has logged in from here before.

    # Else, his is a location the user hasn't recently used
    put_string_set(cache_key, ["arbitrary value"], int(time.time()) + DEFAULT_CACHE_PERIOD)
    return True


def title(event):
    path_to_ip = "event.ip_address"
    city = IPINFO_LOC.city(path_to_ip)
    region = IPINFO_LOC.region(path_to_ip)
    country = IPINFO_LOC.country(path_to_ip)

    user_email = event.deep_walk("event", "actor", "person", "email", default="UNKNWON_EMAIL")
    return f"Notion [{user_email}] logged in from a new location: {city}, {region}, {country}."


def alert_context(event):
    path_to_ip = "event.ip_address"
    city = IPINFO_LOC.city(path_to_ip)
    region = IPINFO_LOC.region(path_to_ip)
    country = IPINFO_LOC.country(path_to_ip)
    user_email = event.deep_walk("event", "actor", "person", "email", default="UNKNWON_EMAIL")

    context = notion_alert_context(event)
    context["user_email"] = user_email
    context["location"] = {"city": city, "region": region, "country": country}

    return context
