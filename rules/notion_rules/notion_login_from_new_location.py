import datetime
import json
import time

from global_filter_notion import filter_include_event
from panther_ipinfo_helpers import IPInfoLocation
from panther_notion_helpers import notion_alert_context
from panther_oss_helpers import get_dictionary, put_dictionary

# How long (in seconds) to keep previous login locations in cached memory
DEFAULT_CACHE_PERIOD = 2419200


def rule(event):
    if not filter_include_event(event):
        return False

    # Only focused on login events
    if event.deep_walk("event", "type") != "user.login":
        return False

    # Get the user's location, via IPInfo
    # Return False if we have no location information
    if "ipinfo_location" not in event.get("p_enrichment", {}):
        return False
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
    # Store the login location. Here, we use Panther's cache to store a dictionary, using the
    #   user's unique ID to ensure it hold data unique to them. In this dictionary, we'll use the
    #   location strings (loc_string) as the key, and the values will be the timestamp of the last
    #   recorded login from that location.
    user = event.deep_walk("event", "actor", "id")
    cache = get_dictionary(user) or {}

    # If this is a unit test, convert cache from string
    if isinstance(cache, str):
        cache = json.loads(cache)

    # -- Step 1: Record this login.
    new_cache = cache.copy()
    new_cache[loc_string] = time.time()
    put_dictionary(user, new_cache)

    # -- Step 2: Determine if we shoul raise an alert.
    if not cache:
        # User hasn't been recorded logging in before. Since this is their first login, we don't
        #   have a baseline to know if it's unusual, so we won't raise an alert.
        return False

    if is_recent_login(cache, loc_string, event.get("p_parse_time")):
        # User has logged in from this location in the recent past. No need to raise an alert.
        return False

    # User has NOT logged in from this location in the recent past - we should trigger an alert!
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


def is_recent_login(cache: dict, loc_string: str, parse_time: str) -> bool:
    # Use p_parse_time to calculate current timestamp, so that unit tests work.
    now = time.mktime(datetime.datetime.fromisoformat(parse_time[:23]).timetuple())
    return (
        loc_string in cache  # location was previously recorded
        and cache[loc_string] > now - DEFAULT_CACHE_PERIOD  # last recorded login is recent
    )
