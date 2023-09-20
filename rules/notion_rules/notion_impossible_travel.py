import time
from global_filter_notion import filter_include_event
from panther_notion_helpers import notion_alert_context
from panther_oss_helpers import get_dictionary, put_dictionary
from panther_ipinfo_helpers import IPInfoLocation, IPInfoPrivacy

# We add this prefix to all cache keys, so we don't bleed information into other detections
CACHE_KEY_PREFIX = "Notion.ImpossibleTravel"

def rule(event):
    if not filter_include_event(event):
        return False
    
    # If this isn't a successful login, then exit
    if event.deep_get("event", "type") != "user.login":
        return False
    
    # Ignore event if the user has a vpn (otherwise we get false positives)
    ipinfo_priv = IPInfoPrivacy(event)
    if ipinfo_priv.vpn('event.ip_address'):
        return False

    # Get the user's location and store it
    # pylint: disable=global-variable-undefined
    global IPINFO_LOC
    IPINFO_LOC = IPInfoLocation(event)
    new_login_stats = {
        "city": IPINFO_LOC.city('event.ip_address'),
        "lon": IPINFO_LOC.longitude('event.ip_address'),
        "lat": IPINFO_LOC.latitude('event.ip_address')
    }
    # Bail out if we have a None value in set as it causes false positives
    if None in new_login_stats.values():
        return False
    
    # Generate a unique cache for each user
    cache_key = CACHE_KEY_PREFIX + event.deep_get("event", "actor", "id")
    # Retrieve the prior login ingo from the cache, if any
    last_login = get_dictionary(cache_key)
    