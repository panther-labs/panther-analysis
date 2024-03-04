from datetime import datetime, timedelta
from json import dumps, loads

import panther_event_type_helpers as event_type
from panther_base_helpers import deep_get
from panther_detection_helpers.caching import get_string_set, put_string_set
from panther_lookuptable_helpers import LookupTableMatches
from panther_oss_helpers import km_between_ipinfo_loc, resolve_timestamp_string

# pylint: disable=global-variable-undefined


def gen_key(event):
    """
    gen_key uses the data_model for the logtype to cache
    an entry that is specific to the Log Source ID

    The data_model needs to answer to "actor_user"
    """
    rule_name = deep_get(event, "p_source_label")
    actor = event.udm("actor_user")
    if None in [rule_name, actor]:
        return None
    return f"{rule_name.replace(' ', '')}..{actor}"


def rule(event):
    # too-many-return-statements due to error checking
    # pylint: disable=global-statement,too-many-return-statements,too-complex
    global EVENT_CITY_TRACKING
    global CACHE_KEY
    global IS_VPN
    global IS_PRIVATE_RELAY

    EVENT_CITY_TRACKING = {}
    CACHE_KEY = None
    IS_VPN = False
    IS_PRIVATE_RELAY = False

    # Only evaluate successful logins
    if event.udm("event_type") != event_type.SUCCESSFUL_LOGIN:
        return False

    p_event_datetime = resolve_timestamp_string(deep_get(event, "p_event_time"))
    if p_event_datetime is None:
        # we couldn't go from p_event_time to a datetime object
        # we need to do this in order to make later time comparisons generic
        return False

    new_login_stats = {
        "p_event_time": p_event_datetime.isoformat(),
        "source_ip": event.udm("source_ip"),
    }
    #
    src_ip_enrichments = LookupTableMatches().p_matches(event, event.udm("source_ip"))

    # stuff everything from ipinfo_location into the new_login_stats
    # new_login_stats is the value that we will cache for this key
    ipinfo_location = deep_get(src_ip_enrichments, "ipinfo_location")
    if ipinfo_location is None:
        return False
    new_login_stats.update(ipinfo_location)

    # Bail out if we have a None value in set as it causes false positives
    if None in new_login_stats.values():
        return False

    ## Check for VPN or Private Relay
    ipinfo_privacy = deep_get(src_ip_enrichments, "ipinfo_privacy")
    if ipinfo_privacy is not None:
        ###  Do VPN/private relay
        IS_PRIVATE_RELAY = all(
            [
                deep_get(ipinfo_privacy, "relay", default=False),
                deep_get(ipinfo_privacy, "service", default="") == "Apple Private Relay",
            ]
        )
        # We've found that some places, like WeWork locations,
        #   have the VPN attribute set to true, but do not have a
        #   service name entry.
        # We have noticed VPN connections with commercial VPN
        #   offerings have the VPN attribute set to true, and
        #   do have a service name entry
        IS_VPN = all(
            [
                deep_get(ipinfo_privacy, "vpn", default=False),
                deep_get(ipinfo_privacy, "service", default="") != "",
            ]
        )
    if IS_VPN or IS_PRIVATE_RELAY:
        new_login_stats.update(
            {
                "is_vpn": f"{IS_VPN}",
                "is_apple_priv_relay": f"{IS_PRIVATE_RELAY}",
                "service_name": f"{deep_get(ipinfo_privacy, 'service', default='<NO_SERVICE>')}",
                "NOTE": "APPLE PRIVATE RELAY AND VPN LOGINS ARE NOT CACHED FOR COMPARISON",
            }
        )

    # Generate a unique cache key for each user per log type
    CACHE_KEY = gen_key(event)
    if CACHE_KEY is None:
        # We can't save without a cache key
        return False
    # Retrieve the prior login info from the cache, if any
    last_login = get_string_set(CACHE_KEY)
    # If we haven't seen this user login in the past 1 day,
    # store this login for future use and don't alert
    if not last_login:
        if not (IS_PRIVATE_RELAY or IS_VPN):
            put_string_set(
                key=CACHE_KEY,
                val=[dumps(new_login_stats)],
                epoch_seconds=int((datetime.utcnow() + timedelta(days=1)).timestamp()),
            )
        return False
    # Load the last login from the cache into an object we can compare
    # str check is in place for unit test mocking
    if isinstance(last_login, str):
        tmp_last_login = loads(last_login)
        last_login = []
        for l_l in tmp_last_login:
            last_login.append(dumps(l_l))
    last_login_stats = loads(last_login.pop())

    distance = km_between_ipinfo_loc(last_login_stats, new_login_stats)
    old_time = resolve_timestamp_string(deep_get(last_login_stats, "p_event_time"))
    new_time = resolve_timestamp_string(deep_get(new_login_stats, "p_event_time"))
    time_delta = (new_time - old_time).total_seconds() / 3600  # seconds in an hour

    # Don't let time_delta be 0 (divide by zero error below)
    time_delta = time_delta or 0.0001
    # Calculate speed in Kilometers / Hour
    speed = distance / time_delta

    # Calculation is complete, write the current login to the cache
    # Only if non-VPN non-relay!
    if not IS_PRIVATE_RELAY and not IS_VPN:
        put_string_set(
            key=CACHE_KEY,
            val=[dumps(new_login_stats)],
            epoch_seconds=int((datetime.utcnow() + timedelta(days=1)).timestamp()),
        )

    EVENT_CITY_TRACKING["previous"] = last_login_stats
    EVENT_CITY_TRACKING["current"] = new_login_stats
    EVENT_CITY_TRACKING["speed"] = int(speed)
    EVENT_CITY_TRACKING["speed_units"] = "km/h"
    EVENT_CITY_TRACKING["distance"] = int(distance)
    EVENT_CITY_TRACKING["distance_units"] = "km"

    return speed > 900  # Boeing 747 cruising speed


def title(event):
    #
    log_source = deep_get(event, "p_source_label", default="<NO_SOURCE_LABEL>")
    old_city = deep_get(EVENT_CITY_TRACKING, "previous", "city", default="<NO_PREV_CITY>")
    new_city = deep_get(EVENT_CITY_TRACKING, "current", "city", default="<NO_PREV_CITY>")
    speed = deep_get(EVENT_CITY_TRACKING, "speed", default="<NO_SPEED>")
    distance = deep_get(EVENT_CITY_TRACKING, "distance", default="<NO_DISTANCE>")
    return (
        f"Impossible Travel: [{event.udm('actor_user')}] "
        f"in [{log_source}] went [{speed}] km/h for [{distance}] km "
        f"between [{old_city}] and [{new_city}]"
    )


def dedup(event):  # pylint: disable=W0613
    return CACHE_KEY


def alert_context(event):
    context = {
        "actor_user": event.udm("actor_user"),
    }
    context.update(EVENT_CITY_TRACKING)
    return context


def severity(_):
    if IS_VPN or IS_PRIVATE_RELAY:
        return "INFO"
    # time = distance/speed
    distance = deep_get(EVENT_CITY_TRACKING, "distance", default=None)
    speed = deep_get(EVENT_CITY_TRACKING, "speed", default=None)
    if speed and distance:
        time = distance / speed
        # time of 0.1666 is 10 minutes
        if time < 0.1666 and distance < 50:
            # This is likely a GEOIP inaccuracy
            return "LOW"
    return "HIGH"
