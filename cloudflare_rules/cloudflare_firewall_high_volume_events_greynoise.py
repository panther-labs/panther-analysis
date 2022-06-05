from ipaddress import ip_address

from panther_cloudflare_helpers import map_source_to_name
from panther_greynoise_helpers import GetGreyNoiseObject, GetGreyNoiseRiotObject


def rule(event):
    if event.get("Action") != "block":
        return False

    # Validate the IP is actually an IP
    try:
        ip_address(event.get("ClientIP"))
    except ValueError:
        return False

    # If IP is in the RIOT dataset, we can assume safe
    global NOISE
    NOISE = GetGreyNoiseObject(event)
    riot = GetGreyNoiseRiotObject(event)
    if riot.is_riot("ClientIP"):
        return False

    # Check if IP is classified as 'malicious'
    if NOISE.classification("ClientIP") == "malicious":
        return True
    return False


def title(event):
    return (
        f"High Volume Events Blocked - "
        f"{map_source_to_name(event.get('Source'))}: {event.get('ClientIP')}"
    )


def dedup(event):
    return f"{event.get('ClientIP')}:{event.get('Source')}"


def alert_context(_):
    return NOISE.context("ClientIP")
