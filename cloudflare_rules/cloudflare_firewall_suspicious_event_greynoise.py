from ipaddress import ip_address

from panther_greynoise_helpers import GetGreyNoiseObject, GetGreyNoiseRiotObject


def rule(event):
    if event.get("Action") == "block":
        return False

    # Validate the IP is actually an IP
    try:
        ip_address(event.get("ClientIP"))
    except ValueError:
        return False

    # Setup GreyNoise variables
    global NOISE
    NOISE = GetGreyNoiseObject(event)
    riot = GetGreyNoiseRiotObject(event)

    # If IP is in the RIOT dataset, we can assume it is safe
    if riot.is_riot("ClientIP"):
        return False

    # Check if IP classified as malicious
    if NOISE.classification("ClientIP") == "malicious":
        return True

    return False


def title(event):
    return f"Suspicious Event Detected - <{event.get('ClientIP', 'UNKNOWN_IP')}>"


def alert_context(_):
    return NOISE.context("ClientIP")
