from ipaddress import ip_address

from panther_cloudflare_helpers import cloudflare_fw_alert_context
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
    global NOISE  # pylint: disable=global-variable-undefined
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
        f"Cloudflare: High Volume of Block Actions - "
        f"from [{event.get('ClientIP', '<NO_CLIENTIP>')}] "
        f"to [{event.get('ClientRequestHost', '<NO_REQ_HOST>')}] "
        f" - GreyNoise identified IP as malicious"
    )


def dedup(event):
    return (
        f"{event.get('ClientIP', '<NO_CLIENTIP>')}:"
        f"{event.get('ClientRequestHost', '<NO_REQ_HOST>')}"
    )


def alert_context(event):
    ctx = cloudflare_fw_alert_context(event)
    ctx["GreyNoise"] = NOISE.context("ClientIP")
    return ctx
