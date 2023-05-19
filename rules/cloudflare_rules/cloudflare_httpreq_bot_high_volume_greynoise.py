from ipaddress import ip_address

from global_filter_cloudflare import filter_include_event
from panther_cloudflare_helpers import cloudflare_http_alert_context
from panther_greynoise_helpers import GetGreyNoiseObject, GetGreyNoiseRiotObject


def rule(event):
    if not filter_include_event(event):
        return False
    # Bot scores are [0, 99] where scores >=1 && <30 indicating likely automated
    # https://developers.cloudflare.com/bots/concepts/bot-score/
    if not all(
        [
            event.get("BotScore", 100) <= 30,
            event.get("BotScore", 100) >= 1,
        ]
    ):
        return False

    # Validate the IP is actually an IP
    try:
        ip_address(event.get("ClientIP"))
    except ValueError:
        return False

    # Setup GreyNoise variables
    global NOISE  # pylint: disable=global-variable-undefined
    NOISE = GetGreyNoiseObject(event)
    riot = GetGreyNoiseRiotObject(event)

    # If IP is in the RIOT dataset, we can assume it is safe
    if riot.is_riot("ClientIP"):
        return False
    return True


def title(event):
    return (
        f"Cloudflare: High Volume of Bot Requests - GreyNoise non-RIOT - "
        f"from [{event.get('ClientIP', '<NO_CLIENTIP>')}] "
        f"to [{event.get('ClientRequestHost', '<NO_REQ_HOST>')}]"
    )


def dedup(event):
    return (
        f"{event.get('ClientIP', '<NO_CLIENTIP>')}:"
        f"{event.get('ClientRequestHost', '<NO_REQ_HOST>')}"
    )


def alert_context(event):
    ctx = cloudflare_http_alert_context(event)
    ctx["GreyNoise"] = NOISE.context("ClientIP")
    return ctx
