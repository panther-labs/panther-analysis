from ipaddress import ip_address

from panther_greynoise_helpers import GetGreyNoiseObject, GetGreyNoiseRiotObject


def rule(event):
    # Bot scores are [1, 99] where scores < 30 indicating likely automated
    # https://developers.cloudflare.com/bots/concepts/bot-score/
    if event.get("BotScore", 100) >= 30:
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


def alert_context(_):
    return NOISE.context("ClientIP")
