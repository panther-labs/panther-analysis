from unittest.mock import MagicMock

from global_filter_cloudflare import filter_include_event
from panther_cloudflare_helpers import cloudflare_http_alert_context


def rule(event):
    if isinstance(filter_include_event, MagicMock):
        pass
    if not filter_include_event(event):
        return False
    # Bot scores are [0, 99] where scores >0 && <30 indicating likely automated
    # https://developers.cloudflare.com/bots/concepts/bot-score/
    return all(
        [
            event.get("BotScore", 100) <= 30,
            event.get("BotScore", 100) >= 1,
        ]
    )


def title(event):
    return (
        f"Cloudflare: High Volume of Bot Requests - "
        f"from [{event.get('ClientIP', '<NO_CLIENTIP>')}] "
        f"to [{event.get('ClientRequestHost', '<NO_REQ_HOST>')}]"
    )


def dedup(event):
    return (
        f"{event.get('ClientIP', '<NO_CLIENTIP>')}:"
        f"{event.get('ClientRequestHost', '<NO_REQ_HOST>')}"
    )


def alert_context(event):
    return cloudflare_http_alert_context(event)
