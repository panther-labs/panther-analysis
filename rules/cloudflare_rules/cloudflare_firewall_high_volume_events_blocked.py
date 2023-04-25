from global_filter_cloudflare import filter_include_event
from panther_cloudflare_helpers import cloudflare_fw_alert_context


def rule(event):
    if not filter_include_event(event):
        return False
    return event.get("Action", "") == "block"


def title(event):
    return (
        f"Cloudflare: High Volume of Block Actions - "
        f"from [{event.get('ClientIP', '<NO_CLIENTIP>')}] "
        f"to [{event.get('ClientRequestHost', '<NO_REQ_HOST>')}] "
    )


def dedup(event):
    return (
        f"{event.get('ClientIP', '<NO_CLIENTIP>')}:"
        f"{event.get('ClientRequestHost', '<NO_REQ_HOST>')}"
    )


def alert_context(event):
    return cloudflare_fw_alert_context(event)
