from panther_cloudflare_helpers import cloudflare_fw_alert_context


def rule(event):

    return event.get("Source", "") == "l7ddos"


def title(_):
    return "Cloudflare: Detected L7 DDoS"


def alert_context(event):
    return cloudflare_fw_alert_context(event)


def severity(event):
    if event.get("Action", "") == "block":
        return "Info"
    return "Medium"
