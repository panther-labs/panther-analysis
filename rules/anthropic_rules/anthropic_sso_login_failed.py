from panther_anthropic_helpers import anthropic_alert_context


def rule(event):
    return event.get("type") == "sso_login_failed"


def title(event):
    actor_ip = event.deep_get("actor", "ip_address", default="<UNKNOWN_IP>")
    return f"Anthropic: SSO login failed from [{actor_ip}]"


def dedup(event):
    return event.deep_get("actor", "ip_address", default="<UNKNOWN_IP>")


def alert_context(event):
    return anthropic_alert_context(event)
