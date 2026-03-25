import ipaddress

from panther_databricks_helpers import databricks_alert_context, filter_noise


def rule(event):
    # Filter out system noise
    if filter_noise(event):
        return False

    # Check user agent for TruffleHog signature
    user_agent = event.get("userAgent", "")
    return "TruffleHog" in user_agent


def title(event):
    source_ip = event.get("sourceIPAddress", "Unknown IP")
    user = event.deep_get("userIdentity", "email", default="Unknown User")
    return f"TruffleHog secret scan detected from {source_ip} (User: {user})"


def severity(event):
    source_ip = event.get("sourceIPAddress", "")
    try:
        if ipaddress.ip_address(source_ip).is_private:
            return "MEDIUM"
    except ValueError:
        pass
    return "HIGH"


def alert_context(event):
    return databricks_alert_context(
        event,
        additional_fields={
            "token_id": event.deep_get("requestParams", "tokenId"),
            "user_agent_full": event.get("userAgent"),
        },
    )
