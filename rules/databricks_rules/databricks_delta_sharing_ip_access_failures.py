from panther_databricks_helpers import databricks_alert_context

# Keywords that indicate IP-based access denials
IP_DENIAL_KEYWORDS = ["address", "network", "cidr", "allowlist", "blocklist"]


def rule(event):
    if event.get("serviceName") != "deltaSharingAccess":
        return False

    status_code = event.deep_get("response", "statusCode")
    if status_code not in [403, 401]:
        return False

    error_message = event.deep_get("response", "errorMessage", default="").lower()
    return any(keyword in error_message for keyword in IP_DENIAL_KEYWORDS)


def title(event):
    recipient = event.deep_get("requestParams", "recipientName", default="Unknown Recipient")
    source_ip = event.get("sourceIPAddress", "Unknown IP")
    return f"Delta Sharing access blocked from {source_ip} for recipient {recipient}"


def alert_context(event):
    return databricks_alert_context(event)
