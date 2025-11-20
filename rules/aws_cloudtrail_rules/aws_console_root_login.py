from panther_ipinfo_helpers import geoinfo_from_ip_formatted


def rule(event):
    return (
        event.get("eventName") == "ConsoleLogin"
        and event.deep_get("userIdentity", "type") == "Root"
        and event.deep_get("responseElements", "ConsoleLogin") == "Success"
    )


def title(event):
    return (
        "AWS root login detected from "
        f"({geoinfo_from_ip_formatted(event, 'sourceIPAddress')}) "
        f"in account "
        f"[{event.get('recipientAccountId')}]"
    )


def dedup(event):
    # Each Root login should generate a unique alert
    return "-".join(
        [event.get("recipientAccountId"), event.get("eventName"), event.get("eventTime")]
    )


def alert_context(event):
    return {
        "sourceIPAddress": event.get("sourceIPAddress"),
        "userIdentityAccountId": event.deep_get("userIdentity", "accountId"),
        "userIdentityArn": event.deep_get("userIdentity", "arn"),
        "eventTime": event.get("eventTime"),
        "mfaUsed": event.deep_get("additionalEventData", "MFAUsed"),
    }
