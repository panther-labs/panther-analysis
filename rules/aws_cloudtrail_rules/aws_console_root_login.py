from panther_aws_helpers import lookup_aws_account_name
from panther_oss_helpers import geoinfo_from_ip_formatted


def rule(event):
    return (
        event.get("eventName") == "ConsoleLogin"
        and event.deep_get("userIdentity", "type") == "Root"
        and event.deep_get("responseElements", "ConsoleLogin") == "Success"
    )


def title(event):
    ip_address = event.get("sourceIPAddress")
    return (
        f"AWS root login detected from [{ip_address}] "
        f"({geoinfo_from_ip_formatted(ip_address)}) "
        f"in account "
        f"[{lookup_aws_account_name(event.get('recipientAccountId'))}]"
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
