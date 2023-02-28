from panther_default import lookup_aws_account_name
from panther_base_helpers import deep_get
from panther_oss_helpers import geoinfo_from_ip_formatted


def rule(event):
    return (
        event.get("eventName") == "ConsoleLogin"
        and deep_get(event, "userIdentity", "type") == "Root"
        and deep_get(event, "responseElements", "ConsoleLogin") == "Success"
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
        "userIdentityAccountId": deep_get(event, "userIdentity", "accountId"),
        "userIdentityArn": deep_get(event, "userIdentity", "arn"),
        "eventTime": event.get("eventTime"),
        "mfaUsed": deep_get(event, "additionalEventData", "MFAUsed"),
    }
