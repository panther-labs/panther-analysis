from panther import lookup_aws_account_name
from panther_base_helpers import deep_get


def rule(event):
    return (
        event.get("eventName") == "ConsoleLogin"
        and deep_get(event, "userIdentity", "type") == "Root"
        and deep_get(event, "responseElements", "ConsoleLogin") == "Success"
    )


def title(event):
    return (
        f"AWS root login detected from [{event.get('sourceIPAddress')}] in account "
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
