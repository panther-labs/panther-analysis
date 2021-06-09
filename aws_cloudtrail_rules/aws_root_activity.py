from panther import aws_cloudtrail_success, lookup_aws_account_name
from panther_base_helpers import deep_get

EVENT_ALLOW_LIST = {"CreateServiceLinkedRole"}


def rule(event):
    return (
        deep_get(event, "userIdentity", "type") == "Root"
        and aws_cloudtrail_success(event)
        and deep_get(event, "userIdentity", "invokedBy") is None
        and event.get("eventType") != "AwsServiceEvent"
        and event.get("eventName") not in EVENT_ALLOW_LIST
    )


def dedup(event):
    return (
        event.get("sourceIPAddress", "<UNKNOWN_IP>")
        + ":"
        + lookup_aws_account_name(event.get("recipientAccountId"))
    )


def title(event):
    action = "activity"
    if event.get("eventName") == "ConsoleLogin":
        action = "login"
    return (
        f"AWS root {action} detected from [{event.get('sourceIPAddress')}] in account "
        f"[{lookup_aws_account_name(event.get('recipientAccountId'))}]"
    )


def alert_context(event):
    return {
        "sourceIPAddress": event.get("sourceIPAddress"),
        "userIdentityAccountId": deep_get(event, "userIdentity", "accountId"),
        "userIdentityArn": deep_get(event, "userIdentity", "arn"),
        "eventTime": event.get("eventTime"),
        "mfaUsed": deep_get(event, "additionalEventData", "MFAUsed"),
    }
