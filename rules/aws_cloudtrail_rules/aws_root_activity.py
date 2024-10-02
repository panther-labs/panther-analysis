from panther_default import aws_cloudtrail_success, lookup_aws_account_name

EVENT_ALLOW_LIST = {"CreateServiceLinkedRole"}


def rule(event):
    return (
        event.deep_get("userIdentity", "type") == "Root"
        and aws_cloudtrail_success(event)
        and event.deep_get("userIdentity", "invokedBy") is None
        and event.get("eventType") != "AwsServiceEvent"
        and event.get("eventName") not in EVENT_ALLOW_LIST
    )


def dedup(event):
    return (
        event.get("sourceIPAddress", "<UNKNOWN_IP>")
        + ":"
        + lookup_aws_account_name(event.get("recipientAccountId"))
        + ":"
        + str(event.get("readOnly"))
    )


def title(event):
    return (
        "AWS root user activity "
        f"[{event.get('eventName')}] "
        "in account "
        f"[{lookup_aws_account_name(event.get('recipientAccountId'))}]"
    )


def alert_context(event):
    return {
        "sourceIPAddress": event.get("sourceIPAddress"),
        "userIdentityAccountId": event.deep_get("userIdentity", "accountId"),
        "userIdentityArn": event.deep_get("userIdentity", "arn"),
        "eventTime": event.get("eventTime"),
        "mfaUsed": event.deep_get("additionalEventData", "MFAUsed"),
    }


def severity(event):
    if event.get("readOnly"):
        return "LOW"
    return "HIGH"
