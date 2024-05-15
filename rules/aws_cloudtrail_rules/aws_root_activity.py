from panther_default import aws_cloudtrail_success, lookup_aws_account_name

EVENT_ALLOW_LIST = {"CreateServiceLinkedRole"}


def rule(event):
    return (
        event.udm("user_type") == "Root"
        and aws_cloudtrail_success(event)
        and event.udm("invoked_by") is None
        and event.udm("event_type") != "AwsServiceEvent"
        and event.udm("event_name") not in EVENT_ALLOW_LIST
    )


def dedup(event):
    return (
        event.udm("source_ip_address", default="<UNKNOWN_IP>")
        + ":"
        + lookup_aws_account_name(event.udm("recipient_account_id"))
        + ":"
        + str(event.get("read_only"))
    )


def title(event):
    return (
        "AWS root user activity "
        f"[{event.udm('event_name')}] "
        "in account "
        f"[{lookup_aws_account_name(event.udm('recipient_account_id'))}]"
    )


def alert_context(event):
    return {
        "sourceIPAddress": event.udm("source_ip_address"),
        "userIdentityAccountId": event.udm("user_account_id"),
        "userIdentityArn": event.udm("user_arn"),
        "eventTime": event.udm("event_time"),
        "mfaUsed": event.udm("mfa_used"),
    }


def severity(event):
    if event.get("read_only"):
        return "LOW"
    return "HIGH"
