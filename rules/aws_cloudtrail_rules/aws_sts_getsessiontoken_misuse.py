from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context


def rule(event):
    if not aws_cloudtrail_success(event):
        return False
    return (
        event.get("eventSource") == "sts.amazonaws.com"
        and event.get("eventName") == "GetSessionToken"
        and event.deep_get("userIdentity", "type") == "IAMUser"
    )


def title(event):
    user = event.deep_get("userIdentity", "userName", default="<unknown>")
    account = event.get("recipientAccountId", "<unknown>")
    return f"IAM user [{user}] called GetSessionToken in account [{account}]"


def alert_context(event):
    return aws_rule_context(event)
