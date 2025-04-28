from panther_aws_helpers import aws_cloudtrail_success


def rule(event):
    if not aws_cloudtrail_success(event):
        return False

    if event.get("eventName") != "AttachUserPolicy":
        return False

    policy = event.deep_get("requestParameters", "policyArn", default="")
    return policy.endswith("AdministratorAccess")


def alert_context(event):
    context = {
        "target": event.deep_get("requestParameters", "userName", default=""),
        "actor": event.deep_get("userIdentity", "arn", default=""),
        "timestamp": event.get("eventTime", ""),
        "parameters": event.deep_get("requestParameters", default={}),
        "action": event.get("eventName", ""),
    }
    return context
