from panther_aws_helpers import aws_cloudtrail_success


def rule(event):
    return aws_cloudtrail_success(event) and event.get("eventName") == "CreateUser"


def alert_context(event):
    context = {
        "target": event.deep_get("requestParameters", "userName", default=""),
        "actor": event.deep_get("userIdentity", "arn", default=""),
        "timestamp": event.get("eventTime", ""),
        "parameters": event.deep_get("requestParameters", default={}),
        "action": event.get("eventName", ""),
    }
    return context
