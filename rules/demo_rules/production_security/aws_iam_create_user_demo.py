from panther_aws_helpers import aws_cloudtrail_success


def rule(event):
    return aws_cloudtrail_success(event) and event.get("eventName") == "CreateUser"


def runbook(event):
    return f"""
    Identify who created the IAM user ({event.get("requestParameters", {}).get("userName", "")}) and validate their role using p_enrichments (if available). Check for suspicious follow-up activities, like admin policy attachments or access key creation within 1 hour in the aws_cloudtrail table. If unauthorized, immediately disable the user and investigate any actions taken using CloudTrail logs.
    """


def alert_context(event):
    context = {
        "target": event.deep_get("requestParameters", "userName", default=""),
        "actor": event.deep_get("userIdentity", "arn", default=""),
        "timestamp": event.get("eventTime", ""),
        "parameters": event.deep_get("requestParameters", default={}),
        "action": event.get("eventName", ""),
    }
    return context
