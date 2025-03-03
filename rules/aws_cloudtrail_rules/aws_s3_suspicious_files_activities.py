from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context

SUSPICIOUS_EVENTS = {
    "DeleteObject",
    "DeleteObjects",
    "GetObject",
    "CopyObject",
}


def rule(event):
    return (
        aws_cloudtrail_success(event)
        and event.get("eventSource") == "s3.amazonaws.com"
        and event.get("eventName") in SUSPICIOUS_EVENTS
    )


def title(event):
    return (
        f"[AWS.CloudTrail] User [{event.udm('actor_user')}] "
        f"performed [{event.get('eventName')}] on "
        f"[{event.deep_get('requestParameters', 'bucketName')}] bucket"
    )


def alert_context(event):
    return aws_rule_context(event)
