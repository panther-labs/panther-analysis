from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context


def rule(event):
    return (
        aws_cloudtrail_success(event)
        and event.get("eventSource") == "s3.amazonaws.com"
        and event.get("eventName") == "DeleteObject"
    )


def title(event):
    return (
        f"[AWS.CloudTrail] User [{event.udm('actor_user')}] "
        f"deleted many items from the "
        f"[{event.deep_get('requestParameters', 'bucketName')}] bucket"
    )


def alert_context(event):
    context = aws_rule_context(event)
    context["bucketName"] = event.deep_get(
        "requestParameters", "bucketName", default="<UNKNOWN_BUCKET>"
    )
    return context
