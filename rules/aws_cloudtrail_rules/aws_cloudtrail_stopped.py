from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context

# API calls that are indicative of CloudTrail changes
CLOUDTRAIL_STOP_DELETE = {
    "DeleteTrail",
    "StopLogging",
}


def rule(event):
    return aws_cloudtrail_success(event) and event.get("eventName") in CLOUDTRAIL_STOP_DELETE


def dedup(event):
    # Merge on the CloudTrail ARN
    return event.deep_get("requestParameters", "name", default="<UNKNOWN_NAME>")


def title(event):
    return (
        f"CloudTrail [{dedup(event)}] in account "
        f"[{event.get('recipientAccountId')}] was stopped/deleted"
    )


def alert_context(event):
    return aws_rule_context(event)
