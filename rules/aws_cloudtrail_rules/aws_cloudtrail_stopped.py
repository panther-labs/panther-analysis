from panther import aws_cloudtrail_success, lookup_aws_account_name
from panther_base_helpers import aws_rule_context, deep_get

# API calls that are indicative of CloudTrail changes
CLOUDTRAIL_STOP_DELETE = {
    "DeleteTrail",
    "StopLogging",
}


def rule(event):
    return aws_cloudtrail_success(event) and event.get("eventName") in CLOUDTRAIL_STOP_DELETE


def dedup(event):
    # Merge on the CloudTrail ARN
    return deep_get(event, "requestParameters", "name", default="<UNKNOWN_NAME>")


def title(event):
    return (
        f"CloudTrail [{dedup(event)}] in account "
        f"[{lookup_aws_account_name(event.get('recipientAccountId'))}] was stopped/deleted"
    )


def alert_context(event):
    return aws_rule_context(event)
