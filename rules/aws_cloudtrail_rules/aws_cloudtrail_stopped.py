from panther_base_helpers import aws_rule_context
from panther_default import aws_cloudtrail_success, lookup_aws_account_name

# API calls that are indicative of CloudTrail changes
CLOUDTRAIL_STOP_DELETE = {
    "DeleteTrail",
    "StopLogging",
}


def rule(event):
    return aws_cloudtrail_success(event) and event.udm("event_name") in CLOUDTRAIL_STOP_DELETE


def dedup(event):
    # Merge on the CloudTrail ARN
    request_parameters = event.udm("request_parameters")
    trail_name = request_parameters.get("name") if request_parameters else "TRAIL_NAME_NOT_FOUND"
    return trail_name


def title(event):
    return (
        f"CloudTrail [{dedup(event)}] in account "
        f"[{lookup_aws_account_name(event.udm('recipient_account_id'))}] was stopped/deleted"
    )


def alert_context(event):
    return aws_rule_context(event)
