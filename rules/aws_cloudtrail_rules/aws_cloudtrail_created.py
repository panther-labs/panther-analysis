from panther_base_helpers import aws_rule_context, deep_get
from panther_default import aws_cloudtrail_success

# API calls that are indicative of CloudTrail changes
CLOUDTRAIL_CREATE_UPDATE = {
    "CreateTrail",
    "UpdateTrail",
    "StartLogging",
}


def rule(event):
    return aws_cloudtrail_success(event) and event.get("eventName") in CLOUDTRAIL_CREATE_UPDATE


def title(event):
    return f"CloudTrail [{deep_get(event, 'requestParameters', 'name')}] was created/updated"


def alert_context(event):
    return aws_rule_context(event)
