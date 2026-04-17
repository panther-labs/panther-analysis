from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context

# API calls that are indicative of CloudTrail changes
CLOUDTRAIL_CREATE_UPDATE = {
    "CreateTrail",
    "UpdateTrail",
    "StartLogging",
}


def rule(event):
    return aws_cloudtrail_success(event) and event.get("eventName") in CLOUDTRAIL_CREATE_UPDATE


def title(event):
    return f"CloudTrail [{event.deep_get('requestParameters', 'name')}] was created/updated"


def alert_context(event):
    return aws_rule_context(event)
