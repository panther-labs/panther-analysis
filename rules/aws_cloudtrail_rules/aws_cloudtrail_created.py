from panther_base_helpers import aws_rule_context
from panther_default import aws_cloudtrail_success

# API calls that are indicative of CloudTrail changes
CLOUDTRAIL_CREATE_UPDATE = {
    "CreateTrail",
    "UpdateTrail",
    "StartLogging",
}


def rule(event):
    return aws_cloudtrail_success(event) and event.udm("event_name") in CLOUDTRAIL_CREATE_UPDATE


def title(event):
    request_parameters = event.udm("request_parameters")
    trail_name = request_parameters.get("name") if request_parameters else "TRAIL_NAME_NOT_FOUND"
    return f"CloudTrail [{trail_name}] was created/updated"


def alert_context(event):
    return aws_rule_context(event)
